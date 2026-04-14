"""
Abuse Engine Knowledge Agent

Passive advisory agent — produces NO verdicts. Answers reputation queries from
other agents during their orient() step. Runs a background warm-up thread on
SharedMemory init to pre-seed known-bad IPs from local cache and (optionally)
live threat intel APIs.

Interface other agents use:
    prior = self.tools.call("query_knowledge_base", ip=top_ip)
    # Returns: {"known_bad": bool, "prior_confidence": float, "history_summary": str}

Data held in LTM (keyed by "knowledge:*"):
    - known-bad IP set (seeded from threat_intel_cache.json)
    - per-IP threat history: flagged count, last seen, confidence trajectory
    - OWASP API Top 10 pattern library (static)
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.memory.shared_memory import SharedMemory
from schemas.models import EvidenceEntry

logger = logging.getLogger(__name__)

# Path to the optional offline threat intel seed file
_CACHE_FILE = Path(__file__).parents[2] / "datasets" / "threat_intel_cache.json"

# OWASP API Security Top 10 (2023) — static reference for prompts / explanations
OWASP_API_TOP10 = {
    "API1": "Broken Object Level Authorisation (BOLA)",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorisation",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorisation",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery (SSRF)",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}


class KnowledgeAgent:
    """
    Passive agent. Instantiated by MetaAgentOrchestrator alongside the detection
    agents. Provides two tool methods registered in ToolRegistry:

        query_knowledge_base(ip, endpoint=None)  → prior dict
        update_knowledge_base(ip, outcome, confidence)  → None
    """

    # Minimum confidence to write a pre-emptive evidence entry
    _PREEMPTIVE_CONFIDENCE_THRESHOLD = 0.70
    # Confidence decay per batch (older history matters less)
    _CONFIDENCE_DECAY = 0.95

    def __init__(self, memory: SharedMemory):
        self.memory = memory
        self._lock = threading.Lock()
        self._started = False

    # ── Public boot ────────────────────────────────────────────────────────

    def warm_up(self) -> None:
        """Start background warm-up thread (non-blocking)."""
        if self._started:
            return
        self._started = True
        t = threading.Thread(target=self._background_load, daemon=True, name="KnowledgeAgent-warmup")
        t.start()
        logger.info("[KnowledgeAgent] Background warm-up started")

    # ── Tool: query ────────────────────────────────────────────────────────

    def query(self, ip: str, endpoint: Optional[str] = None) -> Dict[str, Any]:
        """
        Return reputation prior for an IP.

        Returns:
            {
                "known_bad": bool,
                "prior_confidence": float,   # 0.0–1.0
                "history_summary": str,
                "owasp_context": str | None, # relevant OWASP category if endpoint given
            }
        """
        history = self._get_ip_history(ip)
        known_bad = self._is_known_bad(ip)
        prior_conf = self._compute_prior_confidence(ip, history)

        owasp_context = None
        if endpoint:
            owasp_context = self._match_owasp(endpoint)

        summary = self._summarise_history(ip, history, known_bad)

        return {
            "known_bad": known_bad,
            "prior_confidence": round(prior_conf, 3),
            "history_summary": summary,
            "owasp_context": owasp_context,
        }

    # ── Tool: update ──────────────────────────────────────────────────────

    def update(self, ip: str, outcome: bool, confidence: float) -> None:
        """
        Record that `ip` was involved in a confirmed verdict.

        Args:
            ip:         source IP address
            outcome:    True if verdict was attack, False if benign
            confidence: confidence score of the verdict (0.0–1.0)
        """
        with self._lock:
            history = self._get_ip_history(ip)
            history.append({
                "ts": datetime.now(tz=timezone.utc).isoformat(),
                "outcome": outcome,
                "confidence": round(confidence, 3),
            })
            # Cap history at 50 entries per IP
            if len(history) > 50:
                history = history[-50:]
            self.memory.ltm._batch_stats  # ensure LTM is initialized
            self._set_ip_history(ip, history)

        # Post to evidence board if IP repeatedly flagged
        attack_count = sum(1 for h in history if h["outcome"])
        if attack_count >= 3 and confidence >= self._PREEMPTIVE_CONFIDENCE_THRESHOLD:
            self.memory.board.post(EvidenceEntry(
                posted_by="KnowledgeAgent",
                key=f"knowledge:repeat_offender:{ip}",
                value={"ip": ip, "attack_count": attack_count, "confidence": confidence},
                confidence=min(1.0, 0.5 + (attack_count * 0.1)),
                tags=["knowledge", "reputation"],
            ))
            logger.debug(
                "[KnowledgeAgent] Repeat offender posted: %s (flagged %d times)", ip, attack_count
            )

    # ── Cross-tenant reputation stub ──────────────────────────────────────

    def get_cross_tenant_reputation(self, ip: str) -> None:
        """
        Stub for future shared Redis reputation call.
        Designed so a Redis lookup slots in here without touching agent code.
        Returns None until cross-tenant infrastructure is wired.
        """
        return None

    # ── has_known_bad_in_batch (for triage step) ──────────────────────────

    def has_known_bad_in_batch(self, records) -> bool:
        """O(n) check — returns True if any record's IP is in the known-bad set."""
        known_bad_key = "knowledge:known_bad_ips"
        known_bad_set = self.memory.ltm.__dict__.get("_knowledge_known_bad", set())
        return any(r.ip in known_bad_set for r in records)

    # ── Private helpers ───────────────────────────────────────────────────

    def _is_known_bad(self, ip: str) -> bool:
        known_bad = getattr(self.memory.ltm, "_knowledge_known_bad", set())
        return ip in known_bad

    def _get_ip_history(self, ip: str) -> List[Dict]:
        store = getattr(self.memory.ltm, "_knowledge_ip_history", {})
        return list(store.get(ip, []))

    def _set_ip_history(self, ip: str, history: List[Dict]) -> None:
        if not hasattr(self.memory.ltm, "_knowledge_ip_history"):
            self.memory.ltm._knowledge_ip_history: Dict[str, List] = {}
        self.memory.ltm._knowledge_ip_history[ip] = history

    def _compute_prior_confidence(self, ip: str, history: List[Dict]) -> float:
        if not history:
            return 0.85 if self._is_known_bad(ip) else 0.0
        # Decay-weighted average of past attack confidences
        total_weight = 0.0
        weighted_conf = 0.0
        decay = 1.0
        for entry in reversed(history):
            if entry["outcome"]:
                weighted_conf += entry["confidence"] * decay
                total_weight += decay
            decay *= self._CONFIDENCE_DECAY
        return weighted_conf / total_weight if total_weight > 0 else 0.0

    def _summarise_history(self, ip: str, history: List[Dict], known_bad: bool) -> str:
        if not history and not known_bad:
            return "No prior activity on record."
        attack_count = sum(1 for h in history if h["outcome"])
        total = len(history)
        parts = []
        if known_bad:
            parts.append("IP is in known-bad seed list.")
        if total > 0:
            parts.append(f"Seen in {total} prior batch(es); {attack_count} flagged as attack.")
        if attack_count >= 3:
            parts.append("Repeat offender — escalated pre-emptive confidence.")
        return " ".join(parts) if parts else "No prior activity."

    def _match_owasp(self, endpoint: str) -> Optional[str]:
        ep_lower = endpoint.lower()
        if any(x in ep_lower for x in ("/user/", "/account/", "/profile/", "/order/")):
            return f"{OWASP_API_TOP10['API1']} (object-level access on {endpoint})"
        if any(x in ep_lower for x in ("/login", "/auth", "/token", "/session")):
            return f"{OWASP_API_TOP10['API2']} (authentication endpoint)"
        return None

    # ── Background loader ─────────────────────────────────────────────────

    def _background_load(self) -> None:
        """Load threat intel cache and optionally hit live APIs."""
        known_bad: set = set()

        # Load local cache
        if _CACHE_FILE.exists():
            try:
                data = json.loads(_CACHE_FILE.read_text())
                for ip in data.get("known_bad_ips", []):
                    known_bad.add(ip)
                logger.info(
                    "[KnowledgeAgent] Loaded %d known-bad IPs from cache", len(known_bad)
                )
            except Exception as exc:
                logger.warning("[KnowledgeAgent] Failed to load cache: %s", exc)

        # Optional: AbuseIPDB / GreyNoise enrichment (env-gated)
        abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
        if abuseipdb_key:
            # Stub — wire in actual HTTP call when live API key is available
            logger.info("[KnowledgeAgent] AbuseIPDB key found — live enrichment stub (not yet wired)")

        # Persist to LTM
        self.memory.ltm._knowledge_known_bad = known_bad
        if not hasattr(self.memory.ltm, "_knowledge_ip_history"):
            self.memory.ltm._knowledge_ip_history = {}

        # Post pre-emptive evidence for all known-bad IPs
        for ip in known_bad:
            self.memory.board.post(EvidenceEntry(
                posted_by="KnowledgeAgent",
                key=f"knowledge:known_bad:{ip}",
                value={"ip": ip, "source": "threat_intel_cache"},
                confidence=0.85,
                tags=["knowledge", "threat_intel"],
            ))

        logger.info("[KnowledgeAgent] Warm-up complete. %d IPs indexed.", len(known_bad))
