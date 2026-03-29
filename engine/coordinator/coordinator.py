from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
import logging
import os

from schemas.agent_result import AgentResult, Severity

logger = logging.getLogger(__name__)

# Verdict thresholds
THRESHOLD_SUSPICIOUS = 0.40
THRESHOLD_ATTACK     = 0.70


@dataclass
class CoordinatorResult:
    """Final verdict produced by the coordinator for one user."""
    user_id: str
    final_score: float                      # Weighted combination of all agents
    verdict: str                            # "normal" | "suspicious" | "attack"
    confidence: float                       # 0.0–1.0 (more agents = higher confidence)
    contributing_agents: List[str]          # Which agents flagged this
    all_flags: List[str]                    # Combined flags from all agents
    explanation: str                        # Assembled human-readable XAI text
    agent_scores: Dict[str, float] = field(default_factory=dict)  # Per-agent breakdown
    llm_analysis: Optional[Dict] = field(default=None)  # Filled by LLM layer if enabled


@dataclass
class CoordinatorLLMConfig:
    """
    Configuration for the coordinator's Gemini reasoning layer.

    The LLM is called only for users whose verdict is 'suspicious' or 'attack',
    and only when GEMINI_API_KEY is set (or api_key is passed explicitly).
    """
    api_key: Optional[str] = None          # Falls back to GEMINI_API_KEY env var
    model_name: str = "gemini-1.5-flash"   # Fast + cheap
    temperature: float = 0.1
    max_iterations: int = 5
    min_score_threshold: float = THRESHOLD_SUSPICIOUS  # Only invoke LLM above this


class Coordinator:
    """
    Combines per-user AgentResult objects from behavioral + semantic agents
    and an optional batch-level spatiotemporal result into a single verdict.

    Agent weights reflect relative trust:
      behavioral:       0.45  – per-session time-series behaviour (well validated)
      semantic:         0.35  – API-intent rule matching
      spatio_temporal:  0.20  – network-graph anomaly (batch level, shared across users)

    Optional LLM layer (Gemini ReAct):
      Pass llm_config=CoordinatorLLMConfig() to enrich suspicious/attack verdicts
      with confirmed attack type, MITRE ATT&CK ID, and recommended actions.
      Activates automatically when GEMINI_API_KEY env var is set.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        llm_config: Optional[CoordinatorLLMConfig] = None,
    ):
        self.weights = weights or {
            "behavioral":      0.45,
            "semantic":        0.35,
            "spatio_temporal": 0.20,
        }
        # LLM enrichment layer — lazy-built on first use
        self._llm_config   = llm_config
        self._llm_executor = None   # built on first non-normal verdict

    def combine(
        self,
        agent_results: List[AgentResult],
        spatio_result: Optional[AgentResult] = None,
    ) -> List[CoordinatorResult]:
        """
        Parameters
        ----------
        agent_results:   Flat list of AgentResult from behavioral and semantic agents.
                         Each result must have metadata["user_id"].
        spatio_result:   Single batch-level AgentResult from SpatioTemporalPipeline
                         (same risk score applied to all users in the batch).

        Returns
        -------
        List[CoordinatorResult] sorted by final_score descending.
        """
        # Group per-user results by agent type
        by_user: Dict[str, Dict[str, List[AgentResult]]] = defaultdict(lambda: defaultdict(list))
        for r in agent_results:
            uid = r.metadata.get("user_id", "unknown")
            by_user[uid][r.agent].append(r)

        # Batch-level spatiotemporal values (same for every user)
        spatio_score   = spatio_result.risk_score   if spatio_result else 0.0
        spatio_flags   = spatio_result.flags        if spatio_result else []
        spatio_explain = spatio_result.explanation  if spatio_result else ""

        final_results = []
        for user_id, agent_map in by_user.items():
            agent_scores: Dict[str, float] = {}
            all_flags:    List[str]        = []
            explanations: List[str]        = []
            contributing: List[str]        = []

            # ── Behavioral ────────────────────────────────────────────
            b_results = agent_map.get("behavioral", [])
            if b_results:
                b_score = max(r.risk_score for r in b_results)
                for r in b_results:
                    all_flags.extend(r.flags)
                    if r.risk_score > THRESHOLD_SUSPICIOUS:
                        explanations.append(r.explanation)
                agent_scores["behavioral"] = b_score
                if b_score > THRESHOLD_SUSPICIOUS:
                    contributing.append("behavioral")

            # ── Semantic ──────────────────────────────────────────────
            s_results = agent_map.get("semantic", [])
            if s_results:
                # Dampen by confidence (stored in details)
                s_score = max(r.risk_score * r.details.get("confidence", 1.0) for r in s_results)
                for r in s_results:
                    all_flags.extend(r.flags)
                    if r.risk_score > THRESHOLD_SUSPICIOUS:
                        explanations.append(r.explanation)
                agent_scores["semantic"] = s_score
                if s_score > THRESHOLD_SUSPICIOUS:
                    contributing.append("semantic")

            # ── Spatiotemporal (shared batch score) ───────────────────
            if spatio_result is not None:
                agent_scores["spatio_temporal"] = spatio_score
                all_flags.extend(spatio_flags)
                if spatio_score > THRESHOLD_SUSPICIOUS:
                    contributing.append("spatio_temporal")
                    explanations.append(spatio_explain)

            # ── Weighted combination ──────────────────────────────────
            total_w = sum(self.weights.get(a, 0) for a in agent_scores)
            if total_w > 0:
                final = sum(agent_scores[a] * self.weights.get(a, 0) for a in agent_scores) / total_w
            else:
                final = 0.0
            final = round(min(1.0, max(0.0, final)), 4)

            # ── Confidence ────────────────────────────────────────────
            # 1.0 when all three agents contribute; less when some are missing
            confidence = round(len(agent_scores) / len(self.weights), 2)

            # ── Verdict ───────────────────────────────────────────────
            if final >= THRESHOLD_ATTACK:
                verdict = "attack"
            elif final >= THRESHOLD_SUSPICIOUS:
                verdict = "suspicious"
            else:
                verdict = "normal"

            # ── Explanation ───────────────────────────────────────────
            unique_flags = list(dict.fromkeys(all_flags))
            if contributing:
                explanation = (
                    f"[{verdict.upper()}] User {user_id} — score={final:.3f}  "
                    f"confidence={confidence:.2f}. "
                    f"Flagged by: {', '.join(contributing)}. "
                    + (" | ".join(explanations) if explanations else "")
                )
            else:
                explanation = (
                    f"[NORMAL] User {user_id} — score={final:.3f}. "
                    "No anomalies detected across all agents."
                )

            final_results.append(CoordinatorResult(
                user_id=user_id,
                final_score=final,
                verdict=verdict,
                confidence=confidence,
                contributing_agents=list(contributing),
                all_flags=unique_flags,
                explanation=explanation,
                agent_scores=agent_scores,
            ))

        final_results.sort(key=lambda r: r.final_score, reverse=True)

        # ── Optional LLM enrichment (only for suspicious/attack users) ─
        if self._llm_config is not None:
            for r in final_results:
                if r.verdict != "normal":
                    r.llm_analysis = self._enrich_with_llm(r)

        return final_results

    # ------------------------------------------------------------------
    # LLM enrichment (Gemini ReAct with coordinator-specific tools)
    # ------------------------------------------------------------------

    def _enrich_with_llm(self, result: CoordinatorResult) -> Optional[Dict]:
        """
        Call a Gemini ReAct agent to reason about a suspicious/attack verdict.
        Returns a dict with verdict, confidence, attack_type, mitre_technique,
        reasoning, and recommended_actions.  Never raises \u2014 returns None on error.
        """
        cfg = self._llm_config
        api_key = (cfg.api_key or os.environ.get("GEMINI_API_KEY", "")).strip()
        if not api_key:
            logger.debug("_enrich_with_llm: no GEMINI_API_KEY; skipping.")
            return None

        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            from langgraph.prebuilt import create_react_agent
            from langchain_core.messages import HumanMessage
            from langchain_core.tools import tool

            # ── Build coordinator-specific tools ─────────────────────
            @tool
            def lookup_ip_reputation(ip_address: str) -> str:
                """
                Check whether an IP address is on known threat intelligence blocklists.
                Returns JSON with is_known_bad, categories, confidence, source.
                Always call this for the flagging IPs before forming your verdict.
                """
                # Stub \u2014 swap body for a real AbuseIPDB / VirusTotal call in production
                BAD_PREFIXES = {
                    "10.0.": {"categories": ["botnet", "scanner"],         "confidence": 0.92},
                    "10.1.": {"categories": ["credential_stuffing"],       "confidence": 0.87},
                    "10.2.": {"categories": ["coordinated_scan"],          "confidence": 0.95},
                }
                for prefix, meta in BAD_PREFIXES.items():
                    if ip_address.startswith(prefix):
                        return json.dumps({"ip": ip_address, "is_known_bad": True, **meta,
                                           "source": "mock_threat_feed_v1"})
                return json.dumps({"ip": ip_address, "is_known_bad": False,
                                   "categories": [], "confidence": 1.0, "source": "none"})

            @tool
            def query_mitre_attack(attack_description: str) -> str:
                """
                Map an attack description to the closest MITRE ATT\u0026CK technique.
                Parameters: attack_description \u2014 short description of the suspected pattern.
                Returns JSON with technique_id, technique_name, tactic, description,
                and recommended_mitigations.
                """
                KB = [
                    {"keywords": ["brute", "password", "credential", "login"],
                     "technique_id": "T1110", "technique_name": "Brute Force",
                     "tactic": "Credential Access",
                     "description": "Adversary attempts to gain access by guessing credentials.",
                     "recommended_mitigations": ["Account lockout policy", "MFA", "Rate limiting"]},
                    {"keywords": ["scan", "port", "discovery", "recon", "probe"],
                     "technique_id": "T1595", "technique_name": "Active Scanning",
                     "tactic": "Reconnaissance",
                     "description": "Adversary actively scans infrastructure to gather information.",
                     "recommended_mitigations": ["Network segmentation", "IDS/IPS", "Block scanners"]},
                    {"keywords": ["bot", "scrape", "automated", "flood", "burst"],
                     "technique_id": "T1498", "technique_name": "Network Denial of Service",
                     "tactic": "Impact",
                     "description": "Adversary uses automated traffic to overwhelm services.",
                     "recommended_mitigations": ["Rate limiting", "CAPTCHA", "Block C2 IPs"]},
                    {"keywords": ["enum", "sequential", "idor", "bola", "object"],
                     "technique_id": "T1212", "technique_name": "Exploitation for Credential Access",
                     "tactic": "Credential Access",
                     "description": "Adversary enumerates object IDs to access unauthorized resources.",
                     "recommended_mitigations": ["BOLA/IDOR remediation", "Object-level auth checks"]},
                ]
                desc_lower = attack_description.lower()
                for entry in KB:
                    if any(kw in desc_lower for kw in entry["keywords"]):
                        return json.dumps(entry)
                return json.dumps({"technique_id": "T0000", "technique_name": "Unknown",
                                   "tactic": "Unknown", "description": "No match found.",
                                   "recommended_mitigations": ["Escalate to Tier-2 analyst"]})

            # ── Lazy-build the agent ──────────────────────────────────
            if self._llm_executor is None:
                llm = ChatGoogleGenerativeAI(
                    model=cfg.model_name,
                    google_api_key=api_key,
                    temperature=cfg.temperature,
                )
                _COORDINATOR_SYSTEM = (
                    "You are a senior cybersecurity analyst reviewing a multi-agent "
                    "API abuse detection verdict. You have the final weighted risk scores "
                    "from three specialized detectors (behavioral, semantic, spatiotemporal) "
                    "and the flags they raised. Your job is to:\\n"
                    "1. Call lookup_ip_reputation on any suspicious source IPs.\\n"
                    "2. Call query_mitre_attack with a short description of the attack pattern.\\n"
                    "3. Output ONLY a valid JSON object with keys:\\n"
                    "   verdict (confirmed_threat|likely_fp|uncertain), confidence (0-1),\\n"
                    "   attack_type (string), mitre_technique (string), reasoning (string),\\n"
                    "   recommended_actions (list[str]).\\n"
                    "No markdown, no extra text \u2014 pure JSON only."
                )
                self._llm_executor = create_react_agent(
                    model=llm,
                    tools=[lookup_ip_reputation, query_mitre_attack],
                    prompt=_COORDINATOR_SYSTEM,
                )

            # ── Build prompt from CoordinatorResult ──────────────────
            flags_str  = ", ".join(result.all_flags[:10]) or "none"
            agents_str = json.dumps(result.agent_scores, indent=2)
            prompt = (
                f"MULTI-AGENT VERDICT REVIEW\\n"
                f"User ID      : {result.user_id}\\n"
                f"Final score  : {result.final_score:.4f}\\n"
                f"Verdict      : {result.verdict.upper()}\\n"
                f"Confidence   : {result.confidence:.2f}\\n"
                f"Agent scores :\\n{agents_str}\\n"
                f"Flags        : {flags_str}\\n"
                f"Explanation  : {result.explanation[:300]}\\n\\n"
                "Investigate using your tools and return your verdict as JSON."
            )

            # ── Run ───────────────────────────────────────────────────
            response = self._llm_executor.invoke(
                {"messages": [HumanMessage(content=prompt)]},
                config={"recursion_limit": cfg.max_iterations * 2 + 2},
            )

            messages  = response.get("messages", [])
            raw_text  = ""
            tools_used = []

            from langchain_core.messages import AIMessage, ToolMessage
            for msg in reversed(messages):
                if isinstance(msg, AIMessage):
                    content = msg.content
                    text = (
                        "".join(b.get("text", "") if isinstance(b, dict) else str(b)
                                for b in content)
                        if isinstance(content, list) else str(content)
                    )
                    if text and not getattr(msg, "tool_calls", None):
                        raw_text = text
                        break
                    elif text:
                        raw_text = text
            for msg in messages:
                if isinstance(msg, ToolMessage) and getattr(msg, "name", None):
                    tools_used.append(msg.name)

            # Strip ``` fences
            import re as _re
            clean = _re.sub(r"```(?:json)?|```", "", raw_text).strip()
            result_dict = json.loads(clean)
            result_dict["tool_calls_made"] = list(set(tools_used))
            logger.info("Coordinator LLM: user=%s verdict=%s confidence=%.2f tools=%s",
                        result.user_id, result_dict.get("verdict"),
                        result_dict.get("confidence", 0), tools_used)
            return result_dict

        except Exception as exc:
            logger.warning("Coordinator LLM enrichment failed for %s: %s",
                           result.user_id, exc, exc_info=True)
            return None
