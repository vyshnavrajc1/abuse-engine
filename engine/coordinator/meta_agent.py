"""
Abuse Engine Meta-Agent Orchestrator

Role: Autonomous coordinator that:
  1. Dispatches the active detection agents in parallel (thread pool).
  2. Reads all evidence from the shared board.
  3. Resolves conflicts between agent findings.
  4. Detects compound signals (e.g. High Volume + Bot Timing → Scraping Bot).
  5. Produces a final FusionVerdict with full explainability.

Fusion strategy: weighted vote on confidence scores with XGBoost stacking
layer. The XGB model is a lightweight meta-classifier (n_estimators=50) that
takes per-agent confidence scores as features and predicts the binary attack
label. It is online-fitted from the engine's own verdict history stored in LTM.
During cold-start (< 50 labeled verdicts) the system falls back to the
rule-based weighted vote.
"""

from __future__ import annotations
import dataclasses
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from engine.agents.auth_agent import AuthAgent
from engine.agents.base_agent import BaseAgent
from engine.agents.geo_agent import GeoIPAgent
from engine.agents.knowledge_agent import KnowledgeAgent
from engine.agents.payload_agent import PayloadAgent
from engine.agents.sequence_agent import SequenceAgent
from engine.agents.temporal_agent import TemporalAgent
from engine.agents.volume_agent import VolumeAgent
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import (
    AgentFinding,
    ConfidenceLevel,
    FusionVerdict,
    LogRecord,
    ThreatType,
)


logger = logging.getLogger(__name__)

try:
    from xgboost import XGBClassifier as _XGBClassifier
    _XGB_AVAILABLE = True
except ImportError:
    _XGB_AVAILABLE = False

# Module-level XGB stacker — one model shared across all orchestrator instances
_xgb_stacker: Optional["_XGBClassifier"] = None
_xgb_trained_on: int = 0
_XGB_MIN_SAMPLES = 50          # minimum labeled verdicts before activation
# Feature order: VolumeAgent, TemporalAgent, AuthAgent, PayloadAgent, SequenceAgent, GeoIPAgent, n_active, compound_boost
_XGB_AGENT_ORDER = ["VolumeAgent", "TemporalAgent", "AuthAgent", "PayloadAgent", "SequenceAgent", "GeoIPAgent"]


# ---------------------------------------------------------------------------
# Dispatch plan (triage output)
# ---------------------------------------------------------------------------

@dataclass
class DispatchPlan:
    agents: List[str] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)
    skip_reasons: Dict[str, str] = field(default_factory=dict)

_AGENT_DOMAINS: Dict[str, frozenset] = {
    "VolumeAgent":   frozenset({ThreatType.DOS, ThreatType.SCRAPING}),
    "TemporalAgent": frozenset({ThreatType.BOT_ACTIVITY, ThreatType.SCRAPING}),
    "AuthAgent":     frozenset({ThreatType.BRUTE_FORCE, ThreatType.CREDENTIAL_STUFFING}),
    "PayloadAgent":  frozenset({ThreatType.PORT_SCAN, ThreatType.ENUMERATION}),
    "SequenceAgent": frozenset({ThreatType.SEQUENCE_ABUSE}),
    "GeoIPAgent":    frozenset({ThreatType.GEO_ANOMALY}),
}

# If threat A is active at HIGH confidence, these related threats may have been
# missed by the responsible agent (e.g. DoS often co-occurs with bot timing).
_RELATED_THREATS: Dict[ThreatType, frozenset] = {
    ThreatType.DOS:                 frozenset({ThreatType.BOT_ACTIVITY}),
    ThreatType.CREDENTIAL_STUFFING: frozenset({ThreatType.BOT_ACTIVITY}),
    ThreatType.BOT_ACTIVITY:        frozenset({ThreatType.DOS, ThreatType.SCRAPING}),
    ThreatType.SCRAPING:            frozenset({ThreatType.BOT_ACTIVITY, ThreatType.DOS}),
}


# ---------------------------------------------------------------------------
# Compound signal rules (Meta-Agent "intelligence")
# ---------------------------------------------------------------------------

# (required_threat_types, mapped_threat, label, confidence_boost, min_individual_conf)
_COMPOUND_RULES: List[Tuple[frozenset, ThreatType, str, float, float]] = [
    (
        frozenset({ThreatType.DOS, ThreatType.BOT_ACTIVITY}),
        ThreatType.SCRAPING,
        "High Volume + Bot Timing → Scraping/DDoS Bot",
        0.08,
        0.70,   # each agent must have conf >= 0.70 individually
    ),
    (
        frozenset({ThreatType.CREDENTIAL_STUFFING, ThreatType.BOT_ACTIVITY}),
        ThreatType.CREDENTIAL_STUFFING,
        "Credential Stuffing + Bot Timing → Automated Stuffing Campaign",
        0.10,
        0.65,
    ),
    (
        frozenset({ThreatType.BRUTE_FORCE, ThreatType.DOS}),
        ThreatType.BRUTE_FORCE,
        "Brute Force + High Volume → Distributed Brute Force",
        0.08,
        0.70,
    ),
    (
        frozenset({ThreatType.PORT_SCAN, ThreatType.DOS}),
        ThreatType.PORT_SCAN,
        "Port Scan + High Volume → Network Sweep",
        0.10,
        0.70,
    ),
]


# ---------------------------------------------------------------------------
# Meta-Agent
# ---------------------------------------------------------------------------

class MetaAgentOrchestrator:
    """
    Coordinates all detection agents and produces a FusionVerdict.

    Usage:
        orchestrator = MetaAgentOrchestrator(memory)
        verdict = orchestrator.run(records)
    """

    # Cold-start fallback weights — superseded by LTM-derived precision after ≥20 outcomes
    _AGENT_WEIGHTS_FALLBACK: Dict[str, float] = {
        "VolumeAgent":   1.0,
        "TemporalAgent": 0.9,
        "AuthAgent":     1.0,
        "PayloadAgent":  0.9,
        "SequenceAgent": 0.85,
        "GeoIPAgent":    0.80,
    }

    # Attack decision thresholds
    _ATTACK_THRESHOLD          = 0.60   # raised from 0.45
    _SINGLE_AGENT_THRESHOLD    = 0.80   # when only 1/3 agents fires
    _MIN_CONTRIBUTING_AGENTS   = 1      # at least 1 agent with conf >= 0.55

    def __init__(self, memory: SharedMemory, max_workers: int = 3, llm_client=None):
        self.memory = memory
        self.max_workers = max_workers
        self._llm = llm_client  # Optional[LLMClient]

        # KnowledgeAgent must be created before ToolRegistry so the tools
        # can reference it.  It runs a warm-up thread in the background.
        self._knowledge = KnowledgeAgent(memory)
        self._knowledge.warm_up()

        self.tools = ToolRegistry(memory, knowledge_agent=self._knowledge)

        self._agents: List[BaseAgent] = [
            VolumeAgent(memory, self.tools, llm_client=llm_client),
            TemporalAgent(memory, self.tools, llm_client=llm_client),
            AuthAgent(memory, self.tools, llm_client=llm_client),
            PayloadAgent(memory, self.tools, llm_client=llm_client),
            SequenceAgent(memory, self.tools, llm_client=llm_client),
            GeoIPAgent(memory, self.tools, llm_client=llm_client),
        ]

    # ── Public entry point ─────────────────────────────────────────────────

    def run(self, records: List[LogRecord]) -> FusionVerdict:
        """
        Full pipeline:
          1. Clear the evidence board for this batch.
          2. Triage: decide which agents are warranted.
          3. Dispatch warranted agents in parallel.
          4. Fuse findings → verdict.
        """
        # Fresh board for each batch
        self.memory.board.clear()
        # Increment global batch counter every batch (used by agents for warmup)
        self.memory.ltm.increment_batch_count()

        logger.info(
            "[MetaAgent] Dispatching agents for %d records",
            len(records),
        )

        # ── Step 1: Triage ───────────────────────────────────────────────
        plan = self._triage(records)
        logger.info(
            "[MetaAgent] Triage: dispatching %s | skipped: %s",
            plan.agents, list(plan.skip_reasons.keys()),
        )

        # ── Step 2: Parallel agent dispatch ─────────────────────────────
        findings = self._dispatch(records, plan)

        # ── Step 3: Read consolidated evidence board ─────────────────────
        all_evidence = self.tools.call("read_evidence_board")
        logger.info("[MetaAgent] Evidence board has %d entries", len(all_evidence))

        # ── Step 4: Conflict resolution & compound detection ─────────────
        verdict = self._fuse(findings, all_evidence, plan)

        # ── Step 4: Optional LLM meta-fusion ─────────────────────────────
        if self._llm is not None:
            verdict = self._llm_fuse(verdict, findings, all_evidence)

        # ── Step 5: Record agent outcomes for self-determined weights ─────
        for f in findings:
            self.memory.ltm.record_agent_outcome(
                f.agent_name,
                predicted_attack=f.threat_detected,
                final_verdict_attack=verdict.is_attack,
            )

        # ── Step 6: Update KnowledgeAgent with verdict outcome ────────────
        top_ips = {r.ip for r in records}
        for ip in top_ips:
            self.tools.call(
                "update_knowledge_base",
                ip=ip,
                outcome=verdict.is_attack,
                confidence=verdict.confidence_score,
            )

        logger.info(
            "[MetaAgent] Verdict: %s | conf=%.2f | compound=%s",
            verdict.threat_type,
            verdict.confidence_score,
            verdict.compound_signals,
        )
        return verdict

    # ── XGBoost stacking helpers ───────────────────────────────────────────

    def _xgb_feature_vector(
        self,
        findings: List[AgentFinding],
        compound_boost: float,
    ) -> List[float]:
        """Build a fixed-length feature vector for XGB stacking."""
        # Per-agent confidence scores (0.0 if agent not in this batch)
        conf_by_agent: Dict[str, float] = {
            f.agent_name: f.confidence_score for f in findings
        }
        features = [conf_by_agent.get(name, 0.0) for name in _XGB_AGENT_ORDER]
        # Aggregate features
        features.append(float(sum(1 for f in findings if f.threat_detected)))  # n_active
        features.append(compound_boost)
        return features

    def _retrain_xgb(self) -> None:
        """Refit XGBClassifier on accumulated verdict history from LTM."""
        global _xgb_stacker, _xgb_trained_on
        if not _XGB_AVAILABLE:
            return

        samples = self.memory.ltm.get_verdict_samples()
        n = len(samples)
        if n < _XGB_MIN_SAMPLES:
            return

        # Check if both classes present AND minimum positive ratio (avoid suppression bias)
        labels = [s[1] for s in samples]
        if len(set(labels)) < 2:
            return
        pos_ratio = sum(labels) / len(labels)
        if pos_ratio < 0.05:
            # XGB trained on <5% positive samples would suppress real attacks;
            # wait until the dataset has enough positive examples.
            return

        if _xgb_stacker is not None and _xgb_trained_on >= n - 5:
            return  # No significant new data; skip refit

        X = np.array([s[0] for s in samples])
        y = np.array([s[1] for s in samples])

        _xgb_stacker = _XGBClassifier(
            n_estimators=50,
            max_depth=3,
            learning_rate=0.1,
            use_label_encoder=False,
            eval_metric="logloss",
            verbosity=0,
            n_jobs=1,
            random_state=42,
        )
        _xgb_stacker.fit(X, y)
        _xgb_trained_on = n
        logger.debug("[MetaAgent] XGB stacker retrained on %d samples", n)

    def _xgb_predict_proba(self, features: List[float]) -> Optional[float]:
        """
        Return P(attack=1) from the XGB stacker, or None if not trained.
        """
        if not _XGB_AVAILABLE or _xgb_stacker is None:
            return None
        x = np.array([features])
        return float(_xgb_stacker.predict_proba(x)[0][1])

    # ── Triage ─────────────────────────────────────────────────────────────

    def _triage(self, records: List[LogRecord]) -> DispatchPlan:
        """
        Fast (<1ms) pre-dispatch scan. Decides which agents are warranted
        based on cheap surface signals. Thresholds adapt from LTM after warmup.
        """
        plan = DispatchPlan()
        if not records:
            return plan

        # ── Fast observations ────────────────────────────────────────────
        n_4xx = sum(1 for r in records if r.status in (401, 403))

        # Sample first 50 for rough dom_ratio (no full Counter needed)
        sample = records[:50]
        sample_size = len(sample)
        from collections import Counter as _Counter
        sample_ip_counts = _Counter(r.ip for r in sample)
        top_ip_count = sample_ip_counts.most_common(1)[0][1] if sample_ip_counts else 0
        rough_dom_ratio = top_ip_count / sample_size if sample_size > 0 else 0.0

        timestamps_ms = [r.timestamp.timestamp() * 1000.0 for r in records]
        ts_span_ms = max(timestamps_ms) - min(timestamps_ms) if len(timestamps_ms) > 1 else 0.0

        distinct_endpoints = len({r.endpoint_template or r.endpoint for r in records})

        known_bad_present = self._knowledge.has_known_bad_in_batch(records)

        # ── Adaptive dispatch thresholds from LTM ────────────────────────
        dom_mean, dom_std = self.memory.ltm.get_batch_distribution("VolumeAgent", "dom_ratio")
        ltm_dispatch_vol = (dom_mean + dom_std) if (dom_mean is not None and dom_std is not None) else 0.50

        # ── Dispatch rules ────────────────────────────────────────────────
        if known_bad_present:
            plan.agents = ["VolumeAgent", "TemporalAgent", "AuthAgent", "PayloadAgent", "SequenceAgent", "GeoIPAgent"]
            plan.reasoning.append("known_bad IP in batch — dispatching ALL agents")
            return plan

        if n_4xx > 0:
            plan.agents.append("AuthAgent")
            plan.reasoning.append(f"n_4xx={n_4xx} → AuthAgent warranted")
        else:
            plan.skip_reasons["AuthAgent"] = f"n_4xx=0"

        if rough_dom_ratio > ltm_dispatch_vol:
            plan.agents.append("VolumeAgent")
            plan.reasoning.append(
                f"rough_dom_ratio={rough_dom_ratio:.2f} > {ltm_dispatch_vol:.2f} → VolumeAgent warranted"
            )
        else:
            # Always dispatch VolumeAgent: the 50-sample rough ratio can miss mid-window floods
            # (e.g. DoS Hulk where attacker IP appears after record 50). VolumeAgent uses the
            # full 500-record window and will quickly return INSUFFICIENT_DATA on benign batches.
            plan.agents.append("VolumeAgent")
            plan.reasoning.append(
                f"rough_dom_ratio={rough_dom_ratio:.2f} <= {ltm_dispatch_vol:.2f} but "
                f"VolumeAgent always dispatched (full-window analysis)"
            )

        if ts_span_ms > 200:
            plan.agents.append("TemporalAgent")
            plan.reasoning.append(
                f"ts_span_ms={ts_span_ms:.0f} > 200 → TemporalAgent warranted"
            )
        else:
            plan.skip_reasons["TemporalAgent"] = f"ts_span_ms={ts_span_ms:.0f} <= 200"

        if distinct_endpoints >= 5:
            plan.agents.append("PayloadAgent")
            plan.reasoning.append(
                f"distinct_endpoints={distinct_endpoints} >= 5 → PayloadAgent warranted"
            )
        else:
            plan.skip_reasons["PayloadAgent"] = f"distinct_endpoints={distinct_endpoints} < 5"

        if distinct_endpoints >= 3:
            plan.agents.append("SequenceAgent")
            plan.reasoning.append(
                f"distinct_endpoints={distinct_endpoints} >= 3 → SequenceAgent warranted"
            )
        else:
            plan.skip_reasons["SequenceAgent"] = f"distinct_endpoints={distinct_endpoints} < 3"

        # GeoIPAgent: always dispatch (no-op on private IPs, negligible cost)
        plan.agents.append("GeoIPAgent")
        plan.reasoning.append("GeoIPAgent always dispatched (offline-first, negligible cost)")

        # Ensure at least one agent always runs (fallback: dispatch all)
        if not plan.agents:
            plan.agents = ["VolumeAgent", "TemporalAgent", "AuthAgent", "PayloadAgent", "SequenceAgent", "GeoIPAgent"]
            plan.reasoning.append("no triage signals — dispatching all agents as fallback")
            plan.skip_reasons.clear()

        return plan

    # ── Parallel dispatch ──────────────────────────────────────────────────

    def _dispatch(self, records: List[LogRecord], plan: Optional[DispatchPlan] = None) -> List[AgentFinding]:
        active_names = set(plan.agents) if plan else {a.__class__.__name__ for a in self._agents}
        active_agents = [a for a in self._agents if a.__class__.__name__ in active_names]

        # Agents skipped by triage still emit a "no finding" result so fusion
        # has the full 3-finding list (preserves existing test expectations).
        skipped_names = {a.__class__.__name__ for a in self._agents} - active_names
        skipped_findings: List[AgentFinding] = []
        for a in self._agents:
            if a.__class__.__name__ in skipped_names:
                from schemas.models import AgentFinding, ConfidenceLevel
                skipped_findings.append(AgentFinding(
                    agent_name=a.__class__.__name__,
                    threat_detected=False,
                    confidence=ConfidenceLevel.LOW,
                    confidence_score=0.0,
                    indicators=[],
                    reasoning_trace=[
                        f"[triage] skipped — {plan.skip_reasons.get(a.__class__.__name__, 'triage')}"
                    ] if plan else [],
                ))

        findings: List[AgentFinding] = list(skipped_findings)
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(agent.run, records): agent for agent in active_agents}
            for future in as_completed(futures):
                agent = futures[future]
                try:
                    finding = future.result()
                    findings.append(finding)
                    logger.debug(
                        "[MetaAgent] %s → threat=%s conf=%.2f",
                        finding.agent_name, finding.threat_type, finding.confidence_score,
                    )
                except Exception as exc:
                    logger.error("[MetaAgent] %s failed: %s", agent.name, exc, exc_info=True)
        return findings

    # ── Fusion logic ────────────────────────────────────────────────────────

    def _fuse(
        self,
        findings: List[AgentFinding],
        evidence: List[Dict],
        plan: Optional[DispatchPlan] = None,
    ) -> FusionVerdict:

        active = [f for f in findings if f.threat_detected]
        all_threat_types = {f.threat_type for f in active}

        # ── Compound signal detection (with per-agent minimum confidence) ──
        compound_signals: List[str] = []
        compound_threat: Optional[ThreatType] = None
        compound_boost: float = 0.0

        # Build a lookup: threat_type → best confidence for that threat
        threat_conf: Dict[ThreatType, float] = {}
        for f in active:
            if f.threat_type not in threat_conf:
                threat_conf[f.threat_type] = f.confidence_score
            else:
                threat_conf[f.threat_type] = max(threat_conf[f.threat_type], f.confidence_score)

        for required, mapped_threat, label, boost, min_conf in _COMPOUND_RULES:
            if required.issubset(all_threat_types):
                # Verify all contributing agents meet the individual minimum
                if all(threat_conf.get(t, 0.0) >= min_conf for t in required):
                    compound_signals.append(label)
                    compound_threat = mapped_threat
                    compound_boost = max(compound_boost, boost)
                else:
                    logger.debug(
                        "[MetaAgent] Compound rule '%s' skipped — agents don't meet min_conf %.2f",
                        label, min_conf,
                    )

        # ── Conflict resolution ──────────────────────────────────────────
        resolved_findings = self._resolve_conflicts(findings)

        # ── Weighted confidence fusion ────────────────────────────────────
        total_weight = 0.0
        weighted_conf = 0.0
        contributing = []

        for f in resolved_findings:
            if f.threat_detected:
                w = self.memory.ltm.get_agent_precision(f.agent_name)
                if w == 1.0:
                    # Still in fallback — use per-agent cold-start weight
                    w = self._AGENT_WEIGHTS_FALLBACK.get(f.agent_name, 1.0)
                weighted_conf += f.confidence_score * w
                total_weight += w
                contributing.append(f.agent_name)

        if total_weight > 0:
            fused_conf = min(1.0, weighted_conf / total_weight + compound_boost)
        else:
            fused_conf = 0.0

        # ── Final threat type selection ───────────────────────────────────
        if compound_threat and compound_signals:
            final_threat = compound_threat
        elif active:
            best = max(active, key=lambda f: f.confidence_score)
            final_threat = best.threat_type
        else:
            final_threat = ThreatType.NONE

        # ── Attack decision with calibrated thresholds ────────────────────
        n_contributing = len(contributing)

        if n_contributing == 0:
            is_attack = False
        elif n_contributing == 1:
            # Single agent: require higher confidence to avoid spurious verdicts
            single_conf = max(
                (f.confidence_score for f in resolved_findings if f.threat_detected),
                default=0.0,
            )
            is_attack = single_conf >= self._SINGLE_AGENT_THRESHOLD and final_threat != ThreatType.NONE
            if is_attack:
                logger.debug(
                    "[MetaAgent] Single-agent verdict — enforced high threshold (%.2f >= %.2f)",
                    single_conf, self._SINGLE_AGENT_THRESHOLD,
                )
        else:
            # Multiple agents agree — use the standard fused threshold
            is_attack = fused_conf >= self._ATTACK_THRESHOLD and final_threat != ThreatType.NONE

        # ── XGBoost stacking layer (overrides rule-based verdict if trained) ──
        features = self._xgb_feature_vector(resolved_findings, compound_boost)
        # Record rule-based verdict BEFORE XGB override to avoid circular training bias
        rule_is_attack = is_attack
        self.memory.ltm.record_verdict_sample(features, int(rule_is_attack))
        self._retrain_xgb()
        # Don't let XGB downgrade a high-confidence single-agent verdict —
        # XGB is trained on historical data and may not have seen the current attack type yet.
        # Only apply XGB blend when the rule-based verdict is ambiguous (not a clear high-conf single agent).
        _single_high_conf = (n_contributing == 1 and rule_is_attack)
        xgb_proba = self._xgb_predict_proba(features)
        if xgb_proba is not None and not _single_high_conf:
            # Blend: 0.4 × rule-based + 0.6 × xgb
            blended = 0.4 * fused_conf + 0.6 * xgb_proba
            is_attack_xgb = blended >= self._ATTACK_THRESHOLD and final_threat != ThreatType.NONE
            if is_attack_xgb != is_attack:
                logger.debug(
                    "[MetaAgent] XGB stacker overrides rule verdict: "
                    "rule=%s xgb_proba=%.3f blended=%.3f",
                    is_attack, xgb_proba, blended,
                )
            is_attack = is_attack_xgb
            fused_conf = min(1.0, blended)

        # ── Build explanation ─────────────────────────────────────────────
        explanation = self._build_explanation(
            resolved_findings, compound_signals, fused_conf, is_attack, plan
        )

        return FusionVerdict(
            is_attack=is_attack,
            threat_type=final_threat if is_attack else ThreatType.NONE,
            confidence_score=round(fused_conf, 3),
            contributing_agents=contributing,
            compound_signals=compound_signals,
            explanation=explanation,
            agent_findings=resolved_findings,
        )

    # ── Conflict resolution ────────────────────────────────────────────────

    def _resolve_conflicts(self, findings: List[AgentFinding]) -> List[AgentFinding]:
        """
        If Agent A says 'no threat' (LOW confidence) and Agent B says 'threat'
        (HIGH confidence) for a related threat type, escalate Agent A's finding
        to MEDIUM confidence so it contributes proportionally to fusion.

        Example: VolumeAgent=DoS HIGH + TemporalAgent=NONE →
          DoS often co-occurs with bot timing; escalate TemporalAgent to MEDIUM
          with a cautionary confidence score so the fused verdict reflects the
          cross-agent signal without fully endorsing it.
        """
        resolved = list(findings)

        # Build {threat_type: confidence_score} for all HIGH-confidence detections
        high_conf_threats: Dict[ThreatType, float] = {
            f.threat_type: f.confidence_score
            for f in findings
            if f.threat_detected and f.confidence == ConfidenceLevel.HIGH
        }

        if not high_conf_threats:
            return resolved

        for i, f in enumerate(resolved):
            if f.threat_detected or f.confidence != ConfidenceLevel.LOW:
                continue

            # Only escalate agents that had AT LEAST SOME signal (conf > 0.1).
            # Agents that returned pure INSUFFICIENT_DATA (conf ≈ 0) have no
            # evidence to corroborate the related threat — escalating them
            # without any signal would amplify unrelated FPs.
            if f.confidence_score < 0.10:
                continue

            domain = _AGENT_DOMAINS.get(f.agent_name, frozenset())

            for active_threat, active_conf in high_conf_threats.items():
                related = _RELATED_THREATS.get(active_threat, frozenset())
                implicated = domain & related  # threat types this agent should have caught

                if not implicated:
                    continue

                escalated_type = next(iter(implicated))
                escalated_conf = round(active_conf * 0.45, 3)  # conservative fraction

                resolved[i] = dataclasses.replace(
                    f,
                    threat_detected=True,
                    threat_type=escalated_type,
                    confidence=ConfidenceLevel.MEDIUM,
                    confidence_score=escalated_conf,
                    indicators=f.indicators + [
                        f"conflict_escalation: {active_threat.value} detected at "
                        f"{active_conf:.0%} by another agent — {f.agent_name} "
                        f"escalated to {escalated_type.value} MEDIUM"
                    ],
                )
                logger.info(
                    "[MetaAgent] Conflict resolved: %s escalated to %s MEDIUM (conf=%.2f) "
                    "— related HIGH threat %s from another agent",
                    f.agent_name, escalated_type.value, escalated_conf, active_threat.value,
                )
                break  # one escalation per silent agent

        return resolved

    # ── Explainability ─────────────────────────────────────────────────────

    def _build_explanation(
        self,
        findings: List[AgentFinding],
        compound_signals: List[str],
        fused_conf: float,
        is_attack: bool,
        plan: Optional[DispatchPlan] = None,
    ) -> str:
        lines = []
        if is_attack:
            lines.append(f"⚠️  ATTACK DETECTED (fused confidence={fused_conf:.0%})")
        else:
            lines.append(f"✅  No attack detected (fused confidence={fused_conf:.0%})")

        if plan and plan.reasoning:
            lines.append("Triage:")
            for r in plan.reasoning:
                lines.append(f"  → {r}")
        if plan and plan.skip_reasons:
            for agent, reason in plan.skip_reasons.items():
                lines.append(f"  ⊘ [{agent}] skipped — {reason}")

        if compound_signals:
            lines.append("Compound signals:")
            for sig in compound_signals:
                lines.append(f"  • {sig}")

        for f in findings:
            status = "⚠" if f.threat_detected else "✓"
            lines.append(
                f"{status} [{f.agent_name}] threat={f.threat_type.value} "
                f"conf={f.confidence_score:.2f} ({f.confidence.value})"
            )
            for ind in f.indicators[:3]:  # top 3 indicators per agent
                lines.append(f"    → {ind}")

        return "\n".join(lines)

    # ── LLM meta-fusion ────────────────────────────────────────────────────

    def _llm_fuse(
        self,
        rule_verdict: FusionVerdict,
        findings: List[AgentFinding],
        evidence: List[Dict],
    ) -> FusionVerdict:
        """
        Ask the LLM to review all agent findings and produce a final authoritative
        verdict. Falls back to rule_verdict on any error.
        """
        from engine.llm.prompts import META_SYSTEM_PROMPT, build_meta_user_prompt
        from engine.llm.client import LLMError

        agent_findings_data = [
            {
                "agent": f.agent_name,
                "is_attack": f.threat_detected,
                "threat_type": f.threat_type.value,
                "confidence": f.confidence_score,
                "indicators": f.indicators[:5],
            }
            for f in findings
        ]

        user = build_meta_user_prompt(
            agent_findings=agent_findings_data,
            evidence_board=evidence,
            rule_is_attack=rule_verdict.is_attack,
            rule_confidence=rule_verdict.confidence_score,
            rule_compound=rule_verdict.compound_signals,
        )

        try:
            result = self._llm.reason(META_SYSTEM_PROMPT, user)
        except LLMError as exc:
            logger.error("[MetaAgent] LLM fusion failed: %s — using rule-based verdict", exc)
            return rule_verdict

        is_attack   = bool(result.get("is_attack", rule_verdict.is_attack))
        raw_threat  = str(result.get("threat_type", rule_verdict.threat_type.value))
        confidence  = float(result.get("confidence", rule_verdict.confidence_score))
        compound    = result.get("compound_signal")
        reasoning   = str(result.get("reasoning", ""))

        try:
            threat_type = ThreatType(raw_threat)
        except ValueError:
            threat_type = rule_verdict.threat_type
            logger.warning("[MetaAgent] LLM returned unknown threat_type '%s'", raw_threat)

        confidence = max(0.0, min(1.0, confidence))

        new_compound = list(rule_verdict.compound_signals)
        if compound and compound not in new_compound:
            new_compound.append(f"[LLM] {compound}")

        llm_explanation = rule_verdict.explanation + f"\n\n[LLM Meta-Fusion] {reasoning}"

        logger.debug(
            "[MetaAgent] LLM fusion: is_attack=%s threat=%s conf=%.2f (rule: %s %.2f)",
            is_attack, threat_type, confidence,
            rule_verdict.is_attack, rule_verdict.confidence_score,
        )

        return FusionVerdict(
            is_attack=is_attack,
            threat_type=threat_type if is_attack else ThreatType.NONE,
            confidence_score=round(confidence, 3),
            contributing_agents=rule_verdict.contributing_agents,
            compound_signals=new_compound,
            explanation=llm_explanation,
            agent_findings=rule_verdict.agent_findings,
        )
