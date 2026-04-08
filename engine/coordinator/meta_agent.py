"""
APISentry Meta-Agent Orchestrator

Role: Autonomous coordinator that:
  1. Dispatches the active detection agents in parallel (thread pool).
  2. Reads all evidence from the shared board.
  3. Resolves conflicts between agent findings.
  4. Detects compound signals (e.g. High Volume + Bot Timing → Scraping Bot).
  5. Produces a final FusionVerdict with full explainability.

Fusion strategy: weighted vote on confidence scores (XGBoost stacking
is the full production approach; here we use logistic combination which
is equivalent in the 3-agent case and avoids a training dependency).

Key calibrations:
  - is_attack threshold raised 0.45 → 0.60 (reduces false positives)
  - Single-agent majority guard: if only 1/3 agents fires, require conf ≥ 0.80
  - Compound signal: each contributing agent must have conf ≥ 0.70 individually
  - Compound signal confidence boost applied only when both agents are high-quality
"""

from __future__ import annotations
import dataclasses
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from engine.agents.auth_agent import AuthAgent
from engine.agents.base_agent import BaseAgent
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

# ---------------------------------------------------------------------------
# Agent domain map — which threat types each agent is responsible for
# ---------------------------------------------------------------------------

_AGENT_DOMAINS: Dict[str, frozenset] = {
    "VolumeAgent":   frozenset({ThreatType.DOS, ThreatType.SCRAPING}),
    "TemporalAgent": frozenset({ThreatType.BOT_ACTIVITY, ThreatType.SCRAPING}),
    "AuthAgent":     frozenset({ThreatType.BRUTE_FORCE, ThreatType.CREDENTIAL_STUFFING}),
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

    # Agent weight in fusion (can be tuned via ablation)
    _AGENT_WEIGHTS: Dict[str, float] = {
        "VolumeAgent":   1.0,
        "TemporalAgent": 0.9,
        "AuthAgent":     1.0,
    }

    # Attack decision thresholds
    _ATTACK_THRESHOLD          = 0.60   # raised from 0.45
    _SINGLE_AGENT_THRESHOLD    = 0.80   # when only 1/3 agents fires
    _MIN_CONTRIBUTING_AGENTS   = 1      # at least 1 agent with conf >= 0.55

    def __init__(self, memory: SharedMemory, max_workers: int = 3, llm_client=None):
        self.memory = memory
        self.tools = ToolRegistry(memory)
        self.max_workers = max_workers
        self._llm = llm_client  # Optional[LLMClient]

        self._agents: List[BaseAgent] = [
            VolumeAgent(memory, self.tools, llm_client=llm_client),
            TemporalAgent(memory, self.tools, llm_client=llm_client),
            AuthAgent(memory, self.tools, llm_client=llm_client),
        ]

    # ── Public entry point ─────────────────────────────────────────────────

    def run(self, records: List[LogRecord]) -> FusionVerdict:
        """
        Full pipeline:
          1. Clear the evidence board for this batch.
          2. Dispatch agents in parallel.
          3. Fuse findings → verdict.
        """
        # Fresh board for each batch
        self.memory.board.clear()

        logger.info(
            "[MetaAgent] Dispatching %d agents for %d records",
            len(self._agents), len(records),
        )

        # ── Step 1: Parallel agent dispatch ─────────────────────────────
        findings = self._dispatch(records)

        # ── Step 2: Read consolidated evidence board ─────────────────────
        all_evidence = self.tools.call("read_evidence_board")
        logger.info("[MetaAgent] Evidence board has %d entries", len(all_evidence))

        # ── Step 3: Conflict resolution & compound detection ─────────────
        verdict = self._fuse(findings, all_evidence)

        # ── Step 4: Optional LLM meta-fusion ─────────────────────────────
        if self._llm is not None:
            verdict = self._llm_fuse(verdict, findings, all_evidence)

        logger.info(
            "[MetaAgent] Verdict: %s | conf=%.2f | compound=%s",
            verdict.threat_type,
            verdict.confidence_score,
            verdict.compound_signals,
        )
        return verdict

    # ── Parallel dispatch ──────────────────────────────────────────────────

    def _dispatch(self, records: List[LogRecord]) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(agent.run, records): agent for agent in self._agents}
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
                w = self._AGENT_WEIGHTS.get(f.agent_name, 1.0)
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

        # ── Build explanation ─────────────────────────────────────────────
        explanation = self._build_explanation(
            resolved_findings, compound_signals, fused_conf, is_attack
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
    ) -> str:
        lines = []
        if is_attack:
            lines.append(f"⚠️  ATTACK DETECTED (fused confidence={fused_conf:.0%})")
        else:
            lines.append(f"✅  No attack detected (fused confidence={fused_conf:.0%})")

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
