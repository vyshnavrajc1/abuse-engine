"""
Abuse Engine Base Agent — OODA Reasoning Loop

Every detection agent subclasses BaseAgent and implements:
  - observe()      → collect raw signals from SharedMemory
  - orient()       → build context (read evidence board, query tools)
  - hypothesize()  → form candidate threat hypothesis
  - investigate()  → call tools to validate / refute hypothesis
  - evaluate()     → decide: Conclude | Revise | InsufficientData
  - conclude()     → produce AgentFinding

The loop:
  OBSERVE → ORIENT → HYPOTHESIZE → INVESTIGATE → EVALUATE
                         ↑__________________|  (revise)
                                       ↓  (conclude)
                                   CONCLUDE
"""

from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, ConfidenceLevel, LogRecord, ThreatType


logger = logging.getLogger(__name__)


class LoopDecision(str, Enum):
    CONCLUDE = "CONCLUDE"
    REVISE = "REVISE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


@dataclass
class AgentContext:
    """Mutable working state accumulated across OODA iterations."""
    records: List[LogRecord] = field(default_factory=list)
    hypothesis: Optional[str] = None
    threat_type: ThreatType = ThreatType.NONE
    confidence_score: float = 0.0
    indicators: List[str] = field(default_factory=list)
    raw_metrics: Dict[str, Any] = field(default_factory=dict)
    reasoning_trace: List[str] = field(default_factory=list)
    iteration: int = 0

    def log(self, msg: str) -> None:
        self.reasoning_trace.append(f"[iter={self.iteration}] {msg}")


# ---------------------------------------------------------------------------
# Base Agent
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    """
    Abstract base. Subclasses implement the six OODA methods.
    The run() method drives the loop with a configurable max_iterations guard.

    Optional LLM integration:
      Pass an LLMClient instance as `llm_client`. After the rule-based OODA loop
      completes, the LLM is called once with all gathered metrics + tool evidence
      and its verdict overrides the rule-based finding. The rule-based result is
      included in the prompt as a calibration hint.
    """

    MAX_ITERATIONS: int = 3

    def __init__(self, memory: SharedMemory, tools: ToolRegistry, llm_client=None):
        self.memory = memory
        self.tools = tools
        self.name = self.__class__.__name__
        self._llm = llm_client   # Optional[LLMClient]

    # ── Public entry point ─────────────────────────────────────────────────

    def run(self, records: List[LogRecord]) -> AgentFinding:
        """
        Execute the OODA loop for a batch of log records.
        Returns an AgentFinding regardless of outcome.
        """
        ctx = AgentContext(records=records)
        ctx.log(f"OBSERVE: received {len(records)} records")

        # ① OBSERVE
        self.observe(ctx)

        # ② ORIENT
        ctx.log("ORIENT: building context")
        self.orient(ctx)

        # ③→④→⑤ loop
        while ctx.iteration < self.MAX_ITERATIONS:
            ctx.iteration += 1

            # ③ HYPOTHESIZE
            ctx.log(f"HYPOTHESIZE: {ctx.hypothesis or 'none yet'}")
            self.hypothesize(ctx)

            # ④ INVESTIGATE
            ctx.log("INVESTIGATE: calling tools")
            self.investigate(ctx)

            # ⑤ EVALUATE
            decision = self.evaluate(ctx)
            ctx.log(f"EVALUATE → {decision}")

            if decision == LoopDecision.CONCLUDE:
                break
            elif decision == LoopDecision.INSUFFICIENT_DATA:
                ctx.confidence_score = min(ctx.confidence_score, 0.3)
                break
            # else REVISE → loop again

        # ⑥ CONCLUDE
        finding = self.conclude(ctx)

        # ⑦ LLM OVERRIDE (if client is wired in)
        if self._llm is not None:
            finding = self._llm_conclude(ctx, finding)

        logger.debug("[%s] finding=%s conf=%.2f", self.name, finding.threat_type, finding.confidence_score)
        return finding

    # ── Abstract OODA steps ────────────────────────────────────────────────

    @abstractmethod
    def observe(self, ctx: AgentContext) -> None:
        """Pull raw data / signals from memory into ctx."""

    @abstractmethod
    def orient(self, ctx: AgentContext) -> None:
        """Enrich context: read evidence board, compute derived fields."""

    @abstractmethod
    def hypothesize(self, ctx: AgentContext) -> None:
        """Form or revise threat hypothesis based on current ctx."""

    @abstractmethod
    def investigate(self, ctx: AgentContext) -> None:
        """Call tools to validate / refute current hypothesis."""

    @abstractmethod
    def evaluate(self, ctx: AgentContext) -> LoopDecision:
        """Decide whether to Conclude, Revise, or flag InsufficientData."""

    @abstractmethod
    def conclude(self, ctx: AgentContext) -> AgentFinding:
        """Package ctx into a final AgentFinding."""

    # ── Helpers ────────────────────────────────────────────────────────────

    def _score_to_confidence(self, score: float) -> ConfidenceLevel:
        if score >= 0.75:
            return ConfidenceLevel.HIGH
        elif score >= 0.45:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def _make_finding(
        self,
        ctx: AgentContext,
        threat_detected: bool,
    ) -> AgentFinding:
        return AgentFinding(
            agent_name=self.name,
            threat_detected=threat_detected,
            threat_type=ctx.threat_type if threat_detected else ThreatType.NONE,
            confidence=self._score_to_confidence(ctx.confidence_score),
            confidence_score=round(ctx.confidence_score, 3),
            indicators=ctx.indicators,
            raw_metrics=ctx.raw_metrics,
            reasoning_trace=ctx.reasoning_trace,
        )

    def _post_evidence(self, key: str, value: Any, confidence: float, tags: List[str] = None):
        self.tools.call(
            "post_to_evidence_board",
            posted_by=self.name,
            key=key,
            value=value,
            confidence=confidence,
            tags=tags or [],
        )

    # ── LLM override ──────────────────────────────────────────────────────

    def _llm_conclude(self, ctx: AgentContext, rule_finding: AgentFinding) -> AgentFinding:
        """
        Call the LLM with all gathered evidence and return an LLM-driven finding.
        Falls back to rule_finding on any LLM error.
        """
        from engine.llm.prompts import AGENT_SYSTEM_PROMPTS, build_agent_user_prompt
        from engine.llm.client import LLMError

        system = AGENT_SYSTEM_PROMPTS.get(self.name)
        if system is None:
            logger.warning("[%s] No LLM system prompt registered — using rule-based verdict", self.name)
            return rule_finding

        user = build_agent_user_prompt(
            agent_name=self.name,
            raw_metrics=ctx.raw_metrics,
            indicators=ctx.indicators,
            rule_verdict=rule_finding.threat_detected,
            rule_confidence=rule_finding.confidence_score,
            reasoning_trace=ctx.reasoning_trace,
        )

        try:
            result = self._llm.reason(system, user)
        except LLMError as exc:
            logger.error("[%s] LLM call failed: %s — falling back to rule-based", self.name, exc)
            return rule_finding

        # Parse and validate LLM output
        is_attack   = bool(result.get("is_attack", rule_finding.threat_detected))
        raw_threat  = str(result.get("threat_type", rule_finding.threat_type.value))
        confidence  = float(result.get("confidence", rule_finding.confidence_score))
        reasoning   = str(result.get("reasoning", ""))

        try:
            threat_type = ThreatType(raw_threat)
        except ValueError:
            threat_type = rule_finding.threat_type
            logger.warning("[%s] LLM returned unknown threat_type '%s'", self.name, raw_threat)

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        # Append LLM reasoning to trace
        ctx.reasoning_trace.append(f"[LLM] {reasoning}")

        logger.debug(
            "[%s] LLM verdict: is_attack=%s threat=%s conf=%.2f (rule was: %s %.2f)",
            self.name, is_attack, threat_type, confidence,
            rule_finding.threat_detected, rule_finding.confidence_score,
        )

        # Build updated AgentContext for _make_finding
        ctx.confidence_score = confidence
        ctx.threat_type = threat_type if is_attack else ThreatType.NONE

        return self._make_finding(ctx, is_attack)
