"""
APISentry Base Agent — OODA Reasoning Loop

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
    """

    MAX_ITERATIONS: int = 3

    def __init__(self, memory: SharedMemory, tools: ToolRegistry):
        self.memory = memory
        self.tools = tools
        self.name = self.__class__.__name__

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
