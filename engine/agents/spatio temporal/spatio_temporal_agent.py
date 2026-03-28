"""
spatio_temporal_agent.py – Production-grade spatio-temporal anomaly detection.

What this module provides
-------------------------
1. SpatioTemporalScoringNode
   An agent node that:
   • Slices the incoming events into overlapping time windows (sliding window
     with configurable size and stride).
   • Extracts graph-topology features from each window via WindowFeatureExtractor.
   • Scores every window against the pre-trained IsolationForest in ModelRegistry.
   • Reports the maximum risk score across all windows, the index of the worst
     window, and per-window details for downstream alerting.

2. build_spatio_temporal_graph()
   Assembles the base pipeline:
       validate → score → severity → END
                ↘ skip → END

3. SpatioTemporalPipeline
   High-level façade for production use:
   • Accepts raw events (online or batch).
   • Wraps them in AgentState and runs the graph.
   • Exposes train_baseline() and start_scheduled_retraining().
   • NEW: Accepts an optional LLMConfig to activate the Gemini reasoning layer,
     which extends the graph to:
         validate → score → severity → llm_analysis → END
     The llm_analysis node uses LangChain + Gemini with three tools
     (IP reputation, threat intel, feature explainer) to produce a structured
     verdict (confirmed_threat / likely_fp / uncertain) stored in
     state.metadata["llm_analysis"].
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timedelta
from typing import Callable, List, Optional

import numpy as np

from agent_framework import (
    END,
    AgentGraph,
    make_severity_node,
    make_validation_node,
    no_op,
    skip_router,
)
from model_registry import ModelRegistry, WindowFeatureExtractor
from models import AgentResult, AgentState, CanonicalEvent, Severity
from sliding_window import SlidingWindowManager

# Optional: LLM reasoning layer (requires langchain-google-genai)
try:
    from llm_agent_node import LLMConfig, build_agentic_spatio_temporal_graph as _build_agentic
    _LLM_AVAILABLE = True
except ImportError:
    _LLM_AVAILABLE = False
    LLMConfig = None  # type: ignore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

class SpatioTemporalConfig:
    """All tuneable knobs in one place — easier to override in tests."""

    def __init__(
        self,
        window_size: timedelta = timedelta(minutes=5),
        stride: timedelta = timedelta(minutes=2, seconds=30),
        min_window_events: int = 5,    # windows below this are skipped
        min_total_events: int = 10,    # run() short-circuits below this
        high_risk_threshold: float = 0.80,
        model_path: str = "models/isolation_forest.joblib",
        contamination: float = 0.05,
    ):
        self.window_size = window_size
        self.stride = stride
        self.min_window_events = min_window_events
        self.min_total_events = min_total_events
        self.high_risk_threshold = high_risk_threshold
        self.model_path = model_path
        self.contamination = contamination


# ---------------------------------------------------------------------------
# Scoring node
# ---------------------------------------------------------------------------

def make_scoring_node(
    config: SpatioTemporalConfig,
    registry: ModelRegistry,
) -> Callable[[AgentState], AgentState]:
    """
    Returns a node function that scores all sliding windows extracted from
    state.events and appends an AgentResult to state.results.
    """
    extractor = WindowFeatureExtractor()

    def _generate_windows(events: List[CanonicalEvent]):
        """Yield (start, end, event_list) tuples for each sliding window."""
        if not events:
            return

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        t_start = sorted_events[0].timestamp
        t_end   = sorted_events[-1].timestamp

        current = t_start
        while current <= t_end:
            win_end = current + config.window_size
            window  = [e for e in sorted_events if current <= e.timestamp < win_end]
            if len(window) >= config.min_window_events:
                yield current, win_end, window
            current += config.stride

    def score(state: AgentState) -> AgentState:
        if not registry.is_ready:
            msg = "ModelRegistry has no trained model. Train first with train_baseline()."
            logger.error(msg)
            state.errors.append(msg)
            return state

        windows = list(_generate_windows(state.events))

        if not windows:
            logger.info("No scoreable windows found in the event batch.")
            state.results.append(AgentResult(
                agent="spatio_temporal",
                risk_score=0.0,
                severity=Severity.INFO,
                flags=["no_scoreable_windows"],
                details={"total_events": len(state.events)},
            ))
            return state

        # Build feature matrix for all windows in one pass
        feature_rows = []
        valid_windows = []
        for start, end, evts in windows:
            vec = extractor.extract(evts)
            if vec is not None:
                feature_rows.append(vec)
                valid_windows.append((start, end, evts, vec))

        if not feature_rows:
            state.results.append(AgentResult(
                agent="spatio_temporal",
                risk_score=0.0,
                severity=Severity.INFO,
                flags=["feature_extraction_failed"],
            ))
            return state

        X = np.vstack(feature_rows)
        per_window_risk = registry.score_batch(X)   # shape: (n_windows,)

        max_risk   = float(np.max(per_window_risk))
        worst_idx  = int(np.argmax(per_window_risk))

        worst_start, worst_end, _, worst_vec = valid_windows[worst_idx]

        flags: List[str] = []
        if max_risk >= config.high_risk_threshold:
            flags.append("high_risk_graph_pattern")

        # Package per-window details for audit / downstream agents
        window_details = [
            {
                "window_start": str(valid_windows[i][0]),
                "window_end":   str(valid_windows[i][1]),
                "event_count":  len(valid_windows[i][2]),
                "risk_score":   float(per_window_risk[i]),
                "features": dict(zip(
                    WindowFeatureExtractor.FEATURE_NAMES,
                    valid_windows[i][3].tolist()
                )),
            }
            for i in range(len(valid_windows))
        ]

        result = AgentResult(
            agent="spatio_temporal",
            risk_score=max_risk,
            severity=Severity.INFO,   # filled in by severity node
            flags=flags,
            details={
                "num_windows_scored": len(valid_windows),
                "per_window_details": window_details,
                "worst_window_index": worst_idx,
                "worst_window_start": str(worst_start),
                "worst_window_end":   str(worst_end),
                "worst_window_features": dict(zip(
                    WindowFeatureExtractor.FEATURE_NAMES,
                    worst_vec.tolist()
                )),
            },
        )
        state.results.append(result)
        return state

    return score


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_spatio_temporal_graph(
    config: Optional[SpatioTemporalConfig] = None,
    registry: Optional[ModelRegistry] = None,
) -> AgentGraph:
    """
    Assemble and return the full agentic pipeline:

        [validate] ---(enough events)---> [score] ---> [severity] ---> END
                   ---(too few events)--> [skip]  ---> END
    """
    config   = config   or SpatioTemporalConfig()
    registry = registry or ModelRegistry.instance(
        model_path=config.model_path,
        contamination=config.contamination,
    )

    graph = AgentGraph(name="spatio_temporal_pipeline")

    graph.add_node("validate", make_validation_node(min_events=config.min_total_events))
    graph.add_node("score",    make_scoring_node(config, registry))
    graph.add_node("severity", make_severity_node())
    graph.add_node("skip",     no_op)

    graph.set_entry("validate")
    graph.add_conditional_edge("validate", skip_router, {"score": "score", "skip": "skip"})
    graph.add_edge("score",    "severity")
    graph.add_edge("severity", END)
    graph.add_edge("skip",     END)

    return graph


# ---------------------------------------------------------------------------
# High-level façade
# ---------------------------------------------------------------------------

class SpatioTemporalPipeline:
    """
    Production façade that owns the sliding window, the model registry, and
    the agent graph.  This is the object you instantiate once per service and
    call on every batch of incoming events.

    Typical usage (base pipeline — IsolationForest only)
    -----------------------------------------------------
    pipeline = SpatioTemporalPipeline()
    pipeline.train_baseline(baseline_events)

    state = pipeline.process(events)
    result = state.results[-1]
    print(result.risk_score, result.flags)

    Agentic usage (IsolationForest + Gemini LLM reasoning)
    -------------------------------------------------------
    from llm_agent_node import LLMConfig

    pipeline = SpatioTemporalPipeline(
        llm_config=LLMConfig(api_key="YOUR_GEMINI_KEY"),
        # or set GEMINI_API_KEY env var and pass LLMConfig() with no key
    )
    pipeline.train_baseline(baseline_events)
    pipeline.start_scheduled_retraining(
        data_provider=my_db_fetch_fn,
        interval_hours=24,
    )

    state  = pipeline.process(events)
    result = state.results[-1]
    print(result.risk_score, result.flags)

    # LLM verdict (only present when risk >= LLMConfig.high_risk_threshold)
    llm = state.metadata.get("llm_analysis", {})
    print(llm.get("verdict"), llm.get("reasoning"))
    print("Recommended actions:", llm.get("recommended_actions"))
    """

    def __init__(
        self,
        config: Optional[SpatioTemporalConfig] = None,
        registry: Optional[ModelRegistry] = None,
        llm_config=None,   # LLMConfig | None — pass to enable Gemini reasoning layer
    ):
        self.config   = config   or SpatioTemporalConfig()
        self.registry = registry or ModelRegistry.instance(
            model_path=self.config.model_path,
            contamination=self.config.contamination,
        )
        self._extractor = WindowFeatureExtractor()

        if llm_config is not None and _LLM_AVAILABLE:
            # Full agentic graph: validate→score→severity→llm_analysis→END
            self._graph = _build_agentic(
                llm_config=llm_config,
                spatio_config=self.config,
                registry=self.registry,
            )
            logger.info("SpatioTemporalPipeline: Gemini LLM reasoning node ENABLED.")
        else:
            if llm_config is not None and not _LLM_AVAILABLE:
                logger.warning(
                    "llm_config supplied but llm_agent_node.py / langchain-google-genai "
                    "is not importable — falling back to base pipeline without LLM."
                )
            self._graph = build_spatio_temporal_graph(self.config, self.registry)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def process(self, events: List[CanonicalEvent]) -> AgentState:
        """
        Run the full agent graph on *events* and return the final AgentState.
        The AgentResult(s) are in state.results.
        """
        state = AgentState(events=events)
        return self._graph.run(state)

    # ------------------------------------------------------------------
    # Training helpers
    # ------------------------------------------------------------------

    def train_baseline(self, events: List[CanonicalEvent]) -> None:
        """
        Extract features from *events* using the same sliding-window logic as
        the scoring node, then train (and persist) the IsolationForest.

        Call this once before deploying.  Re-call to retrain manually.
        """
        logger.info("Extracting baseline features from %d events …", len(events))
        X = self._extract_feature_matrix(events)
        if X is None or len(X) == 0:
            raise ValueError(
                "Could not extract any features from the baseline events. "
                "Ensure you provide at least a few hundred events."
            )
        self.registry.train(X)

    def _extract_feature_matrix(
        self, events: List[CanonicalEvent]
    ) -> Optional[np.ndarray]:
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        if not sorted_events:
            return None

        t_start = sorted_events[0].timestamp
        t_end   = sorted_events[-1].timestamp
        rows    = []
        current = t_start

        while current <= t_end:
            win_end = current + self.config.window_size
            window  = [e for e in sorted_events if current <= e.timestamp < win_end]
            if len(window) >= self.config.min_window_events:
                vec = self._extractor.extract(window)
                if vec is not None:
                    rows.append(vec)
            current += self.config.stride

        return np.vstack(rows) if rows else None

    # ------------------------------------------------------------------
    # Scheduled retraining
    # ------------------------------------------------------------------

    def start_scheduled_retraining(
        self,
        data_provider: Callable[[], List[CanonicalEvent]],
        interval_hours: float = 24.0,
        run_immediately: bool = False,
    ) -> None:
        """
        Schedule background retraining.

        Parameters
        ----------
        data_provider:  Callable that returns a fresh list of CanonicalEvents
                        representing recent baseline traffic.  Must be thread-safe.
        interval_hours: 24.0 for daily, 168.0 for weekly.
        run_immediately: If True, retrain once right now before the first
                        scheduled interval.
        """
        def _wrapped_provider() -> np.ndarray:
            events = data_provider()
            X = self._extract_feature_matrix(events)
            if X is None:
                raise ValueError("data_provider returned no scoreable windows.")
            return X

        self.registry.start_scheduler(
            data_provider=_wrapped_provider,
            interval_hours=interval_hours,
            run_immediately=run_immediately,
        )

    def stop_scheduled_retraining(self) -> None:
        self.registry.stop_scheduler()

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def model_status(self) -> dict:
        return self.registry.status()
