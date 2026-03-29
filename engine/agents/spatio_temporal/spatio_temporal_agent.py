"""
spatio_temporal_agent.py – Spatio-temporal anomaly detection pipeline.

Self-contained: includes WindowFeatureExtractor and ModelRegistry inline
(previously split across model_registry.py and sliding_window.py).

Pipeline graph:  [validate] ---(enough events)---> [score] ---> [severity] ---> END
                             ---(too few events)--> [skip]  ---> END

Optional LLM layer (Gemini): validate → score → severity → llm_analysis → END
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from schemas.agent_result import AgentResult, AgentState, Severity
from schemas.event_schema import CanonicalEvent
from engine.agents.spatio_temporal.agent_framework import (
    END,
    AgentGraph,
    make_severity_node,
    make_validation_node,
    no_op,
    skip_router,
)

try:
    from engine.agents.spatio_temporal.llm_agent_node import (
        LLMConfig,
        build_agentic_spatio_temporal_graph as _build_agentic,
    )
    _LLM_AVAILABLE = True
except ImportError:
    _LLM_AVAILABLE = False
    LLMConfig = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature extractor
# ---------------------------------------------------------------------------

_ID_PATTERN = re.compile(r"/\d+(/|$)")

FEATURE_NAMES = [
    "ip_fan_out",
    "user_ip_count",
    "max_user_ip_count",
    "graph_density",
    "shared_endpoint_ips",
    "request_synchrony",
    "ip_endpoint_spread",
    "edge_count",
]


def _normalize_endpoint(path: str) -> str:
    return _ID_PATTERN.sub("/{id}\\1", path.split("?")[0])


def extract_window_features(events: List[CanonicalEvent]) -> Optional[np.ndarray]:
    """Convert one time window of events into an 8-dim feature vector."""
    if len(events) < 5:
        return None
    try:
        import networkx as nx
        G: nx.Graph = nx.Graph()
        for ev in events:
            ip_node  = f"ip::{ev.source_ip}"
            usr_node = f"user::{ev.user_id or 'anonymous'}"
            ep_node  = f"ep::{_normalize_endpoint(ev.request_path)}"
            for node, ntype in [(ip_node, "ip"), (usr_node, "user"), (ep_node, "endpoint")]:
                if node not in G:
                    G.add_node(node, type=ntype)
            for a, b in [(ip_node, usr_node), (usr_node, ep_node)]:
                if G.has_edge(a, b):
                    G.edges[a, b]["count"] += 1
                    G.edges[a, b]["timestamps"].append(ev.timestamp)
                else:
                    G.add_edge(a, b, count=1, timestamps=[ev.timestamp])

        def nbrs(node, t):
            return [n for n in G.neighbors(node) if G.nodes[n]["type"] == t]

        ip_nodes   = [n for n, d in G.nodes(data=True) if d["type"] == "ip"]
        user_nodes = [n for n, d in G.nodes(data=True) if d["type"] == "user"]
        ep_nodes   = [n for n, d in G.nodes(data=True) if d["type"] == "endpoint"]

        ip_fan_out     = float(np.mean([len(nbrs(n, "user")) for n in ip_nodes])) if ip_nodes else 0.0
        user_ip_counts = [len(nbrs(n, "ip")) for n in user_nodes]
        avg_user_ip    = float(np.mean(user_ip_counts)) if user_ip_counts else 0.0
        max_user_ip    = float(max(user_ip_counts)) if user_ip_counts else 0.0
        n_nodes        = G.number_of_nodes()
        n_edges        = G.number_of_edges()
        density        = n_edges / n_nodes if n_nodes > 0 else 0.0

        shared_ep = 0
        for ep in ep_nodes:
            ips = {ip for usr in nbrs(ep, "user") for ip in nbrs(usr, "ip")}
            shared_ep = max(shared_ep, len(ips))

        min_sync = 1e6
        for ep in ep_nodes:
            ts = []
            for usr in nbrs(ep, "user"):
                ed = G.get_edge_data(usr, ep)
                ts.extend(ed.get("timestamps", []))
            if len(ts) >= 2:
                min_sync = min(min_sync, float(np.std([t.timestamp() for t in ts])))

        ip_ep_spread = float(np.mean(
            [len({ep for usr in nbrs(n, "user") for ep in nbrs(usr, "endpoint")}) for n in ip_nodes]
        )) if ip_nodes else 0.0

        return np.array([
            ip_fan_out, avg_user_ip, max_user_ip, density,
            float(shared_ep), min_sync if min_sync < 1e6 else 0.0,
            ip_ep_spread, float(n_edges),
        ], dtype=np.float64)

    except Exception as exc:
        logger.warning("Feature extraction failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Training-data validation
# ---------------------------------------------------------------------------

_MIN_TRAINING_SAMPLES = 50


def _validate_training_data(X: np.ndarray) -> None:
    n, f = X.shape
    if n < _MIN_TRAINING_SAMPLES:
        raise ValueError(f"Only {n} training samples; need ≥{_MIN_TRAINING_SAMPLES}.")
    zero_var = [FEATURE_NAMES[i] for i, v in enumerate(np.var(X, axis=0)) if v < 1e-9]
    if zero_var:
        logger.warning("Near-zero variance features: %s", zero_var)
    if len(zero_var) == f:
        raise ValueError("Every feature has zero variance — cannot train.")


# ---------------------------------------------------------------------------
# Model registry (singleton)
# ---------------------------------------------------------------------------

class ModelRegistry:
    """Thread-safe singleton: IsolationForest + joblib persistence."""

    _instance: Optional[ModelRegistry] = None
    _class_lock = threading.Lock()

    def __init__(self, model_path: str = "models/isolation_forest.joblib", contamination: float = 0.05):
        self.model_path    = Path(model_path)
        self.contamination = contamination
        self._model: Optional[IsolationForest] = None
        self._score_mean: float = 0.0
        self._score_std:  float = 1.0
        self._model_lock          = threading.RLock()
        self._trained_at: Optional[datetime] = None
        self._training_samples: int = 0
        self._scheduler_thread: Optional[threading.Thread] = None
        self._stop_scheduler = threading.Event()
        self._try_load()

    @classmethod
    def instance(cls, **kwargs) -> ModelRegistry:
        if cls._instance is None:
            with cls._class_lock:
                if cls._instance is None:
                    cls._instance = cls(**kwargs)
        return cls._instance

    def train(self, X: np.ndarray, save: bool = True) -> None:
        _validate_training_data(X)
        logger.info("Training IsolationForest on %d × %d …", *X.shape)
        model = IsolationForest(contamination=self.contamination, n_estimators=200,
                                max_samples="auto", random_state=42, n_jobs=-1)
        model.fit(X)
        raw  = model.decision_function(X)
        mean = float(raw.mean())
        std  = float(max(raw.std(), 1e-4))
        with self._model_lock:
            self._model = model
            self._score_mean = mean
            self._score_std  = std
            self._trained_at = datetime.utcnow()
            self._training_samples = len(X)
        logger.info("Trained. mean=%.4f std=%.4f samples=%d at=%s",
                    mean, std, len(X), self._trained_at.isoformat())
        if save:
            self._save()

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        with self._model_lock:
            if self._model is None:
                raise RuntimeError("No model loaded. Call train() first.")
            raw  = self._model.decision_function(X)
            z    = (self._score_mean - raw) / self._score_std
            risk = 1.0 / (1.0 + np.exp(-(z * 1.0 - 2.5)))
            return np.clip(risk.astype(float), 0.0, 1.0)

    def _save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.model_path.with_suffix(".tmp")
        joblib.dump({"model": self._model, "score_mean": self._score_mean,
                     "score_std": self._score_std, "trained_at": self._trained_at,
                     "training_samples": self._training_samples}, tmp)
        tmp.replace(self.model_path)

    def _try_load(self) -> bool:
        if not self.model_path.exists():
            return False
        try:
            p = joblib.load(self.model_path)
            with self._model_lock:
                self._model = p["model"]
                self._score_mean = p.get("score_mean", p.get("score_min", 0.0))
                self._score_std  = p.get("score_std",  p.get("score_max", 1.0))
                self._trained_at = p.get("trained_at")
                self._training_samples = p.get("training_samples", 0)
            logger.info("Model loaded ← %s", self.model_path)
            return True
        except Exception as exc:
            logger.warning("Failed to load model: %s", exc)
            return False

    def start_scheduler(self, data_provider: Callable[[], np.ndarray],
                        interval_hours: float = 24.0, run_immediately: bool = False) -> None:
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return
        self._stop_scheduler.clear()
        def _loop():
            if run_immediately:
                self._safe_retrain(data_provider)
            while not self._stop_scheduler.wait(timeout=interval_hours * 3600):
                self._safe_retrain(data_provider)
        self._scheduler_thread = threading.Thread(target=_loop, daemon=True)
        self._scheduler_thread.start()

    def _safe_retrain(self, dp):
        try:
            self.train(dp(), save=True)
        except Exception as exc:
            logger.error("Scheduled retrain failed: %s", exc, exc_info=True)

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    def status(self) -> dict:
        with self._model_lock:
            return {"ready": self._model is not None,
                    "trained_at": self._trained_at.isoformat() if self._trained_at else None,
                    "training_samples": self._training_samples,
                    "contamination": self.contamination,
                    "model_path": str(self.model_path)}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class SpatioTemporalConfig:
    def __init__(self,
                 window_size:        timedelta = timedelta(minutes=5),
                 stride:             timedelta = timedelta(minutes=2, seconds=30),
                 min_window_events:  int   = 5,
                 min_total_events:   int   = 10,
                 high_risk_threshold: float = 0.80,
                 model_path:         str   = "models/isolation_forest.joblib",
                 contamination:      float = 0.05):
        self.window_size          = window_size
        self.stride               = stride
        self.min_window_events    = min_window_events
        self.min_total_events     = min_total_events
        self.high_risk_threshold  = high_risk_threshold
        self.model_path           = model_path
        self.contamination        = contamination


# ---------------------------------------------------------------------------
# Scoring node
# ---------------------------------------------------------------------------

def make_scoring_node(config: SpatioTemporalConfig, registry: ModelRegistry):
    def _windows(events):
        if not events:
            return
        ev = sorted(events, key=lambda e: e.timestamp)
        t_start, t_end = ev[0].timestamp, ev[-1].timestamp
        cur = t_start
        while cur <= t_end:
            w = [e for e in ev if cur <= e.timestamp < cur + config.window_size]
            if len(w) >= config.min_window_events:
                yield cur, cur + config.window_size, w
            cur += config.stride

    def score(state: AgentState) -> AgentState:
        if not registry.is_ready:
            state.errors.append("ModelRegistry has no trained model.")
            return state

        wins = list(_windows(state.events))
        if not wins:
            state.results.append(AgentResult(
                agent="spatio_temporal", risk_score=0.0, severity=Severity.INFO,
                flags=["no_scoreable_windows"],
                explanation="No scoreable windows found in the event batch.",
                details={"total_events": len(state.events)}))
            return state

        rows, valid = [], []
        for s, e, evts in wins:
            vec = extract_window_features(evts)
            if vec is not None:
                rows.append(vec)
                valid.append((s, e, evts, vec))

        if not rows:
            state.results.append(AgentResult(
                agent="spatio_temporal", risk_score=0.0, severity=Severity.INFO,
                flags=["feature_extraction_failed"],
                explanation="Feature extraction failed for all windows."))
            return state

        X            = np.vstack(rows)
        risks        = registry.score_batch(X)
        max_risk     = float(np.max(risks))
        worst_idx    = int(np.argmax(risks))
        ws, we, _, wv = valid[worst_idx]

        flags = []
        if max_risk >= config.high_risk_threshold:
            flags.append("high_risk_graph_pattern")

        feat = dict(zip(FEATURE_NAMES, wv.tolist()))
        notable = []
        if feat["max_user_ip_count"] > 3:
            notable.append(f"user using {feat['max_user_ip_count']:.0f} IPs")
        if feat["request_synchrony"] < 2.0:
            notable.append("highly synchronised requests")
        if feat["shared_endpoint_ips"] > 10:
            notable.append(f"{feat['shared_endpoint_ips']:.0f} IPs hitting same endpoint")
        if feat["ip_fan_out"] > 5:
            notable.append(f"IP fan-out={feat['ip_fan_out']:.1f}")

        explanation = (
            f"Spatio-temporal risk {max_risk:.3f} over {len(valid)} windows. "
            f"Worst window: {ws.strftime('%H:%M')}–{we.strftime('%H:%M')}. "
            + (f"Signals: {', '.join(notable)}." if notable else "No strong graph signals.")
        )

        state.results.append(AgentResult(
            agent="spatio_temporal",
            risk_score=max_risk,
            severity=Severity.INFO,
            flags=flags,
            explanation=explanation,
            details={
                "num_windows_scored":    len(valid),
                "worst_window_start":    str(ws),
                "worst_window_end":      str(we),
                "worst_window_features": feat,
                "per_window_details": [
                    {"window_start": str(valid[i][0]), "window_end": str(valid[i][1]),
                     "event_count": len(valid[i][2]), "risk_score": float(risks[i]),
                     "features": dict(zip(FEATURE_NAMES, valid[i][3].tolist()))}
                    for i in range(len(valid))
                ],
            },
        ))
        return state

    return score


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_spatio_temporal_graph(config=None, registry=None) -> AgentGraph:
    config   = config   or SpatioTemporalConfig()
    registry = registry or ModelRegistry.instance(
        model_path=config.model_path, contamination=config.contamination)
    g = AgentGraph(name="spatio_temporal_pipeline")
    g.add_node("validate", make_validation_node(min_events=config.min_total_events))
    g.add_node("score",    make_scoring_node(config, registry))
    g.add_node("severity", make_severity_node())
    g.add_node("skip",     no_op)
    g.set_entry("validate")
    g.add_conditional_edge("validate", skip_router, {"score": "score", "skip": "skip"})
    g.add_edge("score",    "severity")
    g.add_edge("severity", END)
    g.add_edge("skip",     END)
    return g


# ---------------------------------------------------------------------------
# High-level facade
# ---------------------------------------------------------------------------

class SpatioTemporalPipeline:
    """
    Production facade.

        pipeline = SpatioTemporalPipeline()
        pipeline.train_baseline(baseline_events)          # train once
        state = pipeline.process(test_events)             # run on new data
        result = next(r for r in state.results if r.agent == "spatio_temporal")
        print(result.risk_score, result.explanation)

    Optional Gemini LLM layer:
        from engine.agents.spatio_temporal.llm_agent_node import LLMConfig
        pipeline = SpatioTemporalPipeline(llm_config=LLMConfig())
    """

    def __init__(self, config=None, registry=None, llm_config=None):
        self.config   = config   or SpatioTemporalConfig()
        self.registry = registry or ModelRegistry.instance(
            model_path=self.config.model_path, contamination=self.config.contamination)

        if llm_config is not None and _LLM_AVAILABLE:
            self._graph = _build_agentic(llm_config=llm_config,
                                         spatio_config=self.config,
                                         registry=self.registry)
            logger.info("SpatioTemporalPipeline: Gemini LLM layer ENABLED.")
        else:
            if llm_config is not None:
                logger.warning("llm_config supplied but langchain-google-genai not installed.")
            self._graph = build_spatio_temporal_graph(self.config, self.registry)

    def process(self, events: List[CanonicalEvent]) -> AgentState:
        return self._graph.run(AgentState(events=events))

    def train_baseline(self, events: List[CanonicalEvent]) -> None:
        logger.info("Extracting baseline features from %d events …", len(events))
        X = self._build_feature_matrix(events)
        if X is None or len(X) == 0:
            raise ValueError("Could not extract features. Provide more events.")
        self.registry.train(X)

    def _build_feature_matrix(self, events: List[CanonicalEvent]) -> Optional[np.ndarray]:
        ev = sorted(events, key=lambda e: e.timestamp)
        if not ev:
            return None
        rows, cur = [], ev[0].timestamp
        t_end = ev[-1].timestamp
        while cur <= t_end:
            w = [e for e in ev if cur <= e.timestamp < cur + self.config.window_size]
            if len(w) >= self.config.min_window_events:
                vec = extract_window_features(w)
                if vec is not None:
                    rows.append(vec)
            cur += self.config.stride
        return np.vstack(rows) if rows else None

    def start_scheduled_retraining(self, data_provider: Callable[[], List[CanonicalEvent]],
                                   interval_hours: float = 24.0,
                                   run_immediately: bool = False) -> None:
        def _wrapped():
            X = self._build_feature_matrix(data_provider())
            if X is None:
                raise ValueError("data_provider returned no scoreable windows.")
            return X
        self.registry.start_scheduler(data_provider=_wrapped,
                                      interval_hours=interval_hours,
                                      run_immediately=run_immediately)

    def model_status(self) -> dict:
        return self.registry.status()
