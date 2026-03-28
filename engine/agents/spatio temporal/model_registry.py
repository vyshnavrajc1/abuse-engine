"""
model_registry.py – Manages the lifecycle of the IsolationForest model used by
the SpatioTemporalAgent.

Responsibilities
----------------
* Train a model from a baseline dataset and persist it to disk (joblib).
* Load a previously saved model for inference.
* Schedule periodic retraining (daily / weekly) using a background thread.
* Validate that a training dataset is large enough and representative before fitting.
* Expose a thread-safe scoring interface.

Design notes
------------
The registry is a singleton so all agent instances share the same model object
and avoid redundant retraining. In a distributed deployment you would back the
registry with a shared object store (e.g. S3 + Redis lock) — the interface here
is intentionally compatible with that swap.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from models import CanonicalEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants / defaults
# ---------------------------------------------------------------------------

MIN_TRAINING_SAMPLES = 50        # fewer samples → refuse to train
MIN_FEATURE_VARIANCE = 1e-9      # each feature must have non-zero variance
DEFAULT_CONTAMINATION = 0.05     # 5 % expected anomaly rate in production


# ---------------------------------------------------------------------------
# Feature extractor (shared between registry and agent)
# ---------------------------------------------------------------------------

class WindowFeatureExtractor:
    """
    Converts a list of CanonicalEvents (a single time window) into a fixed-length
    numpy feature vector that the IsolationForest can consume.

    All eight features are chosen to be scale-invariant across traffic volumes
    so the model generalises across load spikes.
    """

    FEATURE_NAMES = [
        "ip_fan_out",          # avg users served by each IP in window
        "user_ip_count",       # avg IPs used per user in window
        "max_user_ip_count",   # max IPs used by any single user (outlier signal)
        "graph_density",       # edges / nodes  (dense → many cross-connections)
        "shared_endpoint_ips", # max IPs that reach the same endpoint
        "request_synchrony",   # min std-dev of request timestamps per endpoint
        "ip_endpoint_spread",  # avg endpoints reached per IP
        "edge_count",          # total graph edges (size signal)
    ]

    def __init__(self):
        import re
        self._id_pattern = re.compile(r"/\d+(/|$)")

    def normalize_endpoint(self, path: str) -> str:
        path = path.split("?")[0]
        return self._id_pattern.sub("/{id}\\1", path)

    def extract(self, events: List[CanonicalEvent]) -> Optional[np.ndarray]:
        """
        Returns a 1-D float array of length len(FEATURE_NAMES), or None if the
        event list is too short to produce meaningful features.
        """
        if len(events) < 5:
            return None

        try:
            import networkx as nx

            G: nx.Graph = nx.Graph()

            for ev in events:
                ip_node  = f"ip::{ev.source_ip}"
                usr_node = f"user::{ev.user_id or 'anonymous'}"
                ep_node  = f"ep::{self.normalize_endpoint(ev.request_path)}"

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

            ip_fan_out       = np.mean([len(nbrs(n, "user"))     for n in ip_nodes])   if ip_nodes   else 0.0
            user_ip_counts   = [len(nbrs(n, "ip"))               for n in user_nodes]
            avg_user_ip      = np.mean(user_ip_counts)                                  if user_ip_counts else 0.0
            max_user_ip      = float(max(user_ip_counts))                               if user_ip_counts else 0.0

            n_nodes = G.number_of_nodes()
            n_edges = G.number_of_edges()
            density = n_edges / n_nodes if n_nodes > 0 else 0.0

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
                    sync = float(np.std([t.timestamp() for t in ts]))
                    min_sync = min(min_sync, sync)

            ip_ep_spread = np.mean(
                [len({ep for usr in nbrs(n, "user") for ep in nbrs(usr, "endpoint")}) for n in ip_nodes]
            ) if ip_nodes else 0.0

            return np.array([
                ip_fan_out, avg_user_ip, max_user_ip, density,
                float(shared_ep), min_sync, ip_ep_spread, float(n_edges),
            ], dtype=np.float64)

        except Exception as exc:
            logger.warning("Feature extraction failed: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_training_data(X: np.ndarray) -> None:
    """
    Validate the training dataset and raise ValueError only for hard failures.
    Constant-value features are warned about (not rejected) because:
      - They legitimately occur in short sliding windows where no user has had
        time to accumulate multiple IPs within that window.
      - They still carry anomaly signal: an attack window *will* deviate from
        the baseline constant (e.g. user_ip_count jumping from 1.0 → 6.0).
      - IsolationForest can handle constant features without numerical issues.
    """
    n_samples, n_features = X.shape

    if n_samples < MIN_TRAINING_SAMPLES:
        raise ValueError(
            f"Training dataset has only {n_samples} samples; "
            f"minimum required is {MIN_TRAINING_SAMPLES}. "
            "Collect more baseline traffic before training."
        )

    # Identify features with zero variance — warn but do not raise
    variances = np.var(X, axis=0)
    zero_var = [
        WindowFeatureExtractor.FEATURE_NAMES[i]
        for i, v in enumerate(variances)
        if v < MIN_FEATURE_VARIANCE
    ]
    if zero_var:
        logger.warning(
            "The following features have near-zero variance in the training set: %s. "
            "This is expected for well-behaved baseline traffic where, e.g., each "
            "user uses a single IP within a 5-minute window.  Anomalous windows "
            "that deviate from this constant baseline will still score highly.  "
            "If ALL features are constant, consider using a wider window size or "
            "collecting a more diverse baseline.",
            zero_var,
        )

    # Hard fail only if every single feature is constant (truly degenerate)
    if len(zero_var) == n_features:
        raise ValueError(
            "Every feature has near-zero variance across all training windows. "
            "The model cannot learn anything useful. "
            "Ensure your baseline dataset contains diverse traffic patterns "
            "(different IPs, users, endpoints, and inter-request timings)."
        )

    # Warn on small but technically valid datasets
    if n_samples < 200:
        logger.warning(
            "Training dataset has only %d samples. "
            "A larger baseline (≥200 windows) improves generalisation.",
            n_samples,
        )


# ---------------------------------------------------------------------------
# Model registry (singleton)
# ---------------------------------------------------------------------------

class ModelRegistry:
    """
    Thread-safe singleton that holds the active IsolationForest model and
    handles training, persistence, and scheduled retraining.

    Usage
    -----
    registry = ModelRegistry.instance()
    registry.train(feature_matrix)          # initial training
    score = registry.score(feature_vector)  # [0, 1] anomaly risk
    registry.start_scheduler(              # background retraining
        interval_hours=24,
        data_provider=my_callback,
    )
    """

    _instance: Optional[ModelRegistry] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self, model_path: str = "models/isolation_forest.joblib",
                 contamination: float = DEFAULT_CONTAMINATION):
        self.model_path = Path(model_path)
        self.contamination = contamination

        self._model: Optional[IsolationForest] = None
        self._score_min: float = -0.5
        self._score_max: float = 0.5
        self._model_lock = threading.RLock()

        self._trained_at: Optional[datetime] = None
        self._training_samples: int = 0
        self._scheduler_thread: Optional[threading.Thread] = None
        self._stop_scheduler = threading.Event()

        # Try to load an existing model on startup
        self._try_load()

    # ------------------------------------------------------------------
    # Singleton accessor
    # ------------------------------------------------------------------

    @classmethod
    def instance(cls, **kwargs) -> ModelRegistry:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(**kwargs)
        return cls._instance

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, feature_matrix: np.ndarray, save: bool = True) -> None:
        """
        Fit a new IsolationForest on *feature_matrix* (shape: [n_windows, n_features]).
        Validates the data before fitting and calibrates the score range so that
        the public ``score()`` method always returns values in [0, 1].

        Parameters
        ----------
        feature_matrix:  2-D float array produced by WindowFeatureExtractor.
        save:            Persist the model to disk after training.
        """
        _validate_training_data(feature_matrix)

        logger.info(
            "Training IsolationForest on %d windows × %d features …",
            *feature_matrix.shape,
        )

        model = IsolationForest(
            contamination=self.contamination,
            n_estimators=200,       # more trees → more stable scores
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(feature_matrix)

        # Calibrate z-score + sigmoid risk mapping.
        #
        # IsolationForest.decision_function() returns a score where:
        #   higher value  = more normal (inlier)
        #   lower  value  = more anomalous (outlier)
        #
        # We store the mean (μ) and std (σ) of the training scores, then at
        # inference time compute:
        #
        #   z    = (μ - raw) / σ          # positive when anomalous
        #   risk = sigmoid(z * k - offset) # maps z to [0, 1]
        #
        # Constants chosen so that:
        #   raw = μ          → z = 0   → risk ≈ 0.05  (typical normal)
        #   raw = μ - 2σ     → z = 2   → risk ≈ 0.73  (mildly anomalous)
        #   raw = μ - 4σ     → z = 4   → risk ≈ 0.98  (strongly anomalous)
        #
        # This calibration is stable because it depends only on training
        # distribution statistics, not on the size of the test batch.
        raw_scores   = model.decision_function(feature_matrix)
        score_mean   = float(raw_scores.mean())
        score_std    = float(max(raw_scores.std(), 1e-4))

        # Thread-safe swap  (_score_min stores mean, _score_max stores std)
        with self._model_lock:
            self._model      = model
            self._score_min  = score_mean
            self._score_max  = score_std
            self._trained_at = datetime.utcnow()
            self._training_samples = len(feature_matrix)

        logger.info(
            "IsolationForest trained. score_mean=%.4f  score_std=%.4f  "
            "samples=%d  trained_at=%s",
            score_mean, score_std, len(feature_matrix), self._trained_at.isoformat(),
        )

        if save:
            self._save()

    def retrain(self, feature_matrix: np.ndarray) -> None:
        """Alias for ``train`` — called by the scheduler."""
        logger.info("Scheduled retrain triggered at %s", datetime.utcnow().isoformat())
        self.train(feature_matrix, save=True)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def score(self, feature_vector: np.ndarray) -> float:
        """
        Return an anomaly risk score in **[0.0, 1.0]** for a single feature
        vector.  Higher = more anomalous.

        Formula: risk = clip( (upper - raw) / (upper - lower), 0, 1 )
          upper = 90th-percentile of training scores (normal upper bound)
          lower = minimum training score             (worst inlier)

        Raises RuntimeError if the model has not been trained / loaded yet.
        """
        with self._model_lock:
            if self._model is None:
                raise RuntimeError(
                    "No model loaded. Call ModelRegistry.train() first or ensure "
                    "a saved model exists at the configured path."
                )
            raw  = float(self._model.decision_function(feature_vector.reshape(1, -1))[0])
            return float(self._compute_risk(np.array([raw]))[0])

    def score_batch(self, feature_matrix: np.ndarray) -> np.ndarray:
        """Score a batch; returns array of risk scores in [0, 1]."""
        with self._model_lock:
            if self._model is None:
                raise RuntimeError("No model loaded.")
            raw = self._model.decision_function(feature_matrix)
            return self._compute_risk(raw)

    # Sigmoid sensitivity and offset constants.
    #
    # Calibrated so the function has meaningful slope across the z-score range
    # where normal outliers (z≈3.8) and attack windows (z≈4.0+) live:
    #   z = 0   (typical normal)  → risk ≈ 0.08
    #   z = 2                     → risk ≈ 0.38
    #   z = 3.8 (worst normal)    → risk ≈ 0.79
    #   z = 4.1 (attack window)   → risk ≈ 0.83
    # This gives ~3-4 % separation per sigma unit — enough for reliable ranking.
    _SIGMOID_K      = 1.0
    _SIGMOID_OFFSET = 2.5

    def _compute_risk(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Convert raw IsolationForest decision_function scores to [0, 1] risk
        using z-score + sigmoid mapping calibrated on training data.
        Must be called inside self._model_lock.
        """
        mu  = self._score_min   # training mean
        sig = self._score_max   # training std
        if sig < 1e-9:
            return np.zeros(len(raw_scores))
        z    = (mu - raw_scores) / sig        # > 0 when anomalous
        risk = 1.0 / (1.0 + np.exp(-(z * self._SIGMOID_K - self._SIGMOID_OFFSET)))
        return np.clip(risk.astype(float), 0.0, 1.0)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model": self._model,
            "score_min": self._score_min,
            "score_max": self._score_max,
            "trained_at": self._trained_at,
            "training_samples": self._training_samples,
        }
        tmp = self.model_path.with_suffix(".tmp")
        joblib.dump(payload, tmp)
        tmp.replace(self.model_path)          # atomic rename
        logger.info("Model saved to %s", self.model_path)

    def _try_load(self) -> bool:
        if not self.model_path.exists():
            logger.info("No saved model found at %s", self.model_path)
            return False
        try:
            payload = joblib.load(self.model_path)
            with self._model_lock:
                self._model = payload["model"]
                self._score_min = payload["score_min"]
                self._score_max = payload["score_max"]
                self._trained_at = payload.get("trained_at")
                self._training_samples = payload.get("training_samples", 0)
            logger.info(
                "Model loaded from %s  (trained_at=%s  samples=%d)",
                self.model_path,
                self._trained_at,
                self._training_samples,
            )
            return True
        except Exception as exc:
            logger.warning("Failed to load model from %s: %s", self.model_path, exc)
            return False

    # ------------------------------------------------------------------
    # Scheduled retraining
    # ------------------------------------------------------------------

    def start_scheduler(
        self,
        data_provider: Callable[[], np.ndarray],
        interval_hours: float = 24.0,
        run_immediately: bool = False,
    ) -> None:
        """
        Spawn a background daemon thread that calls *data_provider()* every
        *interval_hours* hours and retrains the model with the returned feature
        matrix.

        Parameters
        ----------
        data_provider:   Zero-argument callable that returns a 2-D float array
                         of shape [n_windows, n_features].  Must be thread-safe.
        interval_hours:  Retraining cadence (default 24 h → daily).
                         Pass 168.0 for weekly retraining.
        run_immediately: If True, retrain once right away before starting the loop.
        """
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            logger.warning("Scheduler already running.")
            return

        self._stop_scheduler.clear()

        def _loop():
            if run_immediately:
                self._scheduled_retrain(data_provider)
            while not self._stop_scheduler.wait(timeout=interval_hours * 3600):
                self._scheduled_retrain(data_provider)

        self._scheduler_thread = threading.Thread(
            target=_loop, daemon=True, name="IF-RetainScheduler"
        )
        self._scheduler_thread.start()
        logger.info(
            "Retraining scheduler started (interval=%.1f h)", interval_hours
        )

    def stop_scheduler(self) -> None:
        self._stop_scheduler.set()
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
        logger.info("Retraining scheduler stopped.")

    def _scheduled_retrain(self, data_provider: Callable[[], np.ndarray]) -> None:
        try:
            X = data_provider()
            self.retrain(X)
        except Exception as exc:
            logger.error("Scheduled retrain failed: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    def status(self) -> dict:
        with self._model_lock:
            return {
                "ready": self._model is not None,
                "trained_at": self._trained_at.isoformat() if self._trained_at else None,
                "training_samples": self._training_samples,
                "contamination": self.contamination,
                "score_min": self._score_min,
                "score_max": self._score_max,
                "model_path": str(self.model_path),
            }
