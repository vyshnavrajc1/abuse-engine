"""
Abuse Engine Shared Memory & Evidence Board

Implements the tiered memory architecture:
  - STM  : in-process dict (simulates Redis sessions)
  - LTM  : dict-of-lists   (simulates PostgreSQL baselines)
  - Board: EvidenceBoard   (blackboard pattern)

All agents share a single SharedMemory instance passed at construction.
"""

from __future__ import annotations
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from schemas.models import EvidenceEntry, LogRecord


# ---------------------------------------------------------------------------
# Short-Term Memory  (session / rolling window)
# ---------------------------------------------------------------------------

class ShortTermMemory:
    """Thread-safe sliding window per IP / session."""

    def __init__(self, window_seconds: int = 60):
        self._window = window_seconds
        self._lock = threading.Lock()
        # key -> deque of (timestamp, LogRecord)
        self._store: Dict[str, deque] = defaultdict(deque)

    def push(self, key: str, record: LogRecord) -> None:
        with self._lock:
            q = self._store[key]
            q.append((record.timestamp, record))
            self._evict(q, record.timestamp)

    def get_window(self, key: str, reference_time: Optional[datetime] = None) -> List[LogRecord]:
        """Return all records still inside the window.

        reference_time defaults to the timestamp of the newest record in
        the queue so that historical data (e.g. CICIDS 2017) is never
        accidentally evicted by comparing against wall-clock utcnow().
        """
        with self._lock:
            q = self._store[key]
            if not q:
                return []
            ref = reference_time or q[-1][0]   # newest record's own timestamp
            self._evict(q, ref)
            return [r for _, r in q]

    def _evict(self, q: deque, ref: datetime) -> None:
        cutoff = ref - timedelta(seconds=self._window)
        while q and q[0][0] < cutoff:
            q.popleft()

    def keys(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())


# ---------------------------------------------------------------------------
# Long-Term Memory  (baseline statistics)
# ---------------------------------------------------------------------------

class LongTermMemory:
    """Accumulates per-endpoint / per-IP baselines."""

    def __init__(self):
        self._lock = threading.Lock()
        # endpoint -> list of request rates (req/min) seen historically
        self._endpoint_rates: Dict[str, List[float]] = defaultdict(list)
        # ip -> historical auth failure counts
        self._ip_auth_failures: Dict[str, List[int]] = defaultdict(list)
        # ip -> historical request counts per batch
        self._ip_rates: Dict[str, List[float]] = defaultdict(list)
        # batch counter for warm-up tracking
        self._batch_count: int = 0

    def increment_batch_count(self) -> int:
        """Increment and return the current batch number (1-indexed)."""
        with self._lock:
            self._batch_count += 1
            return self._batch_count

    def get_batch_count(self) -> int:
        with self._lock:
            return self._batch_count

    def record_rate(self, endpoint: str, rate: float) -> None:
        with self._lock:
            self._endpoint_rates[endpoint].append(rate)

    def get_baseline_rate(self, endpoint: str) -> Optional[float]:
        with self._lock:
            vals = self._endpoint_rates[endpoint]
            return (sum(vals) / len(vals)) if vals else None

    def record_auth_failure(self, ip: str, count: int) -> None:
        with self._lock:
            self._ip_auth_failures[ip].append(count)

    def get_baseline_auth_failures(self, ip: str) -> float:
        with self._lock:
            vals = self._ip_auth_failures[ip]
            return (sum(vals) / len(vals)) if vals else 0.0

    def record_ip_rate(self, ip: str, count: float) -> None:
        with self._lock:
            self._ip_rates[ip].append(count)

    def get_ip_baseline_rate(self, ip: str) -> Optional[float]:
        with self._lock:
            vals = self._ip_rates[ip]
            return (sum(vals) / len(vals)) if vals else None

    # ── IAT reference pool (used by TemporalAgent KS-test) ──────────────

    _MIN_IAT_REFERENCE = 200   # minimum samples before the reference is used
    _MAX_IAT_REFERENCE = 2000  # cap to keep memory bounded

    def add_iat_samples(self, samples: List[float]) -> None:
        """Accumulate inter-arrival time samples for the KS-test reference pool."""
        with self._lock:
            if not hasattr(self, "_iat_reference"):
                self._iat_reference: List[float] = []
            combined = self._iat_reference + [s for s in samples if s > 0]
            if len(combined) > self._MAX_IAT_REFERENCE:
                step = max(1, len(combined) // self._MAX_IAT_REFERENCE)
                combined = combined[::step]
            self._iat_reference = combined

    def get_iat_reference(self) -> List[float]:
        """Return accumulated IAT reference samples (empty list if not yet ready)."""
        with self._lock:
            return list(getattr(self, "_iat_reference", []))

    def has_iat_reference(self) -> bool:
        """True once the pool has enough samples for a reliable KS-test."""
        with self._lock:
            return len(getattr(self, "_iat_reference", [])) >= self._MIN_IAT_REFERENCE

    # ── Agent outcome tracking (for self-determined weights) ─────────────

    def record_agent_outcome(
        self, agent_name: str, predicted_attack: bool, final_verdict_attack: bool
    ) -> None:
        """Record whether an agent's prediction matched the final verdict."""
        with self._lock:
            if not hasattr(self, "_agent_outcomes"):
                self._agent_outcomes: Dict[str, List[tuple]] = defaultdict(list)
            self._agent_outcomes[agent_name].append((predicted_attack, final_verdict_attack))
            # Keep rolling window of last 100 outcomes where agent fired
            fired = [(p, v) for p, v in self._agent_outcomes[agent_name] if p]
            self._agent_outcomes[agent_name] = fired[-100:]

    def get_agent_precision(self, agent_name: str) -> float:
        """Rolling precision over last 100 batches where agent fired.
        Returns 1.0 (uniform weight fallback) until 20 outcome records exist."""
        with self._lock:
            outcomes = getattr(self, "_agent_outcomes", {}).get(agent_name, [])
            fired = [(p, v) for p, v in outcomes if p]
            if len(fired) < 20:
                return 1.0
            tp = sum(1 for p, v in fired if p and v)
            return tp / len(fired) if fired else 1.0

    # ── Batch-level distribution tracking (for adaptive thresholds) ──────

    _MAX_BATCH_HISTORY = 500

    def increment_agent_batch_count(self, agent_name: str) -> int:
        """Increment and return a monotonic batch counter for an agent."""
        with self._lock:
            if not hasattr(self, "_agent_batch_counts"):
                self._agent_batch_counts: Dict[str, int] = {}
            self._agent_batch_counts[agent_name] = \
                self._agent_batch_counts.get(agent_name, 0) + 1
            return self._agent_batch_counts[agent_name]

    def get_agent_batch_count(self, agent_name: str) -> int:
        """Return how many batches an agent has processed (never evicted)."""
        with self._lock:
            return getattr(self, "_agent_batch_counts", {}).get(agent_name, 0)

    def record_batch_stats(self, agent_name: str, stats: Dict[str, float]) -> None:
        """Store a snapshot of an agent's key metrics for this batch."""
        with self._lock:
            if not hasattr(self, "_batch_stats"):
                self._batch_stats: Dict[str, List[Dict[str, float]]] = defaultdict(list)
            self._batch_stats[agent_name].append(dict(stats))
            if len(self._batch_stats[agent_name]) > self._MAX_BATCH_HISTORY:
                self._batch_stats[agent_name].pop(0)

    def get_batch_distribution(self, agent_name: str, metric: str) -> tuple:
        """Return (mean, std) of a named metric across stored batches.
        Returns (None, None) if fewer than 5 samples exist."""
        with self._lock:
            history = getattr(self, "_batch_stats", {}).get(agent_name, [])
            vals = [b[metric] for b in history if metric in b]
            if len(vals) < 5:
                return (None, None)
            mean = sum(vals) / len(vals)
            variance = sum((v - mean) ** 2 for v in vals) / len(vals)
            std = variance ** 0.5
            return (mean, std)

    def is_distribution_stable(self, agent_name: str) -> bool:
        """True when rolling variance of key metrics has not changed > 5%
        for the last 10 batches. Replaces the hardcoded WARMUP_BATCHES guard."""
        with self._lock:
            history = getattr(self, "_batch_stats", {}).get(agent_name, [])
            if len(history) < 10:
                return False
            last10 = history[-10:]
            # Check stability across all metrics present in the last 10 batches
            all_metrics = set()
            for b in last10:
                all_metrics.update(b.keys())
            for metric in all_metrics:
                vals = [b[metric] for b in last10 if metric in b]
                if len(vals) < 10:
                    continue
                mean = sum(vals) / len(vals)
                if mean == 0:
                    continue
                variance = sum((v - mean) ** 2 for v in vals) / len(vals)
                # Check if the variance of the last 5 vs previous 5 changed > 5%
                first5 = vals[:5]
                last5 = vals[5:]
                mean1 = sum(first5) / 5
                mean2 = sum(last5) / 5
                var1 = sum((v - mean1) ** 2 for v in first5) / 5
                var2 = sum((v - mean2) ** 2 for v in last5) / 5
                if var1 > 0 and abs(var2 - var1) / var1 > 0.05:
                    return False
            return True

    # ── XGBoost stacking — labeled verdict history ─────────────────────

    _MAX_VERDICT_HISTORY = 2000

    def record_verdict_sample(
        self, feature_vector: "List[float]", label: int
    ) -> None:
        """Store one (feature_vector, label) pair for XGB stacking training."""
        with self._lock:
            if not hasattr(self, "_verdict_samples"):
                self._verdict_samples: List[tuple] = []
            self._verdict_samples.append((list(feature_vector), label))
            if len(self._verdict_samples) > self._MAX_VERDICT_HISTORY:
                self._verdict_samples.pop(0)

    def get_verdict_samples(self) -> "List[tuple]":
        """Return all stored (feature_vector, label) pairs."""
        with self._lock:
            return list(getattr(self, "_verdict_samples", []))


# ---------------------------------------------------------------------------
# Evidence Board  (blackboard)
# ---------------------------------------------------------------------------

class EvidenceBoard:
    """
    Shared blackboard. Agents post EvidenceEntry objects and read
    each other's findings during their INVESTIGATE step.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._entries: List[EvidenceEntry] = []
        self._listeners: List[Callable[[EvidenceEntry], None]] = []

    def post(self, entry: EvidenceEntry) -> None:
        with self._lock:
            self._entries.append(entry)
        for cb in self._listeners:
            cb(entry)

    def read(
        self,
        key_filter: Optional[str] = None,
        agent_filter: Optional[str] = None,
        min_confidence: float = 0.0,
    ) -> List[EvidenceEntry]:
        with self._lock:
            results = list(self._entries)
        if key_filter:
            results = [e for e in results if key_filter in e.key]
        if agent_filter:
            results = [e for e in results if e.posted_by == agent_filter]
        results = [e for e in results if e.confidence >= min_confidence]
        return results

    def get_value(self, key: str, default: Any = None) -> Any:
        """Convenience: latest entry for a given key."""
        entries = [e for e in self.read(key_filter=key) if e.key == key]
        if not entries:
            return default
        return sorted(entries, key=lambda e: e.timestamp)[-1].value

    def register_listener(self, cb: Callable[[EvidenceEntry], None]) -> None:
        self._listeners.append(cb)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# ---------------------------------------------------------------------------
# Unified Shared Memory (facade)
# ---------------------------------------------------------------------------

class SharedMemory:
    """
    Single object injected into every agent.

    Usage:
        mem = SharedMemory()
        mem.stm.push("ip:1.2.3.4", record)
        mem.board.post(EvidenceEntry(...))
    """

    def __init__(self, window_seconds: int = 60):
        self.stm = ShortTermMemory(window_seconds)
        self.ltm = LongTermMemory()
        self.board = EvidenceBoard()
