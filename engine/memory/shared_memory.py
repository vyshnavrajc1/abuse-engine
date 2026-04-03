"""
APISentry Shared Memory & Evidence Board

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
