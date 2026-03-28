"""
sliding_window.py – Maintains a deque-backed, time-bounded window of
CanonicalEvents and exposes an incremental graph that is updated as events
enter or leave the window.

Key design decisions
--------------------
* Uses collections.deque for O(1) append/popleft — important at high event rates.
* The NetworkX graph is built lazily (only when get_current_events() is called
  for scoring) to avoid rebuilding on every push.
* Eviction is timestamp-driven, not count-driven, so the window always spans
  exactly ``window_size`` seconds of real traffic.
* Thread-safe via a single RLock — safe for a single producer/consumer pattern.
  For multi-producer scenarios, upgrade to asyncio or a proper queue.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import List, Optional

from models import CanonicalEvent

logger = logging.getLogger(__name__)


class SlidingWindowManager:
    """
    Manages a rolling time window of CanonicalEvents.

    Parameters
    ----------
    window_size:     How far back in time to retain events.
    min_events:      Windows with fewer events are considered too sparse for
                     reliable scoring and will be skipped.
    """

    def __init__(
        self,
        window_size: timedelta = timedelta(minutes=5),
        min_events: int = 10,
    ):
        self.window_size = window_size
        self.min_events = min_events

        self._events: deque[CanonicalEvent] = deque()
        self._lock = threading.RLock()
        self._dirty = True          # True when events have changed since last snapshot

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def push(self, event: CanonicalEvent) -> None:
        """
        Add a new event to the window, then evict events that have aged out.
        O(1) amortised because eviction walks only the left end of the deque.
        """
        with self._lock:
            self._events.append(event)
            self._evict(event.timestamp)
            self._dirty = True

    def push_batch(self, events: List[CanonicalEvent]) -> None:
        """Bulk-push a sorted list of events (more efficient than individual pushes)."""
        if not events:
            return
        with self._lock:
            for ev in events:
                self._events.append(ev)
            # Evict using the latest timestamp in the batch
            self._evict(events[-1].timestamp)
            self._dirty = True

    def get_current_events(self) -> List[CanonicalEvent]:
        """Return a snapshot of the events currently in the window."""
        with self._lock:
            return list(self._events)

    def is_scoreable(self) -> bool:
        """True when the window contains enough events to produce a reliable score."""
        with self._lock:
            return len(self._events) >= self.min_events

    def size(self) -> int:
        with self._lock:
            return len(self._events)

    def oldest_timestamp(self) -> Optional[datetime]:
        with self._lock:
            return self._events[0].timestamp if self._events else None

    def newest_timestamp(self) -> Optional[datetime]:
        with self._lock:
            return self._events[-1].timestamp if self._events else None

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._dirty = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict(self, reference_time: datetime) -> None:
        """
        Remove events from the left end of the deque that are older than
        ``reference_time - window_size``.  Called inside the lock.
        """
        cutoff = reference_time - self.window_size
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()
