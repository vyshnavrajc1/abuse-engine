from schemas.event_schema import CanonicalEvent
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime


@dataclass
class Session:
    """
    A group of events from the same user/IP that happened
    close together in time. If there's a gap of more than
    30 minutes, it's considered a new session.
    """
    session_id: str
    source_ip: str
    user_id: str
    events: List[CanonicalEvent] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Total time in seconds from first to last event."""
        if len(self.events) < 2:
            return 0.0
        times = [e.timestamp for e in self.events]
        return (max(times) - min(times)).total_seconds()

    @property
    def request_count(self) -> int:
        """How many requests are in this session."""
        return len(self.events)

    @property
    def endpoint_sequence(self) -> List[str]:
        """Ordered list of request paths the user visited."""
        return [e.request_path for e in self.events]


def sessionize(events: List[CanonicalEvent], gap_seconds: float = 1800) -> List[Session]:
    """
    Groups canonical events into sessions.

    How it works:
    1. Group all events by user_id (or IP if no user_id)
    2. Sort each group by timestamp
    3. Walk through events — if the gap between two consecutive
       events is more than gap_seconds (default 30 min), start
       a new session

    Input:  list of CanonicalEvent
    Output: list of Session
    """

    # Step 1: Group events by user identity
    grouped: Dict[str, List[CanonicalEvent]] = {}
    for e in events:
        key = e.user_id or e.source_ip  # use user_id if available, otherwise IP
        grouped.setdefault(key, []).append(e)

    sessions = []
    session_counter = 0

    for key, evts in grouped.items():
        # Step 2: Sort by timestamp
        evts.sort(key=lambda e: e.timestamp)
        current: List[CanonicalEvent] = [evts[0]]

        for i in range(1, len(evts)):
            # No fromisoformat needed — already datetime
            gap = (evts[i].timestamp - evts[i - 1].timestamp).total_seconds()

            if gap > gap_seconds:
                # Gap too large — save current session, start new one
                sessions.append(Session(
                    session_id=f"{key}_session_{session_counter}",
                    source_ip=current[0].source_ip,
                    user_id=current[0].user_id or "",
                    events=current,
                ))
                session_counter += 1
                current = []

            current.append(evts[i])

        # Don't forget the last session
        if current:
            sessions.append(Session(
                session_id=f"{key}_session_{session_counter}",
                source_ip=current[0].source_ip,
                user_id=current[0].user_id or "",
                events=current,
            ))
            session_counter += 1

    return sessions