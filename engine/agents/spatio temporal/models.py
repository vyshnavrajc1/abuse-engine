"""
models.py – Shared data models for the spatio-temporal anomaly detection system.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

@dataclass
class CanonicalEvent:
    """Normalised representation of a single HTTP access-log entry."""
    timestamp: datetime
    source_ip: str
    user_id: Optional[str]
    request_path: str
    http_method: str

    # Optional enrichment fields (populated later in the pipeline)
    asn: Optional[str] = None
    country: Optional[str] = None
    response_code: Optional[int] = None
    bytes_sent: Optional[int] = None


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AgentResult:
    """Standard output produced by every agent node."""
    agent: str
    risk_score: float                  # always in [0.0, 1.0]
    severity: Severity
    flags: List[str]
    details: Dict[str, Any] = field(default_factory=dict)
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    produced_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError(f"risk_score must be in [0,1], got {self.risk_score}")


# ---------------------------------------------------------------------------
# Agent state (passed between nodes in the agent graph)
# ---------------------------------------------------------------------------

@dataclass
class AgentState:
    """
    Mutable state object threaded through every node in the agent graph.
    Nodes read from and write to this object.
    """
    events: List[CanonicalEvent] = field(default_factory=list)
    results: List[AgentResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
