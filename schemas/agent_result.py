import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class AgentResult:
    """Result produced by a single agent for a batch / window of events."""
    agent: str                              # "behavioral" | "semantic" | "spatio_temporal"
    risk_score: float                       # 0.0 (safe) – 1.0 (dangerous)
    severity: str = Severity.INFO           # Severity level
    flags: List[str] = field(default_factory=list)          # Detected signals
    explanation: str = ""                   # Human-readable XAI text
    details: Dict[str, Any] = field(default_factory=dict)   # Per-agent structured data
    metadata: Dict[str, Any] = field(default_factory=dict)  # user_id and other routing keys


@dataclass
class AgentState:
    """Shared mutable state threaded through each node in an agent graph."""
    events: List[Any]                       # List[CanonicalEvent]
    results: List[AgentResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None