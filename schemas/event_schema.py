from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict


@dataclass
class CanonicalEvent:
    """
    Normalized event format for all downstream agents.
    """
    timestamp: datetime                 # When the request happened
    ip: str                              # IP address of the requester
    user_id: Optional[str]               # Who made the request (may be None)
    tenant_id: Optional[str]              # Tenant context (multi‑tenant systems)
    session_id: Optional[str]             # Session identifier (if available)
    endpoint: str                         # API path template, e.g. "/api/users/{id}"
    method: str                           # HTTP method: GET, POST, ...
    status_code: int                       # HTTP response code
    user_agent: str                        # Client identifier
    response_time: Optional[float] = None  # Server processing time (ms)
    path_params: Dict = field(default_factory=dict)   # Extracted from URL, e.g. {"id": "123"}
    query_params: Dict = field(default_factory=dict)  # Query string parameters
    request_body: Optional[Dict] = None                # Parsed body (if applicable)