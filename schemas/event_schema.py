from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict


@dataclass
class CanonicalEvent:
    """
    Unified normalized event format consumed by all downstream agents.
    Field names follow network-log conventions (source_ip, request_path, etc.).
    """
    timestamp: datetime                         # When the request happened
    source_ip: str                              # IP address of the requester
    user_id: Optional[str]                      # Authenticated user (None if anonymous)
    request_path: str                           # URL path template, e.g. /api/users/{id}
    http_method: str                            # GET, POST, DELETE, …
    response_code: Optional[int] = None         # HTTP response code
    bytes_sent: Optional[int] = None            # Response body size in bytes
    asn: Optional[str] = None                   # BGP ASN of source IP (optional enrichment)
    country: Optional[str] = None               # GeoIP country code (optional enrichment)
    session_id: Optional[str] = None            # Session identifier (if available)
    path_params: Dict = field(default_factory=dict)    # e.g. {"id": "123"}
    query_params: Dict = field(default_factory=dict)   # Query string parameters