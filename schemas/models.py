"""
Abuse Engine Data Models
Pure-dataclass schemas — no external dependencies beyond stdlib.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class ConfidenceLevel(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


class ThreatType(str, Enum):
    NONE                = "NONE"
    DOS                 = "DOS"
    DDOS                = "DDOS"
    BRUTE_FORCE         = "BRUTE_FORCE"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    BOT_ACTIVITY        = "BOT_ACTIVITY"
    SCRAPING            = "SCRAPING"
    PORT_SCAN           = "PORT_SCAN"
    ENUMERATION         = "ENUMERATION"
    SEQUENCE_ABUSE      = "SEQUENCE_ABUSE"
    WEB_ATTACK          = "WEB_ATTACK"
    GEO_ANOMALY         = "GEO_ANOMALY"
    UNKNOWN_ABUSE       = "UNKNOWN_ABUSE"


@dataclass
class LogRecord:
    timestamp:         datetime
    ip:                str
    method:            str
    endpoint:          str
    status:            int
    response_size:     int                    = 0
    latency:           float                  = 0.0
    user_agent:        str                    = ""
    label:             str                    = "BENIGN"
    attack_category:   str                    = "Benign"
    is_attack:         bool                   = False
    session_id:           Optional[str]          = None
    endpoint_template:    Optional[str]          = None
    geo_context:          Optional[Dict[str,Any]]= None
    # ISO-3166-1 alpha-2 code embedded from dataset (e.g. 'CZ' for CTU13).
    # GeoIPAgent reads this to determine what counts as "foreign" traffic.
    tenant_home_country:  str                    = ""


@dataclass
class AgentFinding:
    agent_name:        str
    threat_detected:   bool
    threat_type:       ThreatType       = ThreatType.NONE
    confidence:        ConfidenceLevel  = ConfidenceLevel.LOW
    confidence_score:  float            = 0.0
    indicators:        List[str]        = field(default_factory=list)
    raw_metrics:       Dict[str,Any]    = field(default_factory=dict)
    reasoning_trace:   List[str]        = field(default_factory=list)
    timestamp:         datetime         = field(default_factory=datetime.utcnow)


@dataclass
class EvidenceEntry:
    posted_by:  str
    key:        str
    value:      Any
    confidence: float     = 0.5
    tags:       List[str] = field(default_factory=list)
    entry_id:   str       = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:  datetime  = field(default_factory=datetime.utcnow)


@dataclass
class FusionVerdict:
    is_attack:           bool
    threat_type:         ThreatType
    confidence_score:    float
    contributing_agents: List[str]
    compound_signals:    List[str]         = field(default_factory=list)
    explanation:         str               = ""
    agent_findings:      List[AgentFinding]= field(default_factory=list)
    verdict_id:          str               = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp:           datetime          = field(default_factory=datetime.utcnow)
