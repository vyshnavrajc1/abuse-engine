"""
Abuse Engine GeoIP Agent

Mandate: Detect geographic anomalies — impossible travel, TOR/VPN IPs,
and single-tenant requests from unusual country concentrations.

Design goals (paper section 3.3):
  - Offline-first: all lookups use maxminddb (GeoLite2-City.mmdb)
  - No external API calls in hot path
  - Graceful degradation if .mmdb not present (returns NONE finding)
  - Impossible travel: same user token appearing from two countries
    within ΔT < human_travel_time_minutes
  - Country concentration: >80% of batch from a single non-tenant country
  - TOR/VPN detection: IP in TOR exit-node list (loaded from threat_intel_cache.json)

CICIDS 2017 compatibility:
  CICIDS uses synthetic IPs (172.16.x.x, 192.168.x.x) which are private
  and will not geolocate. The agent gracefully returns NONE for private IPs
  and does not penalise. This means GeoIPAgent contributes 0 signal on CICIDS
  but demonstrates the architecture correctly for production use.

OODA logic:
  OBSERVE     → geolocate each IP (cached per-process); compute country distribution
  ORIENT      → check for TOR/VPN IPs from KnowledgeAgent; load tenant home-country
  HYPOTHESIZE → flag if impossible_travel OR foreign_concentration OR tor_present
  INVESTIGATE → verify travel time; confidence from concentration ratio
  EVALUATE    → conclude
  CONCLUDE    → emit finding
"""

from __future__ import annotations
import ipaddress
import os
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from engine.agents.base_agent import AgentContext, BaseAgent, LoopDecision
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, LogRecord, ThreatType

# ── MaxMindDB optional import ────────────────────────────────────────────────
try:
    import maxminddb as _maxminddb
    _MAXMIND_AVAILABLE = True
except ImportError:
    _MAXMIND_AVAILABLE = False

# Module-level GeoIP reader (one open file handle per process)
_geoip_reader: Optional[object] = None
_MMDB_PATH = os.environ.get(
    "GEOIP_MMDB_PATH",
    os.path.join(os.path.dirname(__file__), "../../datasets/GeoLite2-City.mmdb"),
)

# Per-process IP → country cache
_ip_country_cache: Dict[str, str] = {}

# Human travel time floor: fastest one can change country (e.g. 30-minute flight edge case)
_MIN_TRAVEL_MINUTES = 20


def _is_private(ip: str) -> bool:
    """Return True for RFC-1918/loopback/link-local addresses."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _lookup_country(ip: str) -> str:
    """
    Resolve an IP to a 2-letter ISO country code.
    Returns "" for unresolvable or private IPs.
    Caches results in module-level dict.
    """
    if ip in _ip_country_cache:
        return _ip_country_cache[ip]
    if _is_private(ip):
        _ip_country_cache[ip] = ""
        return ""

    global _geoip_reader
    if not _MAXMIND_AVAILABLE:
        return ""

    if _geoip_reader is None:
        if not os.path.exists(_MMDB_PATH):
            return ""
        try:
            _geoip_reader = _maxminddb.open_database(_MMDB_PATH)
        except Exception:
            return ""

    try:
        record = _geoip_reader.get(ip)
        if record and "country" in record:
            code = record["country"].get("iso_code", "")
            _ip_country_cache[ip] = code
            return code
    except Exception:
        pass
    _ip_country_cache[ip] = ""
    return ""


class GeoIPAgent(BaseAgent):

    FOREIGN_CONCENTRATION_THRESHOLD = 0.80   # >80% of batch from single non-home country
    MIN_TRAVEL_MINUTES              = _MIN_TRAVEL_MINUTES

    def observe(self, ctx: AgentContext) -> None:
        """Geolocate each IP; build country distribution and IP→country map."""
        ip_country: Dict[str, str] = {}
        for r in ctx.records:
            if r.ip not in ip_country:
                ip_country[r.ip] = _lookup_country(r.ip)

        # Build country request counts
        country_counts: Counter = Counter()
        for r in ctx.records:
            c = ip_country.get(r.ip, "")
            if c:
                country_counts[c] += 1

        resolved_total = sum(country_counts.values())
        geo_coverage = resolved_total / len(ctx.records) if ctx.records else 0.0

        ctx.raw_metrics["ip_country"]       = ip_country
        ctx.raw_metrics["country_counts"]   = dict(country_counts)
        ctx.raw_metrics["geo_coverage"]     = geo_coverage
        ctx.raw_metrics["resolved_total"]   = resolved_total

        ctx.log(
            f"OBSERVE: geo_coverage={geo_coverage:.0%} | "
            f"countries={len(country_counts)} | "
            f"top={country_counts.most_common(1)}"
        )

    def orient(self, ctx: AgentContext) -> None:
        """Load tenant home country from LTM; check for TOR/VPN markers."""
        # Tenant home country — in production this comes from tenant config.
        # During CICIDS evaluation it's unused (all IPs are private).
        home_country = getattr(self.memory.ltm, "_tenant_home_country", "")
        ctx.raw_metrics["home_country"] = home_country

        # Check board for TOR/VPN evidence posted by KnowledgeAgent
        tor_evidence = self.tools.call(
            "read_evidence_board", key_filter="tor", min_confidence=0.7
        )
        ctx.raw_metrics["tor_evidence"] = tor_evidence
        if tor_evidence:
            ctx.log(f"ORIENT: {len(tor_evidence)} TOR/VPN evidence entries on board")

    def hypothesize(self, ctx: AgentContext) -> None:
        """Hypothesize GEO_ANOMALY if coverage permits meaningful analysis."""
        coverage = ctx.raw_metrics.get("geo_coverage", 0.0)
        if coverage < 0.10:
            ctx.hypothesis = "no_geo_coverage"
            ctx.log("HYPOTHESIZE: <10% IPs resolved — private/synthetic IPs, skipping geo analysis")
            return

        ctx.hypothesis = "check_geo_anomaly"
        ctx.threat_type = ThreatType.GEO_ANOMALY
        ctx.log(f"HYPOTHESIZE: {coverage:.0%} geo coverage — checking for anomalies")

    def investigate(self, ctx: AgentContext) -> None:
        if ctx.hypothesis == "no_geo_coverage":
            return

        records      = ctx.records
        ip_country   = ctx.raw_metrics.get("ip_country", {})
        country_counts = ctx.raw_metrics.get("country_counts", {})
        home_country = ctx.raw_metrics.get("home_country", "")
        tor_evidence = ctx.raw_metrics.get("tor_evidence", [])

        # ── TOR/VPN check ────────────────────────────────────────────────
        if tor_evidence:
            ctx.indicators.append(
                f"tor_vpn_detected: {len(tor_evidence)} IPs on TOR/VPN list"
            )
            ctx.confidence_score = max(ctx.confidence_score, 0.75)

        # ── Foreign concentration ─────────────────────────────────────────
        total_resolved = ctx.raw_metrics.get("resolved_total", 0)
        if total_resolved > 0:
            foreign_counts = {
                c: n for c, n in country_counts.items() if c != home_country
            }
            if foreign_counts:
                top_foreign, top_cnt = max(foreign_counts.items(), key=lambda x: x[1])
                ratio = top_cnt / total_resolved
                if ratio >= self.FOREIGN_CONCENTRATION_THRESHOLD:
                    ctx.indicators.append(
                        f"foreign_concentration: {top_cnt}/{total_resolved} reqs "
                        f"from {top_foreign} ({ratio:.0%})"
                    )
                    ctx.confidence_score = max(ctx.confidence_score, 0.70)
                    self._post_evidence(
                        f"geo:foreign_concentration:{top_foreign}",
                        {"country": top_foreign, "ratio": ratio},
                        0.70,
                        ["geo", "foreign"],
                    )

        # ── Impossible travel detection ───────────────────────────────────
        # Group records by (ip, country) and check if same IP appears in
        # 2+ countries within the minimum travel window.
        # In production: group by session/user_token not just IP.
        ip_to_country_ts: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        for r in records:
            c = ip_country.get(r.ip, "")
            if c:
                ip_to_country_ts[r.ip][c].append(r.timestamp.timestamp())

        for ip, country_ts in ip_to_country_ts.items():
            if len(country_ts) < 2:
                continue
            countries = sorted(country_ts.keys())
            for i, c1 in enumerate(countries):
                for c2 in countries[i + 1:]:
                    # Get max of earlier timestamps and min of later timestamps
                    all_ts_c1 = sorted(country_ts[c1])
                    all_ts_c2 = sorted(country_ts[c2])
                    delta_minutes = abs(all_ts_c2[0] - all_ts_c1[-1]) / 60.0
                    if delta_minutes < self.MIN_TRAVEL_MINUTES:
                        ctx.indicators.append(
                            f"impossible_travel: {ip} seen in {c1} and {c2} "
                            f"within {delta_minutes:.1f}min"
                        )
                        ctx.confidence_score = max(ctx.confidence_score, 0.80)
                        self._post_evidence(
                            f"geo:impossible_travel:{ip}",
                            {"ip": ip, "countries": [c1, c2], "delta_min": delta_minutes},
                            0.80,
                            ["geo", "impossible_travel"],
                        )

    def evaluate(self, ctx: AgentContext) -> LoopDecision:
        if ctx.hypothesis == "no_geo_coverage":
            return LoopDecision.INSUFFICIENT_DATA
        return LoopDecision.CONCLUDE

    def conclude(self, ctx: AgentContext) -> AgentFinding:
        threat_detected = ctx.confidence_score >= 0.60 and bool(ctx.indicators)
        if threat_detected:
            ctx.log(f"CONCLUDE: GEO_ANOMALY detected (conf={ctx.confidence_score:.2f})")
        else:
            ctx.log("CONCLUDE: no geographic anomaly detected")
        return self._make_finding(ctx, threat_detected)
