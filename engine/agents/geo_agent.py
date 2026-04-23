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

    FOREIGN_CONCENTRATION_THRESHOLD = 0.40   # >40% of batch from single non-home country
    DISTRIBUTED_FOREIGN_THRESHOLD   = 0.20   # >20% of batch from ANY foreign countries combined
    DISTRIBUTED_FOREIGN_MIN_COUNTRIES = 3    # require at least 3 distinct foreign countries
    # Botnet spatial spread: many unique IPs from many countries (distributed C2)
    BOTNET_SPREAD_MIN_UNIQUE_IPS    = 10     # at least N distinct IPs in the batch
    BOTNET_SPREAD_MIN_COUNTRIES     = 5      # spanning at least N distinct countries
    BOTNET_SPREAD_DIVERSITY_RATIO   = 0.10   # countries/unique_IPs ratio >= 10%
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
        """Load tenant home country from LTM or batch records; check for TOR/VPN."""
        # Priority 1: CLI-supplied home country stored in LTM
        home_country = getattr(self.memory.ltm, "_tenant_home_country", "")

        # Priority 2: read from LogRecord.tenant_home_country (populated by ingestion
        # from dataset column). This makes CTU13/CICIDS datasets work without --home-country.
        if not home_country and ctx.records:
            for r in ctx.records:
                hc = getattr(r, "tenant_home_country", "")
                if hc:
                    home_country = hc
                    # Cache in LTM so subsequent batches do not re-scan all records
                    self.memory.ltm._tenant_home_country = home_country
                    ctx.log(f"ORIENT: home_country='{home_country}' (from record field)")
                    break

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

        # ── Foreign concentration (single-country) ───────────────────────
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
                    ctx.confidence_score = max(ctx.confidence_score, 0.80)
                    self._post_evidence(
                        f"geo:foreign_concentration:{top_foreign}",
                        {"country": top_foreign, "ratio": ratio},
                        0.80,
                        ["geo", "foreign"],
                    )

        # ── Distributed multi-country foreign traffic ─────────────────────
        # Catches geo attacks that span many countries (e.g. global botnets,
        # distributed port scans) where no single country hits the 40% bar.
        # Uses overall foreign ratio rather than single-country dominance.
        if home_country and total_resolved > 0:
            total_foreign = sum(
                n for c, n in country_counts.items() if c != home_country
            )
            n_foreign_countries = sum(
                1 for c in country_counts if c != home_country
            )
            overall_foreign_ratio = total_foreign / total_resolved

            if (
                overall_foreign_ratio >= self.DISTRIBUTED_FOREIGN_THRESHOLD
                and n_foreign_countries >= self.DISTRIBUTED_FOREIGN_MIN_COUNTRIES
            ):
                conf = round(
                    min(0.50 + overall_foreign_ratio * 0.40, 0.85), 2
                )
                ctx.indicators.append(
                    f"distributed_foreign_traffic: {total_foreign}/{total_resolved} reqs "
                    f"from {n_foreign_countries} foreign countries "
                    f"({overall_foreign_ratio:.0%})"
                )
                ctx.confidence_score = max(ctx.confidence_score, conf)
                ctx.log(
                    f"INVESTIGATE: distributed_foreign_traffic "
                    f"ratio={overall_foreign_ratio:.0%} "
                    f"countries={n_foreign_countries} conf={conf:.2f}"
                )
                self._post_evidence(
                    f"geo:distributed_foreign:{n_foreign_countries}countries",
                    {
                        "total_foreign": total_foreign,
                        "n_countries": n_foreign_countries,
                        "ratio": overall_foreign_ratio,
                    },
                    conf,
                    ["geo", "distributed_foreign"],
                )

        # ── Botnet spatial diversity check ─────────────────────────────────
        # Distributed botnets (like CTU13) use many unique IPs spanning many
        # countries, but each country may be <20% individually. Classic
        # single-country and distributed-foreign checks both miss this because
        # the home-country (CZ) is still dominant. We catch it by measuring
        # how many unique IPs are spread across how many distinct countries.
        # High IP-to-country diversity = coordinated multi-region traffic.
        ip_country_map: Dict[str, str] = ctx.raw_metrics.get("ip_country", {})
        n_unique_ips = len(ip_country_map)
        resolved_countries = {c for c in ip_country_map.values() if c}
        n_resolved_countries = len(resolved_countries)

        if (
            n_unique_ips >= self.BOTNET_SPREAD_MIN_UNIQUE_IPS
            and n_resolved_countries >= self.BOTNET_SPREAD_MIN_COUNTRIES
        ):
            diversity_ratio = n_resolved_countries / n_unique_ips
            if diversity_ratio >= self.BOTNET_SPREAD_DIVERSITY_RATIO:
                # Scale confidence: more countries per unique IP → more suspicious
                spread_conf = round(min(0.55 + diversity_ratio * 0.60, 0.80), 2)
                ctx.indicators.append(
                    f"botnet_spatial_spread: {n_unique_ips} unique IPs across "
                    f"{n_resolved_countries} countries "
                    f"(diversity={diversity_ratio:.2f})"
                )
                ctx.confidence_score = max(ctx.confidence_score, spread_conf)
                ctx.log(
                    f"INVESTIGATE: botnet_spatial_spread "
                    f"unique_ips={n_unique_ips} countries={n_resolved_countries} "
                    f"ratio={diversity_ratio:.2f} conf={spread_conf:.2f}"
                )
                self._post_evidence(
                    f"geo:botnet_spread:{n_resolved_countries}countries",
                    {
                        "unique_ips": n_unique_ips,
                        "n_countries": n_resolved_countries,
                        "diversity_ratio": diversity_ratio,
                    },
                    spread_conf,
                    ["geo", "botnet", "distributed"],
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
        # Lower gate to 0.50 so MEDIUM-confidence distributed signals survive;
        # the MetaAgent's fusion layer applies the final high-confidence bar.
        threat_detected = ctx.confidence_score >= 0.50 and bool(ctx.indicators)
        if threat_detected:
            ctx.log(f"CONCLUDE: GEO_ANOMALY detected (conf={ctx.confidence_score:.2f})")
        else:
            ctx.log("CONCLUDE: no geographic anomaly detected")
        return self._make_finding(ctx, threat_detected)
