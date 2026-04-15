"""
Abuse Engine Payload Agent

Mandate: Detect port scanning, endpoint enumeration, and injection patterns.
Primary signal: Shannon entropy of endpoint distribution per IP.

OODA logic:
  OBSERVE     → compute per-IP endpoint entropy + request counts
  ORIENT      → fetch LTM entropy baseline; check for known-bad IPs from board
  HYPOTHESIZE → "scan/enumeration" if an IP targets many distinct endpoints
  INVESTIGATE → entropy z-score vs baseline; verify request density
  EVALUATE    → conclude on threshold
  CONCLUDE    → emit finding

CICIDS compatibility:
  All endpoints are /port_X. A port scan IP hits many distinct /port_X
  targets in a single batch. Shannon entropy is high for scan IPs, low
  for benign IPs that repeatedly hit the same endpoint.

Adaptive thresholds:
  ENTROPY_THRESHOLD ← ltm_entropy_mean + 2σ  (after warmup)
  MIN_DISTINCT_ENDPOINTS ← fixed (semantic definition of enumeration)
"""

from __future__ import annotations
from collections import Counter, defaultdict
import re
from typing import Dict, List

from engine.agents.base_agent import AgentContext, BaseAgent, LoopDecision
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, LogRecord, ThreatType


class PayloadAgent(BaseAgent):

    # Cold-start fallbacks
    ENTROPY_THRESHOLD       = 2.0    # bits — high entropy = many unique endpoints
    MIN_DISTINCT_ENDPOINTS  = 5      # minimum distinct endpoints to call a scan
    MIN_REQUESTS_PER_IP     = 5      # ignore low-volume IPs (noise)
    MAX_IP_ENTROPY_PAIRS    = 20     # cap how many IPs we fully analyse
    MIN_WARMUP_BATCHES      = 15     # system-level warmup guard (global batch count)

    # Hard-bypass thresholds — fire regardless of LTM distribution stability.
    # Benign per-IP entropy peaks at ~3 bits (few repeated endpoints); a true
    # port scan generates 8-9 bits across 300+ distinct /port_X targets. No
    # warmup period is needed to recognise this extremity.
    HARD_ENTROPY_THRESHOLD  = 6.0    # bits — obvious scanner, bypasses stability check
    HARD_MIN_DISTINCT       = 100    # minimum distinct endpoints for hard bypass

    # Injection pattern detection (Web Attack: XSS, SQLi, path traversal, cmd injection).
    # Patterns match URL-decoded endpoint strings; compiled once at class level.
    _INJECTION_PATTERNS: List[tuple[str, re.Pattern]] = [
        ("xss",          re.compile(r"<\s*script|javascript:|on\w+\s*=|<\s*img[^>]+src\s*=", re.I)),
        ("sqli",         re.compile(r"union\s+select|'\s*(or|and)\s+'?\d|--\s*$|;\s*drop\s+table|select\s+.+\s+from", re.I)),
        ("path_trav",    re.compile(r"\.\./|\.\.\\|%2e%2e[%/\\]|/etc/passwd|/windows/system32", re.I)),
        ("cmd_inject",   re.compile(r";\s*(ls|cat|whoami|id|uname|wget|curl)\b|`[^`]+`|\|\s*(sh|bash|cmd)\b", re.I)),
        ("xxe_ssrf",     re.compile(r"<!entity|file://|dict://|gopher://|/proc/self", re.I)),
    ]
    # Minimum injection hits in a window to hypothesize a Web Attack
    MIN_INJECTION_HITS      = 3

    # Well-known service ports that appear in legitimate multi-protocol traffic.
    # Having entropy across THESE ports alone does NOT indicate a port scan.
    _BENIGN_SERVICE_PORTS = frozenset({
        21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139,
        143, 389, 443, 445, 465, 587, 993, 995, 1080, 1433, 1521,
        3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017,
    })

    def _update_adaptive_thresholds(self) -> None:
        """Adapt entropy threshold from LTM benign baseline."""
        mean, std = self.memory.ltm.get_batch_distribution("PayloadAgent", "max_ip_entropy")
        if mean is not None and std is not None:
            self.ENTROPY_THRESHOLD = mean + 2.0 * std

    def observe(self, ctx: AgentContext) -> None:
        """Compute per-IP endpoint counts and Shannon entropy."""
        ip_endpoints: Dict[str, Counter] = defaultdict(Counter)
        for r in ctx.records:
            ep = r.endpoint_template or r.endpoint
            ip_endpoints[r.ip][ep] += 1

        per_ip_entropy: Dict[str, float] = {}
        per_ip_distinct: Dict[str, int] = {}
        import math
        for ip, ep_counts in ip_endpoints.items():
            # Exclude ephemeral/randomised source ports (>= 49152) from entropy.
            # Port scans target destination service ports (< 49152 overwhelmingly);
            # ephemeral ports are client-side TCP connection IDs, not scan targets.
            scan_ep_counts: Counter = Counter()
            for ep, cnt in ep_counts.items():
                try:
                    port = int(ep.split("/port_")[-1].split("/")[0])
                    if port < 49152:
                        scan_ep_counts[ep] = cnt
                except (ValueError, IndexError):
                    scan_ep_counts[ep] = cnt  # non-port endpoint kept as-is
            total = sum(scan_ep_counts.values())
            if total < self.MIN_REQUESTS_PER_IP:
                continue
            entropy = -sum(
                (c / total) * math.log2(c / total)
                for c in scan_ep_counts.values()
            )
            per_ip_entropy[ip] = round(entropy, 4)
            per_ip_distinct[ip] = len(scan_ep_counts)

        max_entropy_ip = max(per_ip_entropy, key=per_ip_entropy.get) if per_ip_entropy else None
        max_entropy = per_ip_entropy.get(max_entropy_ip, 0.0) if max_entropy_ip else 0.0

        # Injection pattern scanning — URL-decode endpoints and test against signatures.
        # Operates on all records regardless of warmup state (pattern-match, not statistical).
        from urllib.parse import unquote
        injection_hits: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in ctx.records:
            ep = unquote(r.endpoint_template or r.endpoint or "")
            for pattern_name, pattern in self._INJECTION_PATTERNS:
                if pattern.search(ep):
                    injection_hits[r.ip][pattern_name] += 1

        # Summarise: total hits per IP and distinct pattern types per IP
        injection_summary: Dict[str, Dict] = {}
        for ip, hits_by_type in injection_hits.items():
            injection_summary[ip] = {
                "total": sum(hits_by_type.values()),
                "patterns": dict(hits_by_type),
                "distinct_types": len(hits_by_type),
            }
        total_injection_hits = sum(v["total"] for v in injection_summary.values())
        top_injection_ip = (
            max(injection_summary, key=lambda ip: injection_summary[ip]["total"])
            if injection_summary else None
        )

        ctx.raw_metrics["injection_summary"]      = injection_summary
        ctx.raw_metrics["total_injection_hits"]   = total_injection_hits
        ctx.raw_metrics["top_injection_ip"]       = top_injection_ip

        ctx.raw_metrics["ip_endpoints"]     = {ip: dict(c) for ip, c in ip_endpoints.items()}
        ctx.raw_metrics["per_ip_entropy"]   = per_ip_entropy
        ctx.raw_metrics["per_ip_distinct"]  = per_ip_distinct
        ctx.raw_metrics["max_entropy_ip"]   = max_entropy_ip
        ctx.raw_metrics["max_entropy"]      = max_entropy
        ctx.raw_metrics["total_distinct_endpoints"] = len(
            {r.endpoint_template or r.endpoint for r in ctx.records}
        )

        ctx.log(
            f"OBSERVE: {len(ip_endpoints)} IPs | "
            f"max_entropy_ip={max_entropy_ip} entropy={max_entropy:.2f} | "
            f"total_distinct_eps={ctx.raw_metrics['total_distinct_endpoints']} | "
            f"injection_hits={total_injection_hits} ips_with_injection={len(injection_summary)}"
        )

    def orient(self, ctx: AgentContext) -> None:
        """Fetch LTM entropy baseline; check evidence board for known-bad IPs."""
        # Record batch stats for adaptive threshold
        self.memory.ltm.record_batch_stats("PayloadAgent", {
            "max_ip_entropy": ctx.raw_metrics.get("max_entropy", 0.0),
            "total_distinct_endpoints": float(ctx.raw_metrics.get("total_distinct_endpoints", 0)),
        })

        batch_num = self.memory.ltm.get_batch_count()
        if batch_num < self.MIN_WARMUP_BATCHES:
            ctx.raw_metrics["in_warmup"] = True
            ctx.log(f"ORIENT: warm-up batch {batch_num}/{self.MIN_WARMUP_BATCHES} — learning only")
        else:
            ctx.raw_metrics["in_warmup"] = False

        if self.memory.ltm.is_distribution_stable("PayloadAgent"):
            self._update_adaptive_thresholds()
            ctx.log("ORIENT: distribution stable — adaptive entropy threshold active")

        # Check for prior known-bad IP evidence
        kb_evidence = self.tools.call(
            "read_evidence_board", key_filter="knowledge:known_bad", min_confidence=0.7
        )
        ctx.raw_metrics["known_bad_evidence"] = kb_evidence
        if kb_evidence:
            ctx.log(f"ORIENT: {len(kb_evidence)} known-bad IP entries on board")
            ctx.confidence_score = max(ctx.confidence_score, 0.20)

    def hypothesize(self, ctx: AgentContext) -> None:
        """Hypothesize scan/enumeration if a single IP covers many distinct endpoints,
        or web attack if injection patterns are found in endpoint strings."""
        max_entropy = ctx.raw_metrics.get("max_entropy", 0.0)
        max_ip = ctx.raw_metrics.get("max_entropy_ip")
        distinct = ctx.raw_metrics.get("per_ip_distinct", {}).get(max_ip, 0) if max_ip else 0

        # Injection hypothesis — fires before any warmup/stability gate because
        # pattern matching doesn't require a learned baseline.
        total_inj = ctx.raw_metrics.get("total_injection_hits", 0)
        top_inj_ip = ctx.raw_metrics.get("top_injection_ip")
        if total_inj >= self.MIN_INJECTION_HITS and top_inj_ip:
            ctx.hypothesis = "injection_detected"
            ctx.threat_type = ThreatType.WEB_ATTACK
            ctx.confidence_score = max(ctx.confidence_score, 0.60)
            ctx.log(
                f"HYPOTHESIZE: injection patterns detected — {top_inj_ip} "
                f"total_hits={total_inj}"
            )
            # Don't return — still check entropy so both paths can fire simultaneously

        # Hard bypass: extreme entropy from a single IP is unambiguously a scanner.
        # This fires before the warmup/stability gate so port scans are never missed
        # just because the LTM distribution hasn't converged yet.
        if max_ip and max_entropy >= self.HARD_ENTROPY_THRESHOLD and distinct >= self.HARD_MIN_DISTINCT:
            ctx.hypothesis = "endpoint_enumeration"
            ctx.threat_type = ThreatType.PORT_SCAN
            ctx.confidence_score = max(ctx.confidence_score, 0.70)
            ctx.log(
                f"HYPOTHESIZE: hard-bypass scan — {max_ip} entropy={max_entropy:.2f} "
                f"distinct={distinct} (bypassed stability check)"
            )
            return

        if ctx.raw_metrics.get("in_warmup") or not self.memory.ltm.is_distribution_stable("PayloadAgent"):
            if ctx.hypothesis != "injection_detected":
                ctx.hypothesis = "warmup_learning"
                ctx.log("HYPOTHESIZE: warm-up or unstable distribution — building baseline entropy model")
            return

        max_entropy = ctx.raw_metrics.get("max_entropy", 0.0)
        max_ip = ctx.raw_metrics.get("max_entropy_ip")
        distinct = ctx.raw_metrics.get("per_ip_distinct", {}).get(max_ip, 0) if max_ip else 0

        if max_ip and max_entropy >= self.ENTROPY_THRESHOLD and distinct >= self.MIN_DISTINCT_ENDPOINTS and ctx.hypothesis != "endpoint_enumeration":
            ctx.hypothesis = "endpoint_enumeration"
            ctx.threat_type = ThreatType.PORT_SCAN
            ctx.log(
                f"HYPOTHESIZE: {max_ip} entropy={max_entropy:.2f} >= {self.ENTROPY_THRESHOLD:.2f} "
                f"with {distinct} distinct endpoints — scan/enumeration suspected"
            )
        elif max_entropy > 0:
            ctx.hypothesis = "check_entropy"
            ctx.log(f"HYPOTHESIZE: entropy={max_entropy:.2f} below threshold — checking")
        else:
            ctx.hypothesis = "insufficient_endpoint_diversity"
            ctx.log("HYPOTHESIZE: all IPs targeting same endpoint — no enumeration signal")

    def investigate(self, ctx: AgentContext) -> None:
        """Z-score entropy vs LTM baseline; verify per-IP request density."""
        if ctx.hypothesis in ("insufficient_endpoint_diversity", "warmup_learning"):
            return

        per_ip_entropy = ctx.raw_metrics.get("per_ip_entropy", {})
        max_ip = ctx.raw_metrics.get("max_entropy_ip")

        # Compute z-score of max entropy vs all per-IP entropies in this batch
        all_entropies = list(per_ip_entropy.values())
        if len(all_entropies) >= 3 and max_ip:
            result = self.tools.call(
                "run_statistical_test",
                values=all_entropies,
                test="zscore",
                threshold=2.0,
            )
            if result.get("significant"):
                z = result.get("z", 0.0)
                ctx.indicators.append(
                    f"endpoint_entropy_spike: {max_ip} z={z:.2f} "
                    f"(entropy={per_ip_entropy.get(max_ip, 0):.2f})"
                )
                # Cap z-score-alone contribution below the conclude() threshold (0.60).
                # The z-score is supporting evidence; the absolute port-scan check
                # (has_low_service_port + unusual_mid) must also fire to conclude ATTACK.
                # This prevents FPs from normal multi-protocol benign traffic.
                ctx.confidence_score = max(ctx.confidence_score, min(0.55, abs(z) / 5.0))
                ctx.log(f"INVESTIGATE: entropy z-score significant z={z:.2f}")

        # Absolute check: high entropy + many distinct endpoints.
        # The hard-bypass condition (re-checked against the fixed threshold rather than
        # ctx.hypothesis, because the adaptive ENTROPY_THRESHOLD can drift above the
        # port-scan level once the model records high-entropy attack batches in LTM)
        # ensures that port-scan detection never fails due to a drifted threshold.
        max_entropy = ctx.raw_metrics.get("max_entropy", 0.0)
        distinct = ctx.raw_metrics.get("per_ip_distinct", {}).get(max_ip, 0) if max_ip else 0
        hard_bypass_confirmed = (max_entropy >= self.HARD_ENTROPY_THRESHOLD
                                 and distinct >= self.HARD_MIN_DISTINCT)

        if (hard_bypass_confirmed or (max_entropy >= self.ENTROPY_THRESHOLD and distinct >= self.MIN_DISTINCT_ENDPOINTS)):
            # Port scan signature: systematic sweep hits BOTH low service ports (< 1024)
            # AND unusual mid-range destination ports (1024-49151, non-standard).
            # Benign traffic never mixes these two; even high-application-port traffic
            # (e.g. ports 9300-9900) stays in its own narrow band with no low ports.
            ip_eps = ctx.raw_metrics.get("ip_endpoints", {}).get(max_ip, {})
            ip_req_count = sum(ip_eps.values())

            has_low_service_port = False   # any endpoint with port < 1024
            unusual_mid = []               # ports 1024-49151 not in benign service set
            for ep, cnt in ip_eps.items():
                try:
                    port = int(ep.split("/port_")[-1].split("/")[0])
                except (ValueError, IndexError):
                    # non-numeric endpoint — treat as unusual
                    unusual_mid.append(ep)
                    continue
                if port >= 49152:
                    continue  # skip ephemeral source-port noise
                if port < 1024:
                    has_low_service_port = True
                elif port not in self._BENIGN_SERVICE_PORTS:
                    unusual_mid.append(ep)

            if has_low_service_port and len(unusual_mid) >= 20 and ip_req_count >= 100:
                ctx.indicators.append(
                    f"port_scan_signature: {max_ip} hit {distinct} distinct endpoints "
                    f"({ip_req_count} requests, entropy={max_entropy:.2f}, "
                    f"unusual_mid={len(unusual_mid)})"
                )
                ctx.confidence_score = max(ctx.confidence_score, 0.80)
                self._post_evidence(
                    f"payload:port_scan:{max_ip}",
                    {"ip": max_ip, "distinct_endpoints": distinct, "entropy": max_entropy},
                    0.80,
                    ["payload", "port_scan"],
                )

        # Post entropy metrics to LTM for future runs
        for ip, entropy in list(per_ip_entropy.items())[:self.MAX_IP_ENTROPY_PAIRS]:
            self.memory.ltm.record_batch_stats("PayloadAgent", {"ip_entropy": entropy})

        # Injection investigation — score per-IP hit concentration and pattern diversity
        injection_summary = ctx.raw_metrics.get("injection_summary", {})
        top_inj_ip = ctx.raw_metrics.get("top_injection_ip")
        if ctx.hypothesis == "injection_detected" and top_inj_ip and top_inj_ip in injection_summary:
            info = injection_summary[top_inj_ip]
            distinct_types = info["distinct_types"]
            total_hits = info["total"]
            # More diverse pattern types = more confident (attacker probing multiple vectors)
            inj_conf = min(0.95, 0.60 + 0.10 * distinct_types)
            ctx.confidence_score = max(ctx.confidence_score, inj_conf)
            ctx.indicators.append(
                f"injection_patterns: {top_inj_ip} — {total_hits} hits across "
                f"{distinct_types} pattern type(s): {list(info['patterns'].keys())}"
            )
            self._post_evidence(
                f"payload:web_attack:{top_inj_ip}",
                {"ip": top_inj_ip, "patterns": info["patterns"], "total_hits": total_hits},
                inj_conf,
                ["payload", "web_attack", "injection"],
            )
            ctx.log(
                f"INVESTIGATE: injection confirmed — {top_inj_ip} "
                f"hits={total_hits} types={distinct_types} conf={inj_conf:.2f}"
            )

    def evaluate(self, ctx: AgentContext) -> LoopDecision:
        if ctx.hypothesis in ("insufficient_endpoint_diversity", "warmup_learning"):
            return LoopDecision.INSUFFICIENT_DATA
        if ctx.confidence_score >= 0.75 and ctx.indicators:
            return LoopDecision.CONCLUDE
        if ctx.iteration >= 2:
            return LoopDecision.CONCLUDE
        return LoopDecision.CONCLUDE

    def conclude(self, ctx: AgentContext) -> AgentFinding:
        threat_detected = ctx.confidence_score >= 0.60 and bool(ctx.indicators)
        if threat_detected:
            if ctx.hypothesis == "injection_detected":
                ctx.threat_type = ThreatType.WEB_ATTACK
            else:
                # Distinguish port scan (many /port_X) from generic enumeration
                max_ip = ctx.raw_metrics.get("max_entropy_ip", "")
                eps = ctx.raw_metrics.get("ip_endpoints", {}).get(max_ip, {})
                is_port_scan = any(k.startswith("/port_") for k in eps)
                ctx.threat_type = ThreatType.PORT_SCAN if is_port_scan else ThreatType.ENUMERATION
            ctx.log(f"CONCLUDE: {ctx.threat_type.value} detected (conf={ctx.confidence_score:.2f})")
        else:
            ctx.log("CONCLUDE: no endpoint enumeration detected")
        return self._make_finding(ctx, threat_detected)
