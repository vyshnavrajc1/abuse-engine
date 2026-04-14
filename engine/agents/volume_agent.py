"""
Abuse Engine Volume Agent

Mandate: Detect DDoS, scraping, and enumeration spikes.
Primary tools: query_historical_baseline, run_statistical_test (z-score).

OODA logic:
  OBSERVE     → count requests in window per IP; compute diversity metrics
  ORIENT      → fetch historical baseline for endpoint; check warm-up state
  HYPOTHESIZE → "rate is anomalous" if count > threshold AND traffic is concentrated
  INVESTIGATE → compute z-score vs baseline; verify single-source dominance
  EVALUATE    → conclude if z > 3 with strong supporting evidence
  CONCLUDE    → emit finding, post to evidence board

Key calibrations for CICIDS 2017 (500-record windows):
  - HIGH_RATE_ABSOLUTE raised to 450 (100 was too low for mixed batches)
  - IP diversity check: >5 distinct IPs sharing the load = distributed = benign
  - DOMINANT_IP_RATIO: single IP must own >90% of requests to be suspicious
  - warm-up guard: first WARMUP_BATCHES batches only build baselines, no alerts
"""

from __future__ import annotations
from collections import Counter
from typing import List, Optional

import numpy as np

from engine.agents.base_agent import AgentContext, BaseAgent, LoopDecision
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, LogRecord, ThreatType

try:
    from sklearn.ensemble import IsolationForest as _IsolationForest
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


# Module-level model — shared across all VolumeAgent instances (fits once per process)
_iso_forest: Optional["_IsolationForest"] = None
_iso_forest_trained_on: int = 0   # number of samples used at last fit

# Minimum samples needed before the IF is useful
_ISO_MIN_SAMPLES = 30
# Features: [dom_ratio, top_count_normalised, avg_latency_ms_normalised]
_ISO_FEATURES = ("dom_ratio", "top_count", "avg_latency")


class VolumeAgent(BaseAgent):

    # ── Tunable thresholds (calibrated for CICIDS 2017 / 500-record windows) ──
    RATE_SPIKE_THRESHOLD   = 3.5      # z-score
    MIN_REQUESTS_TO_ANALYSE = 5
    MAX_IP_DIVERSITY       = 5        # if >5 unique IPs contribute equally → benign spread
    MIN_ZSCORE_CONFIDENCE  = 0.55     # z-scores alone need this confidence to fire

    # Cold-start fallbacks — replaced by adaptive values once LTM is stable
    HIGH_RATE_ABSOLUTE     = 450      # req / window from a SINGLE IP
    DOMINANT_IP_RATIO      = 0.90     # single IP must own >90% of traffic
    HIGH_LATENCY_BENIGN_MS = 6500.0   # single-IP batches with avg latency above this are likely long-lived benign sessions
    MIN_WARMUP_BATCHES     = 15       # minimum global batches before alerting

    def observe(self, ctx: AgentContext) -> None:
        """Compute per-IP request counts, endpoint rates, diversity metrics, and avg latency."""
        ip_counts: Counter = Counter()
        endpoint_counts: Counter = Counter()
        total_latency = 0.0
        # Track per-(ip, endpoint) pairs to detect single-IP endpoint saturation
        ip_ep_counts: Counter = Counter()

        # Slow-DoS candidate tracking: parallel pass over port 80/8080/8000 pairs only.
        # This bypasses the "wrong top-ep" problem where DNS traffic dominates the batch
        # and hides the slowloris attacker on port 80 from the global top-(ip,ep) view.
        _SDOS_PORTS = frozenset({80, 8080, 8000})
        sdos_cnt:     dict = {}   # (ip, ep) -> count on slow-DoS ports
        sdos_lat_sum: dict = {}   # (ip, ep) -> cumulative latency
        sdos_cap_cnt: dict = {}   # (ip, ep) -> records with latency >= 9_000 ms

        for r in ctx.records:
            ip_counts[r.ip] += 1
            ep = r.endpoint_template or r.endpoint
            endpoint_counts[ep] += 1
            total_latency += r.latency
            ip_ep_counts[(r.ip, ep)] += 1
            # Extract port for slow-DoS candidate tracking
            try:
                port = int(ep.split("/port_")[-1].split("/")[0])
            except (ValueError, IndexError):
                port = 0
            if port in _SDOS_PORTS:
                key = (r.ip, ep)
                sdos_cnt[key]     = sdos_cnt.get(key, 0) + 1
                sdos_lat_sum[key] = sdos_lat_sum.get(key, 0.0) + r.latency
                if r.latency >= 9_000.0:
                    sdos_cap_cnt[key] = sdos_cap_cnt.get(key, 0) + 1

        total = len(ctx.records)
        top_ip, top_count = ip_counts.most_common(1)[0] if ip_counts else ("", 0)
        dominant_ratio = top_count / total if total > 0 else 0.0
        unique_ips = len(ip_counts)
        avg_latency = total_latency / total if total > 0 else 0.0

        # Compute single-IP single-endpoint saturation: top (ip, ep) pair ratio vs total
        top_ip_ep, top_ip_ep_count = ip_ep_counts.most_common(1)[0] if ip_ep_counts else (("", ""), 0)
        top_ep_total = endpoint_counts.get(top_ip_ep[1], 1) if ip_ep_counts else 1
        ip_ep_saturation = top_ip_ep_count / top_ep_total if top_ep_total > 0 else 0.0

        ctx.raw_metrics["ip_counts"]          = dict(ip_counts.most_common(10))
        ctx.raw_metrics["endpoint_counts"]    = dict(endpoint_counts.most_common(10))
        ctx.raw_metrics["top_ip_ep"]          = top_ip_ep
        ctx.raw_metrics["top_ip_ep_count"]    = top_ip_ep_count
        ctx.raw_metrics["ip_ep_saturation"]   = ip_ep_saturation
        ctx.raw_metrics["total_requests"]  = total
        ctx.raw_metrics["top_ip"]          = top_ip
        ctx.raw_metrics["top_ip_count"]    = top_count
        ctx.raw_metrics["dominant_ratio"]  = dominant_ratio
        ctx.raw_metrics["unique_ips"]      = unique_ips
        ctx.raw_metrics["avg_latency"]     = avg_latency

        # Port-80-specific best (ip,ep) pair for slow-DoS detection
        if sdos_cnt:
            sdos_best = max(sdos_cnt, key=lambda k: sdos_cnt[k])
            sdos_best_cnt = sdos_cnt[sdos_best]
            sdos_ep_total = endpoint_counts.get(sdos_best[1], 1)
            sdos_best_sat = sdos_best_cnt / sdos_ep_total
            sdos_best_avg_lat = sdos_lat_sum[sdos_best] / sdos_best_cnt
            sdos_best_cap_ratio = sdos_cap_cnt.get(sdos_best, 0) / sdos_best_cnt
        else:
            sdos_best = ("", ""); sdos_best_cnt = 0
            sdos_best_sat = 0.0; sdos_best_avg_lat = 0.0; sdos_best_cap_ratio = 0.0

        ctx.raw_metrics["slow_dos_best_pair"]      = sdos_best
        ctx.raw_metrics["slow_dos_best_cnt"]       = sdos_best_cnt
        ctx.raw_metrics["slow_dos_best_sat"]       = sdos_best_sat
        ctx.raw_metrics["slow_dos_best_avg_lat"]   = sdos_best_avg_lat
        ctx.raw_metrics["slow_dos_best_cap_ratio"] = sdos_best_cap_ratio

        ctx.log(
            f"OBSERVE: {total} reqs | unique_ips={unique_ips} | "
            f"top_ip={top_ip} ({top_count} reqs, {dominant_ratio:.0%}) | "
            f"avg_lat={avg_latency:.0f}ms"
        )

    def _update_adaptive_thresholds(self) -> None:
        """Replace cold-start constants with data-derived values from LTM.
        Called once per batch after distribution has stabilised."""
        dom_mean, dom_std = self.memory.ltm.get_batch_distribution("VolumeAgent", "dom_ratio")
        if dom_mean is not None and dom_std is not None:
            self.DOMINANT_IP_RATIO = min(0.99, dom_mean + 2.0 * dom_std)

        top_mean, top_std = self.memory.ltm.get_batch_distribution("VolumeAgent", "top_count")
        if top_mean is not None and top_std is not None:
            self.HIGH_RATE_ABSOLUTE = top_mean + 2.0 * top_std

        lat_mean, lat_std = self.memory.ltm.get_batch_distribution("VolumeAgent", "avg_latency")
        if lat_mean is not None and lat_std is not None:
            self.HIGH_LATENCY_BENIGN_MS = lat_mean + 3.0 * lat_std

    def _retrain_iso_forest(self) -> None:
        """Fit (or refit) the Isolation Forest on historical batch stats from LTM."""
        global _iso_forest, _iso_forest_trained_on
        if not _SKLEARN_AVAILABLE:
            return

        # _batch_stats["VolumeAgent"] is a List[Dict[str, float]]
        history: list = getattr(self.memory.ltm, "_batch_stats", {}).get("VolumeAgent", [])
        n = len(history)
        if n < _ISO_MIN_SAMPLES:
            return

        raw_dom   = [d.get("dom_ratio",   0.0) for d in history]
        raw_top   = [d.get("top_count",   0.0) for d in history]
        raw_lat   = [d.get("avg_latency", 0.0) for d in history]

        max_top = max(max(raw_top), 1.0)
        max_lat = max(max(raw_lat), 1.0)

        X = np.column_stack([
            raw_dom,
            [v / max_top for v in raw_top],
            [v / max_lat for v in raw_lat],
        ])

        if _iso_forest is None or _iso_forest_trained_on < n - 10:
            _iso_forest = _IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
                n_jobs=1,
            )
            _iso_forest.fit(X)
            _iso_forest_trained_on = n

    def _iso_anomaly_score(self, dom_ratio: float, top_count: float, avg_latency: float) -> Optional[float]:
        """
        Return the Isolation Forest anomaly score for the current batch features.
        Score < 0 means anomalous; more negative = more anomalous.
        Returns None if IF is not trained yet.
        """
        if not _SKLEARN_AVAILABLE or _iso_forest is None:
            return None
        top_norm = top_count / max(self.HIGH_RATE_ABSOLUTE, 1)
        lat_norm  = avg_latency / max(self.HIGH_LATENCY_BENIGN_MS, 1)
        x = np.array([[dom_ratio, min(top_norm, 1.0), min(lat_norm, 1.0)]])
        return float(_iso_forest.score_samples(x)[0])

    def orient(self, ctx: AgentContext) -> None:
        """Fetch historical baselines for dominant endpoints; check warm-up state."""
        # Use global system batch count (incremented every batch by MetaAgent)
        batch_num = self.memory.ltm.get_batch_count()
        ctx.raw_metrics["batch_num"] = batch_num

        # Record batch-level stats for adaptive threshold computation
        self.memory.ltm.record_batch_stats("VolumeAgent", {
            "dom_ratio":   ctx.raw_metrics.get("dominant_ratio", 0.0),
            "top_count":   float(ctx.raw_metrics.get("top_ip_count", 0)),
            "avg_latency": ctx.raw_metrics.get("avg_latency", 0.0),
        })

        # Replace hardcoded constants once distribution is stable
        if self.memory.ltm.is_distribution_stable("VolumeAgent"):
            self._update_adaptive_thresholds()

        if batch_num >= self.MIN_WARMUP_BATCHES:
            ctx.raw_metrics["in_warmup"] = False
            ctx.log(f"ORIENT: batch {batch_num} — adaptive thresholds active")
        else:
            ctx.raw_metrics["in_warmup"] = True
            ctx.log(f"ORIENT: warm-up batch {batch_num}/{self.MIN_WARMUP_BATCHES} — learning only")

        baselines = {}
        for ep in list(ctx.raw_metrics.get("endpoint_counts", {}).keys())[:5]:
            baseline = self.tools.call("query_historical_baseline", endpoint=ep)
            baselines[ep] = baseline  # may be None on first run

        ctx.raw_metrics["baselines"] = baselines

        # Check evidence board for prior DoS signals
        dos_evidence = self.tools.call("read_evidence_board", key_filter="dos", min_confidence=0.6)
        ctx.raw_metrics["prior_dos_evidence"] = dos_evidence
        if dos_evidence:
            ctx.log(f"ORIENT: {len(dos_evidence)} prior DoS evidence entries found")

    def hypothesize(self, ctx: AgentContext) -> None:
        """
        Hypothesize DoS only when:
          - A single IP dominates (>60% of traffic), AND
          - That IP's count is abnormally high in absolute OR relative terms.
        Diverse multi-IP traffic is NOT flagged regardless of total volume.
        """
        if ctx.raw_metrics.get("in_warmup"):
            ctx.hypothesis = "warmup_learning"
            ctx.log("HYPOTHESIZE: in warm-up — skipping alerting")
            return

        dominant_ratio  = ctx.raw_metrics.get("dominant_ratio", 0.0)
        top_count       = ctx.raw_metrics.get("top_ip_count", 0)
        unique_ips      = ctx.raw_metrics.get("unique_ips", 0)
        total           = ctx.raw_metrics.get("total_requests", 0)
        ip_ep_sat       = ctx.raw_metrics.get("ip_ep_saturation", 0.0)
        top_ip_ep_count = ctx.raw_metrics.get("top_ip_ep_count", 0)
        avg_latency     = ctx.raw_metrics.get("avg_latency", 0.0)

        # Slow-DoS detection: single IP saturates a single endpoint with high latency.
        # Slowloris / Slowhttptest keep many connections open — they appear distributed
        # overall but monopolise one HTTP service endpoint.
        # Restrict to plain-HTTP ports (80, 8080, 8000) — HTTPS (443) at high saturation
        # from one browsing machine is normal behaviour, NOT a slow-DoS attack.
        _SLOW_DOS_PORTS = frozenset({80, 8080, 8000})
        top_ip_ep_tuple = ctx.raw_metrics.get("top_ip_ep", ("", ""))
        _top_ep = top_ip_ep_tuple[1] if isinstance(top_ip_ep_tuple, (list, tuple)) and len(top_ip_ep_tuple) == 2 else ""
        try:
            _top_ep_port = int(_top_ep.split("/port_")[-1].split("/")[0])
        except (ValueError, IndexError):
            _top_ep_port = 0
        top_ep_is_slow_dos_candidate = _top_ep_port in _SLOW_DOS_PORTS

        SLOW_DOS_EP_SAT  = 0.50   # single IP owns ≥50% of top endpoint
        SLOW_DOS_MIN_CNT = 40     # at least 40 requests to that endpoint
        slow_dos = (
            ip_ep_sat >= SLOW_DOS_EP_SAT
            and top_ip_ep_count >= SLOW_DOS_MIN_CNT
            and avg_latency > self.HIGH_LATENCY_BENIGN_MS
            and top_ep_is_slow_dos_candidate   # only plain-HTTP slow attacks (Slowloris, Slowhttptest)
        )

        # Path 2: port-80-specific pair with high cap-ratio.
        # This catches batches where DNS/NTP/other traffic dominates globally so the
        # slowloris attacker on port 80 is NOT the top (ip,ep) overall, AND batches
        # where fast benign traffic dilutes the batch avg_latency below the threshold.
        # Signal: ≥30% of the port-80 best pair's connections are at the latency cap
        # (≥9,000 ms) — normal browsing hits the cap in ~10% of connections; slowloris,
        # which holds connections open until timeout, hits ~30-70%.
        _sdos_pair_sat       = ctx.raw_metrics.get("slow_dos_best_sat", 0.0)
        _sdos_pair_cnt       = ctx.raw_metrics.get("slow_dos_best_cnt", 0)
        _sdos_pair_cap_ratio = ctx.raw_metrics.get("slow_dos_best_cap_ratio", 0.0)
        _SLOW_DOS_CAP_RATIO  = 0.50   # ≥50% at cap — slowloris p50=10,000ms (cap); benign ~10%
        slow_dos_path2 = (
            _sdos_pair_cnt >= 100      # 100+ connections from one IP to port_80 is unusual for benign
            and _sdos_pair_sat >= 0.50
            and _sdos_pair_cap_ratio >= _SLOW_DOS_CAP_RATIO
        )
        slow_dos = slow_dos or slow_dos_path2
        if slow_dos:
            ctx.hypothesis = "slow_dos_flood"
            ctx.threat_type = ThreatType.DOS
            if slow_dos_path2 and not (ip_ep_sat >= 0.50 and top_ip_ep_count >= 40):
                # Path 2 fired: use the port-80 best pair for logging
                _sdos_best = ctx.raw_metrics.get("slow_dos_best_pair", ("", ""))
                ctx.log(
                    f"HYPOTHESIZE: slow-DoS (path2/cap-ratio) — "
                    f"{_sdos_best[0]} owns {_sdos_pair_sat:.0%} of {_sdos_best[1]} "
                    f"({_sdos_pair_cnt} reqs, cap_ratio={_sdos_pair_cap_ratio:.0%})"
                )
            else:
                ctx.log(
                    f"HYPOTHESIZE: slow-DoS — single IP owns {ip_ep_sat:.0%} of {_top_ep} "
                    f"({top_ip_ep_count} reqs) with avg_lat={avg_latency:.0f}ms"
                )
            return

        # Traffic-profile guard: high-rate to DNS/NTP/NetBIOS/HTTPS from internal IPs
        # is normal LAN behaviour — never a volumetric DoS attack vector.
        # HTTPS (443/8443) at high saturation from one machine = persistent TLS session.
        _BENIGN_HIGH_RATE_PORTS = frozenset({53, 123, 137, 138, 443, 5353, 67, 68})
        top_ip_ep_is_benign_svc = _top_ep_port in _BENIGN_HIGH_RATE_PORTS
        extreme_flood_pre = top_count > total * 0.90
        if top_ip_ep_is_benign_svc and not extreme_flood_pre:
            ctx.hypothesis = "udp_service_traffic_benign"
            ctx.log(
                f"HYPOTHESIZE: top traffic is benign service port {_top_ep} — DNS/NTP/HTTPS"
            )
            return

        # Strong diversity guard: many IPs sharing the load → distributed benign traffic
        if unique_ips > self.MAX_IP_DIVERSITY and dominant_ratio < self.DOMINANT_IP_RATIO:
            ctx.hypothesis = "distributed_traffic_benign"
            ctx.log(
                f"HYPOTHESIZE: {unique_ips} unique IPs sharing load (dominant={dominant_ratio:.0%}) "
                f"— distributed traffic, not spike"
            )
            return

        # Absolute single-source flood
        if top_count >= self.HIGH_RATE_ABSOLUTE and dominant_ratio >= self.DOMINANT_IP_RATIO:
            avg_latency = ctx.raw_metrics.get("avg_latency", 0.0)
            extreme_flood = top_count > total * 0.90  # >90% of window from single IP
            if unique_ips <= 2 and avg_latency > self.HIGH_LATENCY_BENIGN_MS and not extreme_flood:
                ctx.hypothesis = "high_latency_single_ip_benign"
                ctx.log(
                    f"HYPOTHESIZE: single-IP high volume BUT avg_latency={avg_latency:.0f}ms "
                    f"> {self.HIGH_LATENCY_BENIGN_MS}ms — likely long-lived benign session"
                )
            else:
                ctx.hypothesis = "high_absolute_volume"
                ctx.threat_type = ThreatType.DOS
                ctx.log(
                    f"HYPOTHESIZE: single-source HIGH volume — {top_count} reqs from "
                    f"{ctx.raw_metrics['top_ip']} ({dominant_ratio:.0%} of window)"
                )
        elif total >= self.MIN_REQUESTS_TO_ANALYSE:
            ctx.hypothesis = "possible_rate_anomaly"
            ctx.log(f"HYPOTHESIZE: checking rate anomaly (total={total})")
        else:
            ctx.hypothesis = "insufficient_volume"
            ctx.log("HYPOTHESIZE: not enough data to form hypothesis")

    def investigate(self, ctx: AgentContext) -> None:
        """Compute z-scores against baselines; verify dominant-IP evidence."""
        if ctx.hypothesis in ("warmup_learning", "distributed_traffic_benign",
                               "insufficient_volume", "high_latency_single_ip_benign",
                               "udp_service_traffic_benign"):
            # Update LTM but do not raise confidence
            endpoint_counts = ctx.raw_metrics.get("endpoint_counts", {})
            for ep, count in endpoint_counts.items():
                self.memory.ltm.record_rate(ep, float(count))
            return

        # Slow-DoS: single IP monopolises a single endpoint — high confidence
        if ctx.hypothesis == "slow_dos_flood":
            ip_ep_sat       = ctx.raw_metrics.get("ip_ep_saturation", 0.0)
            top_ip_ep_count = ctx.raw_metrics.get("top_ip_ep_count", 0)
            top_ip_ep       = ctx.raw_metrics.get("top_ip_ep", ("", ""))
            ip, ep          = top_ip_ep if isinstance(top_ip_ep, (list, tuple)) and len(top_ip_ep) == 2 else ("?", "?")
            conf = min(1.0, 0.60 + ip_ep_sat * 0.40)  # 0.80 at sat=0.50, 1.0 at sat=1.0
            ctx.confidence_score = conf
            ctx.indicators.append(
                f"slow_dos_endpoint: {ip} owns {ip_ep_sat:.0%} of {ep} "
                f"({top_ip_ep_count} reqs, avg_lat={ctx.raw_metrics.get('avg_latency', 0):.0f}ms)"
            )
            self._post_evidence("dos:slow_flood", top_ip_ep_count, conf, ["volume", "dos"])
            ctx.log(f"INVESTIGATE: slow-DoS conf={conf:.2f} (ep_saturation={ip_ep_sat:.2f})")
            return

        ip_counts       = ctx.raw_metrics.get("ip_counts", {})
        baselines       = ctx.raw_metrics.get("baselines", {})
        endpoint_counts = ctx.raw_metrics.get("endpoint_counts", {})
        dominant_ratio  = ctx.raw_metrics.get("dominant_ratio", 0.0)

        z_scores = {}
        for ep, count in endpoint_counts.items():
            baseline = baselines.get(ep)
            if baseline is None:
                self.memory.ltm.record_rate(ep, float(count))
                continue
            historical = [baseline] * 10
            result = self.tools.call(
                "run_statistical_test",
                values=historical + [float(count)],
                test="zscore",
                threshold=self.RATE_SPIKE_THRESHOLD,
            )
            z_scores[ep] = result
            if result.get("significant"):
                ctx.indicators.append(f"rate_spike on {ep}: z={result['z']:.2f}")

        ctx.raw_metrics["z_scores"] = z_scores

        # Update LTM for future runs
        for ep, count in endpoint_counts.items():
            self.memory.ltm.record_rate(ep, float(count))

        # Absolute-volume AND dominant check (both required)
        top_count = ctx.raw_metrics.get("top_ip_count", 0)
        top_ip    = ctx.raw_metrics.get("top_ip", "")
        if top_count >= self.HIGH_RATE_ABSOLUTE and dominant_ratio >= self.DOMINANT_IP_RATIO:
            ctx.indicators.append(
                f"absolute_high_volume: {top_count} reqs from {top_ip} "
                f"({dominant_ratio:.0%} dominance)"
            )
            ctx.confidence_score = max(ctx.confidence_score, 0.82)
            self._post_evidence("dos:high_volume", top_count, 0.82, ["volume", "dos"])

        # ── Isolation Forest anomaly check ────────────────────────────────
        self._retrain_iso_forest()
        iso_score = self._iso_anomaly_score(
            dominant_ratio,
            float(top_count),
            ctx.raw_metrics.get("avg_latency", 0.0),
        )
        if iso_score is not None:
            ctx.raw_metrics["iso_score"] = iso_score
            # Isolation Forest scores range ~[-0.5, 0]; lower = more anomalous
            if iso_score < -0.25:
                iso_conf = min(1.0, abs(iso_score) * 2.0)
                ctx.confidence_score = max(ctx.confidence_score, iso_conf)
                ctx.indicators.append(
                    f"isolation_forest_anomaly: score={iso_score:.3f} "
                    f"(dom={dominant_ratio:.2f}, top={top_count})"
                )
                ctx.log(f"INVESTIGATE: IF anomaly score={iso_score:.3f} → conf boost to {iso_conf:.2f}")

        # Update per-IP rates in LTM for future historical comparisons
        for ip, cnt in ip_counts.items():
            self.memory.ltm.record_ip_rate(ip, float(cnt))

        # Aggregate z-score confidence (only if dominant IP is also suspicious)
        significant = [v for v in z_scores.values() if v.get("significant")]
        if significant and dominant_ratio >= self.DOMINANT_IP_RATIO:
            avg_z = sum(abs(v["z"]) for v in significant) / len(significant)
            z_conf = min(1.0, avg_z / 6.0)
            # Only apply z-score confidence if it clears the minimum bar
            if z_conf >= self.MIN_ZSCORE_CONFIDENCE:
                ctx.confidence_score = max(ctx.confidence_score, z_conf)
                ctx.log(
                    f"INVESTIGATE: {len(significant)} endpoints with significant z-scores; "
                    f"avg_z={avg_z:.2f} → conf={z_conf:.2f}"
                )
        elif significant:
            ctx.log(
                f"INVESTIGATE: z-scores significant BUT traffic is distributed — "
                f"suppressing confidence (dominant_ratio={dominant_ratio:.0%})"
            )

    def evaluate(self, ctx: AgentContext) -> LoopDecision:
        if ctx.hypothesis in ("warmup_learning", "insufficient_volume",
                               "distributed_traffic_benign",
                               "high_latency_single_ip_benign",
                               "udp_service_traffic_benign"):
            return LoopDecision.INSUFFICIENT_DATA

        if ctx.confidence_score >= 0.75 and ctx.indicators:
            return LoopDecision.CONCLUDE

        if ctx.iteration >= 2 and ctx.confidence_score > 0.0:
            return LoopDecision.CONCLUDE

        # Revise if not enough signal after first iteration
        if ctx.confidence_score < 0.3 and ctx.iteration == 1:
            ctx.log("EVALUATE: low confidence, will revise hypothesis")
            ctx.hypothesis = "revisiting_with_lower_threshold"
            return LoopDecision.REVISE

        return LoopDecision.CONCLUDE

    def conclude(self, ctx: AgentContext) -> AgentFinding:
        # Raised threshold: need 0.55 confidence AND indicators to call ATTACK
        threat_detected = ctx.confidence_score >= 0.55 and bool(ctx.indicators)

        if threat_detected:
            self._post_evidence(
                "dos:detected",
                {"confidence": ctx.confidence_score, "indicators": ctx.indicators},
                ctx.confidence_score,
                ["volume", "dos"],
            )
            ctx.log(f"CONCLUDE: DoS detected (conf={ctx.confidence_score:.2f})")
        else:
            ctx.log("CONCLUDE: no significant volume anomaly")

        return self._make_finding(ctx, threat_detected)
