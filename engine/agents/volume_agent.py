"""
APISentry Volume Agent

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
from typing import List

from engine.agents.base_agent import AgentContext, BaseAgent, LoopDecision
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, LogRecord, ThreatType


class VolumeAgent(BaseAgent):

    # ── Tunable thresholds (calibrated for CICIDS 2017 / 500-record windows) ──
    RATE_SPIKE_THRESHOLD   = 3.5      # z-score
    MIN_REQUESTS_TO_ANALYSE = 5
    HIGH_RATE_ABSOLUTE     = 450      # req / window from a SINGLE IP
    DOMINANT_IP_RATIO      = 0.90     # single IP must own >90% of traffic
    MAX_IP_DIVERSITY       = 5        # if >5 unique IPs contribute equally → benign spread
    WARMUP_BATCHES         = 10       # first N batches only learn, never alert
    MIN_ZSCORE_CONFIDENCE  = 0.55     # z-scores alone need this confidence to fire
    HIGH_LATENCY_BENIGN_MS = 6500.0   # single-IP batches with avg latency above this are likely long-lived benign sessions

    def observe(self, ctx: AgentContext) -> None:
        """Compute per-IP request counts, endpoint rates, diversity metrics, and avg latency."""
        ip_counts: Counter = Counter()
        endpoint_counts: Counter = Counter()
        total_latency = 0.0

        for r in ctx.records:
            ip_counts[r.ip] += 1
            ep = r.endpoint_template or r.endpoint
            endpoint_counts[ep] += 1
            total_latency += r.latency

        total = len(ctx.records)
        top_ip, top_count = ip_counts.most_common(1)[0] if ip_counts else ("", 0)
        dominant_ratio = top_count / total if total > 0 else 0.0
        unique_ips = len(ip_counts)
        avg_latency = total_latency / total if total > 0 else 0.0

        ctx.raw_metrics["ip_counts"]       = dict(ip_counts.most_common(10))
        ctx.raw_metrics["endpoint_counts"] = dict(endpoint_counts.most_common(10))
        ctx.raw_metrics["total_requests"]  = total
        ctx.raw_metrics["top_ip"]          = top_ip
        ctx.raw_metrics["top_ip_count"]    = top_count
        ctx.raw_metrics["dominant_ratio"]  = dominant_ratio
        ctx.raw_metrics["unique_ips"]      = unique_ips
        ctx.raw_metrics["avg_latency"]     = avg_latency

        ctx.log(
            f"OBSERVE: {total} reqs | unique_ips={unique_ips} | "
            f"top_ip={top_ip} ({top_count} reqs, {dominant_ratio:.0%}) | "
            f"avg_lat={avg_latency:.0f}ms"
        )

    def orient(self, ctx: AgentContext) -> None:
        """Fetch historical baselines for dominant endpoints; check warm-up state."""
        # Track batch counter in LTM for warm-up
        batch_num = self.memory.ltm.increment_batch_count()
        ctx.raw_metrics["batch_num"] = batch_num
        ctx.raw_metrics["in_warmup"] = batch_num <= self.WARMUP_BATCHES

        if ctx.raw_metrics["in_warmup"]:
            ctx.log(f"ORIENT: warm-up batch {batch_num}/{self.WARMUP_BATCHES} — learning only")

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

        dominant_ratio = ctx.raw_metrics.get("dominant_ratio", 0.0)
        top_count      = ctx.raw_metrics.get("top_ip_count", 0)
        unique_ips     = ctx.raw_metrics.get("unique_ips", 0)
        total          = ctx.raw_metrics.get("total_requests", 0)

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
            # Latency guard: single-IP batches with very high latency are likely
            # long-lived benign sessions, not DoS floods
            avg_latency = ctx.raw_metrics.get("avg_latency", 0.0)
            if unique_ips <= 2 and avg_latency > self.HIGH_LATENCY_BENIGN_MS:
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
                               "insufficient_volume", "high_latency_single_ip_benign"):
            # Update LTM but do not raise confidence
            endpoint_counts = ctx.raw_metrics.get("endpoint_counts", {})
            for ep, count in endpoint_counts.items():
                self.memory.ltm.record_rate(ep, float(count))
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
                               "high_latency_single_ip_benign"):
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
