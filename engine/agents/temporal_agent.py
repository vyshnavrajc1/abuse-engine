"""
APISentry Temporal Agent

Mandate: Detect bot periodicity and off-hours access patterns.
Primary tools: detect_periodicity, run_statistical_test (kstest), compute_entropy.

OODA logic:
  OBSERVE     → extract timestamps per IP, compute inter-arrival times
  ORIENT      → read volume/dos evidence from board (context enrichment)
  HYPOTHESIZE → "bot timing" if CV is very low OR off-hours ratio is very high
  INVESTIGATE → FFT periodicity, KS-test vs human distribution, entropy
  EVALUATE    → conclude on bot_confidence threshold
  CONCLUDE    → emit finding

Key calibrations for CICIDS 2017 (synthetic timestamps):
  - BOT_CONFIDENCE_THRESHOLD raised 0.65 → 0.85 (CICIDS timestamps are synthetically regular)
  - MIN_PERIODIC_IPS: require ≥ 2 IPs showing periodicity (single IP is insufficient)
  - MIN_TIMESTAMP_SPAN_MS: if entire batch spans < 200ms, skip periodicity (synthetic artifact)
  - OFF_HOURS threshold tightened: 0.7 → 0.85 required ratio
"""

from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

import numpy as np

from engine.agents.base_agent import AgentContext, BaseAgent, LoopDecision
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, LogRecord, ThreatType


# "Human" inter-arrival distribution parameters (synthesised from empirical studies)
# Mean ~2000ms, std ~3000ms — high variance, long tail
_HUMAN_IAT_SAMPLE = [
    200, 800, 1500, 3000, 500, 12000, 250, 7000, 1100, 4500,
    300, 600, 9000, 2200, 800, 350, 18000, 1200, 500, 3300,
]


class TemporalAgent(BaseAgent):

    BOT_CONFIDENCE_THRESHOLD  = 0.85     # raised from 0.65 — CICIDS timestamps are synthetically regular
    MIN_EVENTS_FOR_ANALYSIS   = 10       # raised from 8 — need more data for reliable periodicity
    MIN_PERIODIC_IPS          = 2        # require ≥ 2 IPs showing periodicity
    MIN_TIMESTAMP_SPAN_MS     = 200.0    # skip if whole batch spans < 200ms (synthetic artifact)
    MIN_IAT_RESOLUTION_MS     = 500.0    # skip per-IP periodicity if median IAT < this (timestamp resolution too low)
    OFF_HOURS                 = set(range(0, 6))   # 00:00 – 05:59 UTC
    OFF_HOURS_DOMINANT_RATIO  = 0.85     # raised from 0.70 — need strong majority

    def observe(self, ctx: AgentContext) -> None:
        """Extract timestamps per IP, compute off-hours ratio, and check span."""
        ip_timestamps: Dict[str, List[float]] = defaultdict(list)
        off_hours_count = 0
        all_ts_ms: List[float] = []

        for r in ctx.records:
            ts_ms = r.timestamp.timestamp() * 1000.0
            ip_timestamps[r.ip].append(ts_ms)
            all_ts_ms.append(ts_ms)
            if r.timestamp.hour in self.OFF_HOURS:
                off_hours_count += 1

        ts_span_ms = (max(all_ts_ms) - min(all_ts_ms)) if len(all_ts_ms) > 1 else 0.0

        ctx.raw_metrics["ip_timestamps"] = {
            ip: sorted(ts) for ip, ts in ip_timestamps.items()
        }
        ctx.raw_metrics["off_hours_ratio"] = (
            off_hours_count / len(ctx.records) if ctx.records else 0.0
        )
        ctx.raw_metrics["ts_span_ms"] = ts_span_ms

        ctx.log(
            f"OBSERVE: {len(ip_timestamps)} unique IPs | "
            f"off_hours_ratio={ctx.raw_metrics['off_hours_ratio']:.2f} | "
            f"span={ts_span_ms:.1f}ms"
        )

    def orient(self, ctx: AgentContext) -> None:
        """Check if volume agent already signalled DoS; accumulate IAT reference samples."""
        dos_evidence = self.tools.call(
            "read_evidence_board", key_filter="dos", min_confidence=0.6
        )
        ctx.raw_metrics["related_dos_evidence"] = bool(dos_evidence)
        if dos_evidence:
            ctx.log("ORIENT: DoS evidence on board — bot timing investigation relevant")
            ctx.confidence_score = max(ctx.confidence_score, 0.25)

        # Accumulate IATs from this batch into LTM to build a data-derived
        # reference distribution for the KS-test (replaces the synthetic
        # _HUMAN_IAT_SAMPLE once MIN_IAT_REFERENCE samples are collected).
        ip_timestamps = ctx.raw_metrics.get("ip_timestamps", {})
        batch_iats: List[float] = []
        for timestamps in ip_timestamps.values():
            if len(timestamps) >= 2:
                batch_iats.extend(float(x) for x in np.diff(sorted(timestamps)))
        if batch_iats:
            self.memory.ltm.add_iat_samples(batch_iats)
        ctx.raw_metrics["iat_reference_ready"] = self.memory.ltm.has_iat_reference()

    def hypothesize(self, ctx: AgentContext) -> None:
        """Form bot-timing hypothesis with stricter guards."""
        off_ratio     = ctx.raw_metrics.get("off_hours_ratio", 0.0)
        ip_timestamps = ctx.raw_metrics.get("ip_timestamps", {})
        ts_span_ms    = ctx.raw_metrics.get("ts_span_ms", 0.0)

        # Guard: if timestamps barely span any time, the data is likely synthetic
        # and periodicity detection will be unreliable
        if ts_span_ms < self.MIN_TIMESTAMP_SPAN_MS:
            ctx.hypothesis = "insufficient_timestamp_span"
            ctx.log(
                f"HYPOTHESIZE: timestamp span={ts_span_ms:.1f}ms < "
                f"{self.MIN_TIMESTAMP_SPAN_MS}ms — synthetic data artifact, skip"
            )
            return

        has_enough_data = any(
            len(ts) >= self.MIN_EVENTS_FOR_ANALYSIS for ts in ip_timestamps.values()
        )

        if not has_enough_data:
            ctx.hypothesis = "insufficient_timing_data"
        elif off_ratio > self.OFF_HOURS_DOMINANT_RATIO:
            ctx.hypothesis = "off_hours_dominant"
            ctx.threat_type = ThreatType.BOT_ACTIVITY
            ctx.log(f"HYPOTHESIZE: off-hours dominant ({off_ratio:.0%} > {self.OFF_HOURS_DOMINANT_RATIO:.0%})")
        else:
            ctx.hypothesis = "check_periodicity"
            ctx.log("HYPOTHESIZE: will investigate inter-arrival periodicity")

    def investigate(self, ctx: AgentContext) -> None:
        """Run FFT periodicity and KS-test on per-IP timestamp sequences."""
        if ctx.hypothesis in ("insufficient_timing_data", "insufficient_timestamp_span"):
            return

        ip_timestamps = ctx.raw_metrics.get("ip_timestamps", {})
        periodicity_results = {}
        periodic_ip_count = 0   # track how many IPs show periodicity

        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) < self.MIN_EVENTS_FOR_ANALYSIS:
                continue

            # ── Resolution guard: skip IPs where timestamps lack sufficient
            #    granularity (e.g. all same-second in CICIDS) — this creates
            #    artificial zero-IAT patterns that look periodic but aren't.
            iats = list(np.diff(sorted(timestamps)))
            if iats:
                median_iat = float(np.median(iats))
                if median_iat < self.MIN_IAT_RESOLUTION_MS:
                    ctx.log(
                        f"INVESTIGATE: skipping {ip} — median IAT={median_iat:.0f}ms "
                        f"< {self.MIN_IAT_RESOLUTION_MS}ms (timestamp resolution too low)"
                    )
                    continue

            # ── Periodicity (FFT) ────────────────────────────────────────
            peri = self.tools.call("detect_periodicity", timestamps_ms=timestamps)
            periodicity_results[ip] = peri

            bot_conf = peri.get("bot_confidence", 0.0)
            if peri.get("periodic") and bot_conf > self.BOT_CONFIDENCE_THRESHOLD:
                periodic_ip_count += 1
                ctx.indicators.append(
                    f"bot_periodicity on {ip}: cv={peri.get('cv')}, "
                    f"period={peri.get('dominant_period_ms')}ms, conf={bot_conf:.2f}"
                )
                # Only update confidence if MULTIPLE IPs show the pattern
                if periodic_ip_count >= self.MIN_PERIODIC_IPS:
                    ctx.confidence_score = max(ctx.confidence_score, bot_conf * 0.9)
                else:
                    # Single IP — tentatively raise but cap lower
                    ctx.confidence_score = max(ctx.confidence_score, bot_conf * 0.6)

            # ── KS-test vs traffic reference distribution ────────────────
            if len(iats) >= 6:
                # Use LTM-derived reference once enough samples have accumulated;
                # fall back to the synthetic constants until then.
                reference = (
                    self.memory.ltm.get_iat_reference()
                    if ctx.raw_metrics.get("iat_reference_ready")
                    else _HUMAN_IAT_SAMPLE
                )
                combined = reference + iats
                ks_result = self.tools.call(
                    "run_statistical_test",
                    values=combined,
                    test="kstest",
                )
                # KS-test alone is weak evidence — only use if periodicity also fires
                if ks_result.get("significant") and periodic_ip_count >= self.MIN_PERIODIC_IPS:
                    ctx.indicators.append(
                        f"ks_test_significant for {ip}: p={ks_result.get('p')}"
                    )
                    ctx.confidence_score = max(ctx.confidence_score, 0.70)

        ctx.raw_metrics["periodicity_results"] = periodicity_results
        ctx.raw_metrics["periodic_ip_count"]   = periodic_ip_count

        # ── Off-hours bonus (only for very dominant ratio) ──────────────
        off_ratio = ctx.raw_metrics.get("off_hours_ratio", 0.0)
        if off_ratio > 0.85:
            ctx.indicators.append(f"off_hours_access: {off_ratio:.0%} requests in 00-06 UTC")
            ctx.confidence_score = max(ctx.confidence_score, 0.60)
        elif off_ratio > 0.70:
            # Weaker signal — only record as indicator if combined with other evidence
            if ctx.confidence_score > 0.40:
                ctx.indicators.append(f"off_hours_elevated: {off_ratio:.0%} in 00-06 UTC")

        # Post to evidence board only with strong multi-IP evidence
        if ctx.confidence_score > 0.65 and periodic_ip_count >= self.MIN_PERIODIC_IPS:
            self._post_evidence(
                "bot_timing:detected",
                {
                    "confidence": ctx.confidence_score,
                    "periodic_ips": [
                        ip for ip, r in periodicity_results.items() if r.get("periodic")
                    ],
                    "periodic_ip_count": periodic_ip_count,
                },
                ctx.confidence_score,
                ["temporal", "bot"],
            )

    def evaluate(self, ctx: AgentContext) -> LoopDecision:
        if ctx.hypothesis in ("insufficient_timing_data", "insufficient_timestamp_span"):
            return LoopDecision.INSUFFICIENT_DATA

        if ctx.confidence_score >= self.BOT_CONFIDENCE_THRESHOLD:
            return LoopDecision.CONCLUDE

        if ctx.iteration >= 2:
            return LoopDecision.CONCLUDE

        if ctx.confidence_score < 0.2 and ctx.iteration == 1:
            ctx.hypothesis = "revisit_with_off_hours_only"
            return LoopDecision.REVISE

        return LoopDecision.CONCLUDE

    def conclude(self, ctx: AgentContext) -> AgentFinding:
        # Raised threshold: need 0.60 confidence AND indicators
        threat_detected = ctx.confidence_score >= 0.60 and bool(ctx.indicators)
        if threat_detected:
            ctx.threat_type = ThreatType.BOT_ACTIVITY
            ctx.log(f"CONCLUDE: bot timing detected (conf={ctx.confidence_score:.2f})")
        else:
            ctx.log("CONCLUDE: no bot timing pattern detected")

        return self._make_finding(ctx, threat_detected)
