"""
APISentry Auth Agent

Mandate: Detect credential stuffing, brute-force, and token abuse.
Primary tools: auth_failure_streak (derived from records), query_ip_reputation,
               run_statistical_test.

OODA logic:
  OBSERVE     → collect auth-related requests (status 401/403) per IP
  ORIENT      → baseline auth-failure rates from LTM; check board for geo signals
  HYPOTHESIZE → "credential stuffing" if failure rate is high; "token abuse" if key shared
  INVESTIGATE → compute streak lengths, success-rate signature (~3.2%), entropy of user-agents
  EVALUATE    → conclude if failure streak or suspicious success rate detected
  CONCLUDE    → emit finding
"""

from __future__ import annotations
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from engine.agents.base_agent import AgentContext, BaseAgent, LoopDecision
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, LogRecord, ThreatType


class AuthAgent(BaseAgent):

    # Credential-stuffing "success signature": ~3.2% of attempts succeed
    STUFFING_SUCCESS_RATE_MIN = 0.01
    STUFFING_SUCCESS_RATE_MAX = 0.08
    MIN_ATTEMPTS_FOR_STUFFING = 20   # need enough attempts to detect pattern
    BRUTE_FORCE_FAILURE_STREAK = 10  # consecutive 401/403 from same IP
    HIGH_FAILURE_RATIO = 0.8          # >80% of requests from IP are failures

    def observe(self, ctx: AgentContext) -> None:
        """Split records into auth failures vs successes per IP."""
        ip_failures: Dict[str, int] = defaultdict(int)
        ip_successes: Dict[str, int] = defaultdict(int)
        ip_total: Dict[str, int] = defaultdict(int)

        # Track consecutive failure streaks per IP
        ip_sequences: Dict[str, List[int]] = defaultdict(list)

        for r in ctx.records:
            ip_total[r.ip] += 1
            if r.status in (401, 403):
                ip_failures[r.ip] += 1
                ip_sequences[r.ip].append(0)  # 0 = failure
            elif r.status == 200:
                ip_successes[r.ip] += 1
                ip_sequences[r.ip].append(1)  # 1 = success

        ctx.raw_metrics["ip_failures"] = dict(ip_failures)
        ctx.raw_metrics["ip_successes"] = dict(ip_successes)
        ctx.raw_metrics["ip_total"] = dict(ip_total)
        ctx.raw_metrics["ip_sequences"] = {ip: seq for ip, seq in ip_sequences.items()}

        total_failures = sum(ip_failures.values())
        ctx.log(
            f"OBSERVE: {total_failures} auth failures across {len(ip_failures)} IPs "
            f"out of {len(ctx.records)} total requests"
        )

    def orient(self, ctx: AgentContext) -> None:
        """Enrich with historical baselines and IP reputation."""
        ip_failures = ctx.raw_metrics.get("ip_failures", {})
        ip_total = ctx.raw_metrics.get("ip_total", {})

        # Fetch historical auth-failure baselines from LTM
        baselines = {}
        for ip in list(ip_failures.keys())[:20]:
            baselines[ip] = self.memory.ltm.get_baseline_auth_failures(ip)
        ctx.raw_metrics["auth_baselines"] = baselines

        # Check for datacenter IPs from GeoIP agent / evidence board
        datacenter_ips = self.tools.call("read_evidence_board", key_filter="geo:", min_confidence=0.6)
        ctx.raw_metrics["datacenter_evidence"] = datacenter_ips

        # Read temporal bot evidence — bots + auth failures → credential stuffing
        bot_evidence = self.tools.call("read_evidence_board", key_filter="bot_timing", min_confidence=0.5)
        ctx.raw_metrics["bot_timing_evidence"] = bool(bot_evidence)

        if bot_evidence:
            ctx.log("ORIENT: bot timing evidence found — credential stuffing probability elevated")

    def hypothesize(self, ctx: AgentContext) -> None:
        """
        Hypothesis selection:
          - credential_stuffing : many IPs with low-but-nonzero success rate
          - brute_force         : few IPs with very high failure streaks
          - token_abuse         : normal user-agent entropy but anomalous API key sharing (stub)
          - clean               : no auth anomalies
        """
        ip_failures = ctx.raw_metrics.get("ip_failures", {})
        ip_successes = ctx.raw_metrics.get("ip_successes", {})
        ip_total = ctx.raw_metrics.get("ip_total", {})

        if not ip_failures:
            ctx.hypothesis = "no_auth_failures"
            ctx.log("HYPOTHESIZE: no auth failures found")
            return

        # Compute per-IP success rates where failures exist
        suspicious_success_rates = []
        for ip, failures in ip_failures.items():
            total = ip_total.get(ip, failures)
            successes = ip_successes.get(ip, 0)
            if total >= self.MIN_ATTEMPTS_FOR_STUFFING:
                rate = successes / total
                if self.STUFFING_SUCCESS_RATE_MIN <= rate <= self.STUFFING_SUCCESS_RATE_MAX:
                    suspicious_success_rates.append((ip, rate))

        if suspicious_success_rates:
            ctx.hypothesis = "credential_stuffing"
            ctx.threat_type = ThreatType.CREDENTIAL_STUFFING
            ctx.raw_metrics["suspicious_ips"] = suspicious_success_rates
            ctx.log(
                f"HYPOTHESIZE: credential stuffing — {len(suspicious_success_rates)} IPs "
                f"with suspicious success rates"
            )
            return

        # Brute force: single IP with very high failure count
        top_ip, top_failures = max(ip_failures.items(), key=lambda x: x[1])
        if top_failures >= self.BRUTE_FORCE_FAILURE_STREAK:
            ctx.hypothesis = "brute_force"
            ctx.threat_type = ThreatType.BRUTE_FORCE
            ctx.raw_metrics["brute_force_ip"] = top_ip
            ctx.log(f"HYPOTHESIZE: brute force from {top_ip} ({top_failures} failures)")
        else:
            ctx.hypothesis = "low_level_auth_noise"
            ctx.log("HYPOTHESIZE: low-level auth noise, investigating further")

    def investigate(self, ctx: AgentContext) -> None:
        """Compute streak lengths, success-rate signatures, and user-agent entropy."""
        ip_sequences = ctx.raw_metrics.get("ip_sequences", {})
        ip_failures = ctx.raw_metrics.get("ip_failures", {})
        ip_total = ctx.raw_metrics.get("ip_total", {})
        ip_successes = ctx.raw_metrics.get("ip_successes", {})

        # ── Failure streak detection ─────────────────────────────────────
        max_streak = 0
        streaky_ips = []
        for ip, seq in ip_sequences.items():
            streak = current = 0
            for s in seq:
                if s == 0:  # failure
                    current += 1
                    streak = max(streak, current)
                else:
                    current = 0
            if streak >= self.BRUTE_FORCE_FAILURE_STREAK:
                streaky_ips.append((ip, streak))
                ctx.indicators.append(f"auth_failure_streak: {ip} → {streak} consecutive failures")

        ctx.raw_metrics["max_failure_streak"] = max_streak
        ctx.raw_metrics["streaky_ips"] = streaky_ips

        # ── Success-rate signature (credential stuffing) ─────────────────
        stuffing_ips = []
        for ip, failures in ip_failures.items():
            total = ip_total.get(ip, failures)
            successes = ip_successes.get(ip, 0)
            if total >= self.MIN_ATTEMPTS_FOR_STUFFING:
                rate = successes / total
                if self.STUFFING_SUCCESS_RATE_MIN <= rate <= self.STUFFING_SUCCESS_RATE_MAX:
                    stuffing_ips.append((ip, round(rate, 4)))
                    ctx.indicators.append(
                        f"stuffing_signature: {ip} success_rate={rate:.1%} "
                        f"({successes}/{total})"
                    )

        if stuffing_ips:
            ctx.confidence_score = max(ctx.confidence_score, 0.80)
            self._post_evidence(
                "auth:credential_stuffing",
                {"ips": stuffing_ips},
                ctx.confidence_score,
                ["auth", "stuffing"],
            )

        if streaky_ips:
            streak_conf = min(1.0, max(s for _, s in streaky_ips) / 50.0)
            ctx.confidence_score = max(ctx.confidence_score, streak_conf + 0.4)
            self._post_evidence(
                "auth:brute_force",
                {"ips": streaky_ips},
                ctx.confidence_score,
                ["auth", "brute_force"],
            )

        # ── High failure ratio (catch-all) ───────────────────────────────
        for ip, failures in ip_failures.items():
            total = ip_total.get(ip, 1)
            ratio = failures / total
            if ratio >= self.HIGH_FAILURE_RATIO and total >= 5:
                ctx.indicators.append(f"high_failure_ratio: {ip} → {ratio:.0%}")
                ctx.confidence_score = max(ctx.confidence_score, 0.60)

        # Update LTM
        for ip, failures in ip_failures.items():
            self.memory.ltm.record_auth_failure(ip, failures)

    def evaluate(self, ctx: AgentContext) -> LoopDecision:
        if ctx.hypothesis == "no_auth_failures":
            return LoopDecision.CONCLUDE  # clean — no threat

        if ctx.confidence_score >= 0.7 and ctx.indicators:
            return LoopDecision.CONCLUDE

        if ctx.iteration >= 2:
            return LoopDecision.CONCLUDE

        if ctx.hypothesis == "low_level_auth_noise" and ctx.iteration == 1:
            ctx.log("EVALUATE: revising to check failure ratios more carefully")
            return LoopDecision.REVISE

        return LoopDecision.CONCLUDE

    def conclude(self, ctx: AgentContext) -> AgentFinding:
        threat_detected = ctx.confidence_score >= 0.45 and bool(ctx.indicators)
        if threat_detected:
            ctx.log(f"CONCLUDE: auth threat detected — {ctx.threat_type} (conf={ctx.confidence_score:.2f})")
        else:
            ctx.log("CONCLUDE: no significant auth anomaly")
        return self._make_finding(ctx, threat_detected)
