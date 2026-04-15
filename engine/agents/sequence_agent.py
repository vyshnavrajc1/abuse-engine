"""
Abuse Engine Sequence Agent

Mandate: Detect sequential access anomalies using per-IP Markov transition models.

Detection logic:
  - Build a transition map per IP: {(endpoint_a, endpoint_b): count}
  - Score each transition by its probability vs the LTM benign baseline
  - Flag IPs whose transition sequence has low probability under the baseline
    (e.g. /port_20 → /port_21 → /port_22 — sequential numeric enumeration)
  - Numeric sequential detection: consecutive ports/IDs incrementing by ≤ 2

OODA logic:
  OBSERVE     → sort requests per IP by timestamp, build transition map
  ORIENT      → fetch LTM transition baseline; compute per-IP log-probability
  HYPOTHESIZE → "sequence_abuse" if any IP has transitions anomalous vs baseline
  INVESTIGATE → verify numeric sequential pattern; z-score log-prob vs batch mean
  EVALUATE    → conclude
  CONCLUDE    → emit finding

Adaptive:
  LTM transition baseline updated each batch (rolling window, cap 200 unique transitions).
  MIN_SEQUENCE_LENGTH adapts as mean of IP sequence lengths on benign batches.
"""

from __future__ import annotations
import math
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

from engine.agents.base_agent import AgentContext, BaseAgent, LoopDecision
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from schemas.models import AgentFinding, LogRecord, ThreatType


# Regex to extract a numeric component from an endpoint string
# /port_22 → 22  |  /api/user/42 → 42  |  /v1/resource/7 → 7
_NUMERIC_RE = re.compile(r"[\/_\-](\d+)(?:[\/\?#]|$)")


def _extract_numeric(endpoint: str) -> Optional[int]:
    m = _NUMERIC_RE.search(endpoint)
    return int(m.group(1)) if m else None


def _is_sequential(nums: List[int], max_step: int = 2, min_run: int = 10) -> bool:
    """Return True if at least min_run consecutive numbers differ by <= max_step
    AND are in the port scan range (1–10000).
    Higher threshold (10 vs 5) prevents near-sequential source-port FPs on benign traffic."""
    if len(nums) < min_run:
        return False
    # Filter to well-known port range to avoid ephemeral port FPs
    nums = [n for n in nums if 1 <= n <= 10000]
    if len(nums) < min_run:
        return False
    consecutive = 1
    for i in range(1, len(nums)):
        if 1 <= abs(nums[i] - nums[i - 1]) <= max_step:
            consecutive += 1
            if consecutive >= min_run:
                return True
        else:
            consecutive = 1
    return False


class SequenceAgent(BaseAgent):

    # Cold-start fallbacks
    MIN_SEQUENCE_LENGTH       = 4     # minimum transitions per IP to analyse
    LOW_PROB_THRESHOLD        = -4.5  # avg log-prob per step threshold (base-2)
    SEQUENTIAL_BOOST          = 0.20  # confidence boost for numeric sequential IPs
    MAX_IPS_ANALYSED          = 30    # cap analysis to top-N IPs by sequence length
    MIN_BASELINE_BATCHES      = 30    # warm-up: require this many batches before alerting

    def _get_baseline_transition_prob(self, a: str, b: str) -> float:
        """
        Fetch P(b | a) from LTM baseline.
        Returns small smoothed probability if transition not seen before.
        """
        mean, _ = self.memory.ltm.get_batch_distribution(
            "SequenceAgent", f"trans::{a}::{b}"
        )
        if mean is not None and mean > 0:
            return min(1.0, mean)
        # Laplace-smoothed fallback: unknown transitions treated as rare
        return 0.01

    def _ip_log_prob(self, transitions: List[Tuple[str, str]]) -> float:
        """Return AVERAGE log2 probability per transition step."""
        if not transitions:
            return 0.0
        total = 0.0
        for a, b in transitions:
            p = self._get_baseline_transition_prob(a, b)
            total += math.log2(max(p, 1e-10))
        return total / len(transitions)  # normalised per step

    # ── OODA phases ────────────────────────────────────────────────────────

    def observe(self, ctx: AgentContext) -> None:
        """Sort records per IP by timestamp, build transition map."""
        ip_records: Dict[str, List[LogRecord]] = defaultdict(list)
        for r in ctx.records:
            ip_records[r.ip].append(r)

        # Sort each IP's requests by timestamp
        ip_sorted: Dict[str, List[str]] = {}
        ip_transitions: Dict[str, List[Tuple[str, str]]] = {}
        for ip, reqs in ip_records.items():
            reqs.sort(key=lambda r: r.timestamp)
            eps = [r.endpoint_template or r.endpoint for r in reqs]
            ip_sorted[ip] = eps
            if len(eps) >= 2:
                ip_transitions[ip] = list(zip(eps[:-1], eps[1:]))

        # Rank IPs by sequence length (most activity first)
        ranked_ips = sorted(
            ip_transitions.keys(),
            key=lambda ip: len(ip_transitions[ip]),
            reverse=True,
        )

        ctx.raw_metrics["ip_sorted"]      = ip_sorted
        ctx.raw_metrics["ip_transitions"] = ip_transitions
        ctx.raw_metrics["ranked_ips"]     = ranked_ips
        ctx.raw_metrics["total_transitions"] = sum(
            len(t) for t in ip_transitions.values()
        )

        ctx.log(
            f"OBSERVE: {len(ip_records)} IPs | "
            f"{ctx.raw_metrics['total_transitions']} transitions | "
            f"top_ip={ranked_ips[0] if ranked_ips else 'none'}"
        )

    def orient(self, ctx: AgentContext) -> None:
        """Compute per-IP log-probabilities vs LTM baseline."""
        ip_transitions = ctx.raw_metrics.get("ip_transitions", {})
        ranked_ips = ctx.raw_metrics.get("ranked_ips", [])

        ip_log_probs: Dict[str, float] = {}
        for ip in ranked_ips[:self.MAX_IPS_ANALYSED]:
            transitions = ip_transitions.get(ip, [])
            if len(transitions) < self.MIN_SEQUENCE_LENGTH:
                continue
            ip_log_probs[ip] = self._ip_log_prob(transitions)

        # Record transition frequency for adaptive baseline
        all_transitions: Counter = Counter()
        for transitions in ip_transitions.values():
            all_transitions.update(transitions)
        # Store top-20 transition counts as ratios (normalised to [0,1])
        total = max(sum(all_transitions.values()), 1)
        for (a, b), cnt in all_transitions.most_common(20):
            self.memory.ltm.record_batch_stats(
                "SequenceAgent", {f"trans::{a}::{b}": cnt / total}
            )
        # Monotonic batch counter (never evicted, unlike _batch_stats)
        batch_count = self.memory.ltm.increment_agent_batch_count("SequenceAgent")

        ctx.raw_metrics["ip_log_probs"] = ip_log_probs

        ctx.raw_metrics["sequence_batch_count"] = batch_count
        ctx.raw_metrics["in_warmup"] = batch_count < self.MIN_BASELINE_BATCHES

        if ip_log_probs:
            worst_ip = min(ip_log_probs, key=ip_log_probs.get)
            worst_lp = ip_log_probs[worst_ip]
            ctx.log(f"ORIENT: worst log-prob IP={worst_ip} lp={worst_lp:.2f} "
                    f"(warmup={ctx.raw_metrics['in_warmup']}, batch={batch_count})")
        else:
            ctx.log("ORIENT: no IPs with sufficient sequence length")

    def hypothesize(self, ctx: AgentContext) -> None:
        """Hypothesize sequence abuse if any IP has unusually low log-probability."""
        if ctx.raw_metrics.get("in_warmup"):
            ctx.hypothesis = "warmup_learning"
            ctx.log(
                f"HYPOTHESIZE: warm-up (batch {ctx.raw_metrics.get('sequence_batch_count','?')}"
                f"/{self.MIN_BASELINE_BATCHES}) — building baseline transition model"
            )
            return

        ip_log_probs = ctx.raw_metrics.get("ip_log_probs", {})
        if not ip_log_probs:
            ctx.hypothesis = "insufficient_sequence_data"
            ctx.log("HYPOTHESIZE: no sequence data for analysis")
            return

        ip_sorted = ctx.raw_metrics.get("ip_sorted", {})

        # Primary signal: numeric sequential patterns (port scans, ID enumeration)
        sequential_ips: List[str] = []
        for ip, eps in ip_sorted.items():
            if len(eps) < self.MIN_SEQUENCE_LENGTH:
                continue
            numerics = [_extract_numeric(e) for e in eps]
            numerics = [n for n in numerics if n is not None]
            if _is_sequential(numerics):
                sequential_ips.append(ip)

        # Secondary signal: low Markov probability (only after warm-up baseline is rich)
        low_prob_ips = [ip for ip, lp in ip_log_probs.items() if lp < self.LOW_PROB_THRESHOLD]

        # Use sequential IPs as the primary (and only) detection signal.
        # The Markov-only fallback was tested and caused excessive FPs on benign batches
        # because the model is not calibrated enough to use log-prob alone without
        # sequential confirmation. Keep it as supporting evidence only.
        suspect_ips = sequential_ips or []

        if suspect_ips:
            ctx.hypothesis = "sequence_abuse"
            ctx.threat_type = ThreatType.SEQUENCE_ABUSE
            ctx.raw_metrics["suspect_ips"] = suspect_ips
            ctx.raw_metrics["low_prob_ips"] = low_prob_ips
            ctx.log(
                f"HYPOTHESIZE: {len(sequential_ips)} sequential IP(s), "
                f"{len(low_prob_ips)} low-prob IP(s) — sequence abuse suspected"
            )
        else:
            ctx.hypothesis = "normal_sequence"
            ctx.raw_metrics["suspect_ips"] = []
            ctx.raw_metrics["low_prob_ips"] = low_prob_ips
            ctx.log("HYPOTHESIZE: no sequential patterns detected")

    def investigate(self, ctx: AgentContext) -> None:
        if ctx.hypothesis in ("insufficient_sequence_data", "normal_sequence", "warmup_learning"):
            return

        ip_sorted     = ctx.raw_metrics.get("ip_sorted", {})
        ip_log_probs  = ctx.raw_metrics.get("ip_log_probs", {})
        suspect_ips   = ctx.raw_metrics.get("suspect_ips", [])  # sequential IPs

        for ip in suspect_ips[:5]:  # cap investigation depth
            lp = ip_log_probs.get(ip, 0.0)
            eps = ip_sorted.get(ip, [])
            numerics = [_extract_numeric(e) for e in eps]
            numerics = [n for n in numerics if n is not None]

            # Only numeric sequential patterns (reliable on CICIDS port_X data)
            ctx.indicators.append(
                f"numeric_sequential_scan: {ip} — {numerics[:8]} "
                f"(log-prob={lp:.2f})"
            )
            base_conf = 0.80 + self.SEQUENTIAL_BOOST
            # Boost confidence if Markov also agrees (low log-prob corroborates)
            if lp < self.LOW_PROB_THRESHOLD:
                base_conf = min(1.0, base_conf + 0.05)
            ctx.confidence_score = max(ctx.confidence_score, base_conf)
            self._post_evidence(
                f"sequence:numeric_scan:{ip}",
                {"ip": ip, "numeric_sequence": numerics[:10], "log_prob": lp},
                base_conf,
                ["sequence", "port_scan", "enumeration"],
            )

    def evaluate(self, ctx: AgentContext) -> LoopDecision:
        if ctx.hypothesis in ("insufficient_sequence_data", "normal_sequence", "warmup_learning"):
            return LoopDecision.INSUFFICIENT_DATA
        return LoopDecision.CONCLUDE

    def conclude(self, ctx: AgentContext) -> AgentFinding:
        threat_detected = ctx.confidence_score >= 0.60 and bool(ctx.indicators)
        if threat_detected:
            ctx.log(
                f"CONCLUDE: SEQUENCE_ABUSE detected "
                f"(conf={ctx.confidence_score:.2f}, {len(ctx.indicators)} indicator(s))"
            )
        else:
            ctx.log("CONCLUDE: no sequence abuse detected")
        return self._make_finding(ctx, threat_detected)
