"""
Abuse Engine LLM Prompts

Prompt templates for each detection agent and the MetaAgent fusion step.

Design principles:
  - System prompts are short — just the agent's mandate and output schema.
  - User prompts inject the raw_metrics, indicators, and rule-based hint.
  - The rule-based verdict is included as a "prior" to help the LLM calibrate,
    not as a ground truth (LLM is free to override).
  - JSON schema is enforced in the system prompt to reduce parsing failures.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Output schema (shared by all per-agent prompts)
# ---------------------------------------------------------------------------

_AGENT_SCHEMA = """\
Output ONLY a JSON object with these exact keys:
{
  "is_attack": <bool>,
  "threat_type": <one of: NONE | DOS | BRUTE_FORCE | CREDENTIAL_STUFFING | BOT_ACTIVITY | SCRAPING | UNKNOWN_ABUSE>,
  "confidence": <float 0.0 – 1.0>,
  "reasoning": <string, max 3 sentences>
}
Do not include any text outside the JSON object."""

_META_SCHEMA = """\
Output ONLY a JSON object with these exact keys:
{
  "is_attack": <bool>,
  "threat_type": <one of: NONE | DOS | BRUTE_FORCE | CREDENTIAL_STUFFING | BOT_ACTIVITY | SCRAPING | UNKNOWN_ABUSE>,
  "confidence": <float 0.0 – 1.0>,
  "compound_signal": <string or null, e.g. "High Volume + Bot Timing → Scraping Bot">,
  "reasoning": <string, max 4 sentences>
}
Do not include any text outside the JSON object."""


# ---------------------------------------------------------------------------
# Per-agent system prompts
# ---------------------------------------------------------------------------

AGENT_SYSTEM_PROMPTS: Dict[str, str] = {
    "VolumeAgent": f"""\
You are VolumeAgent, a network security analyst specialising in volumetric attacks.
Your mandate: detect DoS floods, scraping bursts, and enumeration spikes from API access logs.
Key signals: single-IP dominance ratio, request rate vs baseline, z-score spikes,
average latency (DoS floods are fast; long-lived benign sessions have high latency).
Threshold guidance: a single IP owning >90% of traffic at 450+ requests/batch with
latency <6500ms is a strong DoS indicator.
{_AGENT_SCHEMA}""",

    "TemporalAgent": f"""\
You are TemporalAgent, a network security analyst specialising in timing-based anomalies.
Your mandate: detect bot periodicity and off-hours automated access.
Key signals: inter-arrival time coefficient of variation (CV), FFT-detected dominant
period, KS-test vs human distribution, off-hours request ratio (00:00–06:00 UTC).
Low CV (< 0.3) and high bot_confidence (> 0.85) across multiple IPs strongly
indicates automated traffic. Ignore timestamps with median IAT < 500ms (low resolution).
{_AGENT_SCHEMA}""",

    "AuthAgent": f"""\
You are AuthAgent, a network security analyst specialising in authentication anomalies.
Your mandate: detect credential stuffing, brute-force, and token abuse patterns.
Key signals: consecutive 401/403 streaks per IP (≥10 = brute force),
success rate in range 1–8% with ≥20 attempts (= credential stuffing signature),
high failure ratio (>80% of IP requests are failures).
{_AGENT_SCHEMA}""",
}


# ---------------------------------------------------------------------------
# MetaAgent fusion system prompt
# ---------------------------------------------------------------------------

META_SYSTEM_PROMPT = f"""\
You are MetaAgent, the orchestrating security analyst for the Abuse Engine.
Your mandate: fuse findings from three specialist agents (VolumeAgent, TemporalAgent,
AuthAgent) into a single authoritative verdict.
Apply conflict resolution (trust the highest-confidence agent on its area of expertise),
detect compound threats (e.g. DoS + Bot Timing → Scraping Bot), and assess overall
attack probability.
If multiple agents agree, weight their confidence. A single low-confidence agent is
insufficient to call ATTACK unless its confidence is ≥ 0.80.
{_META_SCHEMA}"""


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def build_agent_user_prompt(
    agent_name: str,
    raw_metrics: Dict[str, Any],
    indicators: List[str],
    rule_verdict: bool,
    rule_confidence: float,
    reasoning_trace: List[str],
) -> str:
    """Build the user prompt for a per-agent LLM call."""
    # Trim raw_metrics to avoid huge prompts — keep the most informative keys
    slim_metrics = _slim_metrics(raw_metrics)

    lines = [
        "=== Observed batch metrics ===",
        json.dumps(slim_metrics, indent=2),
        "",
        "=== Evidence from tool investigation ===",
        "\n".join(f"  • {ind}" for ind in indicators) if indicators else "  (none)",
        "",
        "=== Rule-based engine hint ===",
        f"  verdict: {'ATTACK' if rule_verdict else 'CLEAN'} | confidence: {rule_confidence:.2f}",
        "",
        "Analyse the evidence and produce your verdict as JSON.",
    ]
    return "\n".join(lines)


def build_meta_user_prompt(
    agent_findings: List[Dict[str, Any]],
    evidence_board: List[Dict[str, Any]],
    rule_is_attack: bool,
    rule_confidence: float,
    rule_compound: List[str],
) -> str:
    """Build the user prompt for the MetaAgent fusion LLM call."""
    findings_block = json.dumps(agent_findings, indent=2)
    board_block = json.dumps(
        [{"key": e["key"], "confidence": e["confidence"]} for e in evidence_board],
        indent=2,
    )
    lines = [
        "=== Agent findings ===",
        findings_block,
        "",
        "=== Evidence board summary ===",
        board_block,
        "",
        "=== Rule-based fusion hint ===",
        f"  verdict: {'ATTACK' if rule_is_attack else 'CLEAN'} | confidence: {rule_confidence:.2f}",
        f"  compound_signals: {rule_compound or 'none'}",
        "",
        "Fuse the agent findings and produce the final verdict as JSON.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_METRIC_WHITELIST = {
    # VolumeAgent
    "total_requests", "unique_ips", "dominant_ratio", "top_ip",
    "top_ip_count", "avg_latency", "in_warmup", "batch_num",
    # TemporalAgent
    "off_hours_ratio", "ts_span_ms", "periodic_ip_count",
    "related_dos_evidence",
    # AuthAgent
    "ip_failures", "ip_successes", "ip_total",
}

def _slim_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the high-signal keys to reduce token count."""
    slim: Dict[str, Any] = {}
    for k, v in metrics.items():
        if k in _METRIC_WHITELIST:
            slim[k] = v
        elif k == "z_scores":
            # Only include if any are significant
            sig = {ep: r for ep, r in v.items() if isinstance(r, dict) and r.get("significant")}
            if sig:
                slim["z_scores_significant"] = sig
        elif k == "periodicity_results":
            # Only include periodic IPs
            peri = {ip: {"cv": r.get("cv"), "bot_confidence": r.get("bot_confidence")}
                    for ip, r in v.items() if isinstance(r, dict) and r.get("periodic")}
            if peri:
                slim["periodic_ips"] = peri
    return slim
