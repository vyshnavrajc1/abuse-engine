"""
llm_agent_node.py – LangChain + Gemini reasoning layer for the spatio-temporal
anomaly detection pipeline.

What this adds
--------------
This module turns the pipeline into a *real* agent by giving a Gemini LLM the
ability to:

1. Read the scored AgentResult (risk score, worst window, feature vector).
2. Call tools to gather more evidence:
     • lookup_ip_reputation   – checks whether an IP is in known threat lists
     • query_threat_intel     – searches a mock threat-intel feed by attack pattern
     • explain_window_features – translates raw feature values into plain English
3. Reason (via ReAct / tool-calling loop) about whether the anomaly is a real
   threat or a false positive.
4. Write a structured LLMAnalysis back into AgentState.metadata so downstream
   alerting / SIEM can consume it.

Integration
-----------
Import make_llm_analysis_node() and wire it into the existing graph:

    from llm_agent_node import make_llm_analysis_node, LLMConfig

    cfg = LLMConfig(api_key="YOUR_GEMINI_KEY")
    graph.add_node("llm_analysis", make_llm_analysis_node(cfg))
    graph.add_edge("severity", "llm_analysis")
    graph.add_edge("llm_analysis", END)

Or use build_agentic_spatio_temporal_graph() which does all of this for you.

Dependencies
------------
    pip install langchain langchain-google-genai google-generativeai

Environment variable shortcut:
    export GEMINI_API_KEY="your-key-here"
    # then pass api_key=None to LLMConfig and it reads from env automatically
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from models import AgentState, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    """All tuneable knobs for the LLM reasoning layer."""
    api_key: Optional[str] = None           # falls back to GEMINI_API_KEY env var
    model_name: str = "gemini-1.5-flash"    # fast + cheap; swap for gemini-1.5-pro
    temperature: float = 0.1               # low = deterministic reasoning
    max_iterations: int = 6                # max ReAct tool-calling rounds
    high_risk_threshold: float = 0.50      # only invoke LLM above this score


# ---------------------------------------------------------------------------
# Result dataclass written into AgentState.metadata["llm_analysis"]
# ---------------------------------------------------------------------------

@dataclass
class LLMAnalysis:
    verdict: str                           # "confirmed_threat" | "likely_fp" | "uncertain"
    confidence: float                      # 0.0 – 1.0
    attack_type: Optional[str]             # e.g. "coordinated_scan", "ip_hopping"
    affected_ips: List[str]
    affected_endpoints: List[str]
    reasoning: str                         # free-text chain-of-thought
    recommended_actions: List[str]
    tool_calls_made: List[str]
    produced_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "attack_type": self.attack_type,
            "affected_ips": self.affected_ips,
            "affected_endpoints": self.affected_endpoints,
            "reasoning": self.reasoning,
            "recommended_actions": self.recommended_actions,
            "tool_calls_made": self.tool_calls_made,
            "produced_at": self.produced_at,
        }


# ---------------------------------------------------------------------------
# Tools (LangChain @tool definitions)
# ---------------------------------------------------------------------------

def _build_tools():
    """
    Build and return the list of LangChain tools available to the agent.

    Returned lazily so that importing this module doesn't fail if langchain
    is not installed — the error surfaces only when make_llm_analysis_node()
    is actually called.
    """
    from langchain_core.tools import tool

    # ------------------------------------------------------------------ #
    # Tool 1 – IP reputation lookup                                        #
    # ------------------------------------------------------------------ #

    @tool
    def lookup_ip_reputation(ip_address: str) -> str:
        """
        Check whether an IP address appears in known threat intelligence feeds.

        Returns a JSON string with keys:
          - ip           : the queried address
          - is_known_bad : true if on a blocklist
          - categories   : list of threat categories (e.g. ["scanner", "botnet"])
          - confidence   : 0.0-1.0 confidence in the classification
          - source       : which feed matched (or "none")

        Use this tool whenever you see a suspicious source IP in the worst
        window features or event list.
        """
        # --- Production swap: replace the body below with a real API call ---
        # e.g.  requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}",
        #                    headers={"Key": ABUSEIPDB_KEY}).json()
        # ---------------------------------------------------------------------
        KNOWN_BAD = {
            "10.0.": {"categories": ["botnet", "scanner"], "confidence": 0.92},
            "10.1.": {"categories": ["credential_stuffing"], "confidence": 0.87},
            "10.2.": {"categories": ["coordinated_scan"], "confidence": 0.95},
        }
        for prefix, meta in KNOWN_BAD.items():
            if ip_address.startswith(prefix):
                return json.dumps({
                    "ip": ip_address,
                    "is_known_bad": True,
                    "categories": meta["categories"],
                    "confidence": meta["confidence"],
                    "source": "mock_threat_feed_v1",
                })
        return json.dumps({
            "ip": ip_address,
            "is_known_bad": False,
            "categories": [],
            "confidence": 1.0,
            "source": "none",
        })

    # ------------------------------------------------------------------ #
    # Tool 2 – Threat intel pattern query                                  #
    # ------------------------------------------------------------------ #

    @tool
    def query_threat_intel(attack_pattern: str) -> str:
        """
        Search a threat-intelligence knowledge base for a given attack pattern
        or technique name.

        Parameters
        ----------
        attack_pattern : str
            A short description of the suspected attack pattern.  Examples:
              "synchronised HTTP flood"
              "IP hopping credential stuffing"
              "coordinated endpoint scan"

        Returns a JSON string with keys:
          - pattern_matched : the closest known pattern
          - mitre_technique : MITRE ATT&CK technique ID (if applicable)
          - description     : short description of the technique
          - typical_ips_per_window : typical number of source IPs seen per window
          - recommended_response   : suggested containment actions
        """
        # --- Production swap: call your SIEM / CTI platform API here ---
        KB = [
            {
                "keywords": ["sync", "flood", "burst", "simultaneous"],
                "pattern_matched": "synchronised_http_flood",
                "mitre_technique": "T1498.001",
                "description": (
                    "Multiple hosts send requests to the same endpoint within a "
                    "very short time window, causing request_synchrony to drop "
                    "to near-zero."
                ),
                "typical_ips_per_window": "20-100",
                "recommended_response": [
                    "Rate-limit /target endpoint",
                    "Block source /24 CIDRs",
                    "Enable CAPTCHA challenge",
                ],
            },
            {
                "keywords": ["hop", "credential", "stuffing", "ip churn", "multi-ip"],
                "pattern_matched": "ip_hopping_credential_stuffing",
                "mitre_technique": "T1110.004",
                "description": (
                    "A single user_id authenticates from many distinct IPs in a "
                    "short window, evading per-IP rate limits.  max_user_ip_count "
                    "spikes well above the baseline constant of 1."
                ),
                "typical_ips_per_window": "5-30",
                "recommended_response": [
                    "Force re-authentication for affected user",
                    "Enable MFA",
                    "Alert account owner",
                ],
            },
            {
                "keywords": ["scan", "coordinated", "discovery", "recon", "spread"],
                "pattern_matched": "coordinated_endpoint_scan",
                "mitre_technique": "T1595.001",
                "description": (
                    "Many IPs simultaneously probe the same endpoint.  Both "
                    "shared_endpoint_ips and request_synchrony deviate from baseline."
                ),
                "typical_ips_per_window": "30-200",
                "recommended_response": [
                    "Block /admin externally",
                    "Add geo-fencing if attackers are foreign",
                    "File incident report",
                ],
            },
        ]
        pattern_lower = attack_pattern.lower()
        for entry in KB:
            if any(kw in pattern_lower for kw in entry["keywords"]):
                return json.dumps(entry)

        return json.dumps({
            "pattern_matched": "unknown",
            "mitre_technique": None,
            "description": "No matching pattern found in threat-intel KB.",
            "typical_ips_per_window": "N/A",
            "recommended_response": ["Escalate to Tier-2 analyst"],
        })

    # ------------------------------------------------------------------ #
    # Tool 3 – Feature explainer                                           #
    # ------------------------------------------------------------------ #

    @tool
    def explain_window_features(features_json: str) -> str:
        """
        Translate a raw feature vector (JSON dict) from a scored window into
        plain-English analyst notes.

        Parameters
        ----------
        features_json : str
            JSON string mapping feature names to their float values.
            Example:
              '{"ip_fan_out": 1.2, "user_ip_count": 1.0, "max_user_ip_count": 10.0,
                "graph_density": 0.8, "shared_endpoint_ips": 40.0,
                "request_synchrony": 5.8, "ip_endpoint_spread": 1.0, "edge_count": 92.0}'

        Returns a JSON string with key "explanation": a bulleted plain-English
        description of what each anomalous feature implies.
        """
        try:
            features = json.loads(features_json)
        except json.JSONDecodeError:
            return json.dumps({"explanation": "Could not parse features JSON."})

        notes = []

        ip_fan_out = features.get("ip_fan_out", 0)
        if ip_fan_out > 5:
            notes.append(
                f"ip_fan_out={ip_fan_out:.1f}: Each source IP served many distinct "
                "users — unusual; may indicate shared proxy or botnet C2."
            )

        max_uip = features.get("max_user_ip_count", 0)
        if max_uip > 3:
            notes.append(
                f"max_user_ip_count={max_uip:.0f}: A single user_id appeared from "
                f"{max_uip:.0f} IPs in this window — strong IP-hopping signal."
            )

        shared_ep = features.get("shared_endpoint_ips", 0)
        if shared_ep > 15:
            notes.append(
                f"shared_endpoint_ips={shared_ep:.0f}: {shared_ep:.0f} distinct IPs "
                "all reached the same endpoint — coordinated scan or DDoS."
            )

        sync = features.get("request_synchrony", 1e6)
        if sync < 20:
            notes.append(
                f"request_synchrony={sync:.2f}s: Requests were nearly simultaneous "
                "(baseline ≥ 32 s) — automated / scripted traffic."
            )

        density = features.get("graph_density", 0)
        if density > 1.5:
            notes.append(
                f"graph_density={density:.2f}: The IP→user→endpoint graph is unusually "
                "dense, suggesting many cross-connections between actors."
            )

        if not notes:
            notes.append("All feature values appear within normal baseline ranges.")

        return json.dumps({"explanation": "\n".join(f"• {n}" for n in notes)})

    return [lookup_ip_reputation, query_threat_intel, explain_window_features]


# ---------------------------------------------------------------------------
# LangChain agent builder
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a senior cybersecurity analyst specialising in
network anomaly detection.  You have been given a structured anomaly report
produced by an IsolationForest-based spatio-temporal pipeline.  Your job is to:

1. Interpret the numeric risk score and worst-window features.
2. Use your tools to gather additional evidence (IP reputation, threat intel,
   feature explanations).
3. Decide whether this is a confirmed threat, a likely false positive, or
   uncertain.
4. Recommend concrete containment or investigation actions.

IMPORTANT RULES:
- Always call explain_window_features on the worst-window feature dict first.
- If risk_score >= 0.70, always call lookup_ip_reputation on at least one IP
  from the worst window event list.
- If you identify a likely attack pattern, call query_threat_intel with a
  short description of that pattern.
- After gathering evidence, output ONLY a valid JSON object (no markdown, no
  extra text) with exactly these keys:
    verdict              : "confirmed_threat" | "likely_fp" | "uncertain"
    confidence           : float 0.0-1.0
    attack_type          : string or null
    affected_ips         : list[str]
    affected_endpoints   : list[str]
    reasoning            : string (multi-sentence chain-of-thought)
    recommended_actions  : list[str]
"""


def _build_agent(config: LLMConfig):
    """
    Construct and return a LangGraph ReAct agent backed by Gemini.

    Uses langgraph.prebuilt.create_react_agent — compatible with
    langchain>=1.0, langchain-google-genai>=2.0, langgraph>=0.2.
    AgentExecutor was removed in langchain v1.x; LangGraph is the
    supported replacement.
    """
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langgraph.prebuilt import create_react_agent
    from langchain_core.messages import SystemMessage

    api_key = config.api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "Gemini API key not found.  Pass it via LLMConfig(api_key=...) "
            "or set the GEMINI_API_KEY environment variable."
        )

    llm = ChatGoogleGenerativeAI(
        model=config.model_name,
        google_api_key=api_key,
        temperature=config.temperature,
    )

    tools = _build_tools()

    # create_react_agent accepts a prompt string or SystemMessage for the
    # system prompt; the human turn is passed at invoke() time.
    graph = create_react_agent(
        model=llm,
        tools=tools,
        prompt=_SYSTEM_PROMPT,
    )
    return graph


# ---------------------------------------------------------------------------
# Node factory
# ---------------------------------------------------------------------------

def make_llm_analysis_node(config: Optional[LLMConfig] = None) -> Callable[[AgentState], AgentState]:
    """
    Returns a node function compatible with AgentGraph.add_node().

    The node:
      1. Skips gracefully (no LLM call) when risk_score < config.high_risk_threshold.
      2. Builds a natural-language prompt summarising the AgentResult.
      3. Runs the Gemini ReAct agent with the three tools.
      4. Parses the JSON verdict and writes an LLMAnalysis into
         state.metadata["llm_analysis"].

    Parameters
    ----------
    config : LLMConfig, optional
        Gemini model settings.  Reads GEMINI_API_KEY from env if api_key omitted.
    """
    config = config or LLMConfig()
    _agent_executor = None   # lazy init — built on first call

    def llm_analysis(state: AgentState) -> AgentState:
        nonlocal _agent_executor

        # ── 1. Find the spatio-temporal result ───────────────────────────
        st_result = next(
            (r for r in state.results if r.agent == "spatio_temporal"), None
        )
        if st_result is None:
            logger.info("llm_analysis: no spatio_temporal result found; skipping.")
            return state

        # ── 2. Skip if below threshold ────────────────────────────────────
        if st_result.risk_score < config.high_risk_threshold:
            logger.info(
                "llm_analysis: risk_score=%.3f < threshold=%.2f; skipping LLM.",
                st_result.risk_score, config.high_risk_threshold,
            )
            state.metadata["llm_analysis"] = {
                "verdict": "likely_fp",
                "confidence": 1.0 - st_result.risk_score,
                "attack_type": None,
                "affected_ips": [],
                "affected_endpoints": [],
                "reasoning": (
                    f"Risk score {st_result.risk_score:.3f} is below the "
                    f"LLM analysis threshold {config.high_risk_threshold}. "
                    "Classified as low-risk without LLM reasoning."
                ),
                "recommended_actions": ["No action required."],
                "tool_calls_made": [],
                "produced_at": datetime.utcnow().isoformat(),
            }
            return state

        # ── 3. Build human-readable prompt from the AgentResult ──────────
        details = st_result.details
        worst_features = details.get("worst_window_features", {})
        per_window = details.get("per_window_details", [])

        # Collect unique source IPs from the worst window events for the prompt
        worst_idx = details.get("worst_window_index", 0)
        worst_win_detail = per_window[worst_idx] if worst_idx < len(per_window) else {}

        # Pull a sample of IPs from state.events around the worst window time
        worst_start_str = details.get("worst_window_start", "")
        sample_ips: List[str] = []
        sample_endpoints: List[str] = []
        if worst_start_str:
            try:
                worst_start = datetime.fromisoformat(worst_start_str)
                from datetime import timedelta
                win_end = worst_start + timedelta(minutes=6)
                for ev in state.events:
                    if worst_start <= ev.timestamp <= win_end:
                        if ev.source_ip not in sample_ips:
                            sample_ips.append(ev.source_ip)
                        if ev.request_path not in sample_endpoints:
                            sample_endpoints.append(ev.request_path)
                        if len(sample_ips) >= 5:  # cap for prompt length
                            break
            except ValueError:
                pass

        # Pre-compute values that would cause f-string parse errors if inlined
        report_time = datetime.utcnow().isoformat()
        win_risk_raw = worst_win_detail.get('risk_score', None)
        win_risk_str = f"{win_risk_raw:.4f}" if isinstance(win_risk_raw, float) else "?"
        worst_start_label = details.get('worst_window_start', '?')
        worst_end_label   = details.get('worst_window_end',   '?')
        flags_str   = ', '.join(st_result.flags) if st_result.flags else 'none'
        ips_str     = str(sample_ips)     if sample_ips     else "['(none extracted)']"
        eps_str     = str(sample_endpoints) if sample_endpoints else "['(none extracted)']"
        features_str = json.dumps(worst_features, indent=2)

        prompt_text = (
            f"ANOMALY REPORT - {report_time}\n\n"
            f"Risk score        : {st_result.risk_score:.4f}   (threshold for alert: {config.high_risk_threshold})\n"
            f"Severity (auto)   : {st_result.severity.value}\n"
            f"Flags             : {flags_str}\n"
            f"Windows scored    : {details.get('num_windows_scored', '?')}\n"
            f"Worst window      : {worst_start_label} to {worst_end_label}\n"
            f"  Event count     : {worst_win_detail.get('event_count', '?')}\n"
            f"  Window risk     : {win_risk_str}\n\n"
            "Worst-window feature vector (raw):\n"
            f"{features_str}\n\n"
            f"Sample source IPs in worst window : {ips_str}\n"
            f"Sample endpoints hit              : {eps_str}\n\n"
            "Task: Investigate this anomaly using your tools, then output your verdict as JSON."
        )

        # ── 4. Lazy-build the LangChain agent ────────────────────────────
        if _agent_executor is None:
            try:
                _agent_executor = _build_agent(config)
            except Exception as exc:
                msg = f"llm_analysis: failed to build Gemini agent: {exc}"
                logger.error(msg, exc_info=True)
                state.errors.append(msg)
                return state

        # ── 5. Run the LangGraph ReAct agent ─────────────────────────────
        try:
            from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

            # LangGraph create_react_agent takes {"messages": [...]}
            response = _agent_executor.invoke(
                {"messages": [HumanMessage(content=prompt_text)]},
                config={"recursion_limit": config.max_iterations * 2 + 2},
            )

            # response["messages"] is a list of BaseMessage objects.
            # The final AIMessage with no tool_calls is the agent's answer.
            messages = response.get("messages", [])

            def _extract_text(content) -> str:
                """
                Normalise Gemini's msg.content into a plain string.

                Gemini sometimes returns a list of content blocks:
                  [{'type': 'text', 'text': '...actual text...',
                    'extras': {'signature': '...'}}]
                Other times it returns a plain string.
                We always want the concatenated text.
                """
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    parts = []
                    for block in content:
                        if isinstance(block, dict):
                            # Gemini block format: {'type': 'text', 'text': '...'}
                            parts.append(block.get("text", ""))
                        elif isinstance(block, str):
                            parts.append(block)
                    return "".join(parts)
                return str(content)

            raw_output = ""
            for msg in reversed(messages):
                if isinstance(msg, AIMessage):
                    text = _extract_text(msg.content)
                    # Prefer messages that have actual text content
                    if text and not getattr(msg, "tool_calls", None):
                        raw_output = text
                        break
                    elif text:
                        raw_output = text
                        break

            # Collect names of tools called.
            # LangGraph ToolMessage stores the tool name in .name;
            # AIMessage stores pending calls in .tool_calls (list of dicts).
            tool_name_set = set()
            for m in messages:
                if isinstance(m, ToolMessage) and getattr(m, "name", None):
                    tool_name_set.add(m.name)
                elif isinstance(m, AIMessage):
                    for tc in getattr(m, "tool_calls", []) or []:
                        if isinstance(tc, dict) and tc.get("name"):
                            tool_name_set.add(tc["name"])
            tools_used = list(tool_name_set)

        except Exception as exc:
            msg = f"llm_analysis: Gemini agent invocation failed: {exc}"
            logger.error(msg, exc_info=True)
            state.errors.append(msg)
            return state

        # ── 6. Parse JSON verdict ─────────────────────────────────────────
        try:
            # Gemini often wraps its answer in ```json ... ``` fences.
            # Strip all leading/trailing fences robustly.
            import re as _re
            clean = raw_output.strip()
            # Remove ```json ... ``` or ``` ... ``` wrappers
            fence_match = _re.search(r"```(?:json)?\s*([\s\S]*?)```", clean)
            if fence_match:
                clean = fence_match.group(1).strip()
            verdict_dict = json.loads(clean)
        except (json.JSONDecodeError, IndexError) as exc:
            logger.warning(
                "llm_analysis: could not parse LLM JSON output (%s). "
                "Storing raw text instead.", exc
            )
            verdict_dict = {
                "verdict": "uncertain",
                "confidence": 0.5,
                "attack_type": None,
                "affected_ips": sample_ips,
                "affected_endpoints": sample_endpoints,
                "reasoning": raw_output,
                "recommended_actions": ["Manual review required — LLM output was non-JSON."],
            }

        verdict_dict["tool_calls_made"] = tools_used
        verdict_dict["produced_at"] = datetime.utcnow().isoformat()

        state.metadata["llm_analysis"] = verdict_dict
        logger.info(
            "llm_analysis complete: verdict=%s  confidence=%.2f  tools_used=%s",
            verdict_dict.get("verdict"),
            verdict_dict.get("confidence", 0),
            tools_used,
        )
        return state

    return llm_analysis


# ---------------------------------------------------------------------------
# Drop-in graph builder (replaces build_spatio_temporal_graph for agentic use)
# ---------------------------------------------------------------------------

def build_agentic_spatio_temporal_graph(
    llm_config: Optional[LLMConfig] = None,
    spatio_config=None,
    registry=None,
):
    """
    Build the full agentic pipeline with the Gemini reasoning node wired in:

        [validate] → (enough events) → [score] → [severity] → [llm_analysis] → END
                   → (too few events) → [skip] → END

    Parameters
    ----------
    llm_config     : LLMConfig controlling the Gemini model.
    spatio_config  : SpatioTemporalConfig (uses defaults if None).
    registry       : ModelRegistry (uses singleton if None).

    Returns
    -------
    AgentGraph ready to call .run(AgentState(...))
    """
    # Import here to avoid circular imports (this file is a sibling module)
    from spatio_temporal_agent import (
        SpatioTemporalConfig,
        build_spatio_temporal_graph,
    )
    from agent_framework import END

    # Build the base graph (validate → score → severity → END  /  skip → END)
    graph = build_spatio_temporal_graph(spatio_config, registry)

    # Rewire: severity now goes to llm_analysis, not END
    # AgentGraph exposes _edges so we can patch the wiring
    graph._edges["severity"] = "llm_analysis"

    graph.add_node(
        "llm_analysis",
        make_llm_analysis_node(llm_config),
        description="Gemini ReAct agent: gathers tool evidence and produces verdict",
    )
    graph.add_edge("llm_analysis", END)

    return graph
