"""
APISentry Tool Registry

Agents call these functions during their ④ INVESTIGATE step.
Each tool is a plain function; the registry maps names → callables so
agents can invoke tools by name (agentic dispatch pattern).

Tool categories:
  - Data    : query_historical_baseline, get_session_history, query_ip_reputation
  - Logic   : run_statistical_test, compute_entropy, detect_periodicity, calculate_similarity
  - Social  : query_agent (stub), post_to_evidence_board, read_evidence_board
"""

from __future__ import annotations
import math
import statistics
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
from scipy import stats as scipy_stats

from engine.memory.shared_memory import SharedMemory
from schemas.models import EvidenceEntry, LogRecord


# ---------------------------------------------------------------------------
# Tool registry container
# ---------------------------------------------------------------------------

class ToolRegistry:
    """Holds all callable tools. Agents receive a registry instance."""

    def __init__(self, memory: SharedMemory):
        self._memory = memory
        self._tools: Dict[str, Callable] = {}
        self._register_all()

    def call(self, name: str, **kwargs) -> Any:
        if name not in self._tools:
            raise ValueError(f"Unknown tool: {name}")
        return self._tools[name](**kwargs)

    def _register_all(self):
        m = self._memory

        # ── DATA TOOLS ──────────────────────────────────────────────────────

        def query_historical_baseline(endpoint: str) -> Optional[float]:
            """Return mean historical request rate for endpoint (req/min)."""
            return m.ltm.get_baseline_rate(endpoint)

        def get_session_history(ip: str, window_seconds: int = 60) -> List[LogRecord]:
            """Return all records for an IP within the rolling window."""
            return m.stm.get_window(f"ip:{ip}")

        def query_ip_reputation(ip: str) -> Dict[str, Any]:
            """
            Stub: in production calls GeoIP / threat-intel API.
            Returns a dict with datacenter/vpn/tor flags from board or defaults.
            """
            board_entry = m.board.get_value(f"geo:{ip}")
            if board_entry:
                return board_entry
            # Minimal synthetic heuristic for CICIDS (all internal IPs)
            return {"datacenter": False, "vpn": False, "tor": False, "asn": "UNKNOWN"}

        # ── LOGIC TOOLS ─────────────────────────────────────────────────────

        def run_statistical_test(
            values: List[float],
            test: str = "zscore",
            threshold: float = 3.0,
        ) -> Dict[str, Any]:
            """
            test='zscore'  : returns z-score of the last value vs the rest.
            test='kstest'  : two-sample KS test between values[:n//2] and values[n//2:].
            test='mannwhitney': Mann-Whitney U test.
            """
            if len(values) < 4:
                return {"significant": False, "reason": "insufficient_data"}

            if test == "zscore":
                if len(values) < 2:
                    return {"significant": False, "z": 0.0}
                mean = statistics.mean(values[:-1])
                std = statistics.stdev(values[:-1]) or 1e-9
                z = (values[-1] - mean) / std
                return {"significant": abs(z) > threshold, "z": round(z, 3)}

            elif test == "kstest":
                mid = len(values) // 2
                a, b = values[:mid], values[mid:]
                stat, p = scipy_stats.ks_2samp(a, b)
                return {"significant": p < 0.05, "stat": round(stat, 4), "p": round(p, 4)}

            elif test == "mannwhitney":
                mid = len(values) // 2
                a, b = values[:mid], values[mid:]
                stat, p = scipy_stats.mannwhitneyu(a, b, alternative="two-sided")
                return {"significant": p < 0.05, "p": round(p, 4)}

            return {"significant": False, "reason": "unknown_test"}

        def compute_entropy(values: List[Any]) -> float:
            """Shannon entropy of a discrete distribution."""
            from collections import Counter
            if not values:
                return 0.0
            counts = Counter(values)
            total = len(values)
            return round(
                -sum((c / total) * math.log2(c / total) for c in counts.values()), 4
            )

        def detect_periodicity(timestamps_ms: List[float]) -> Dict[str, Any]:
            """
            FFT-based periodicity detector on inter-arrival times.
            Returns dominant period (ms) and a bot-confidence score.
            """
            if len(timestamps_ms) < 8:
                return {"periodic": False, "reason": "insufficient_data"}
            iats = np.diff(sorted(timestamps_ms))
            if iats.std() < 1e-9:
                return {"periodic": True, "dominant_period_ms": float(iats[0]), "bot_confidence": 0.99}
            # Coefficient of variation: low CV → regular spacing → bot
            cv = iats.std() / (iats.mean() + 1e-9)
            # FFT peak
            fft_vals = np.abs(np.fft.rfft(iats))
            peak_freq_idx = int(np.argmax(fft_vals[1:])) + 1
            n = len(iats)
            period_ms = (n / peak_freq_idx) * iats.mean() if peak_freq_idx > 0 else 0.0
            bot_conf = max(0.0, min(1.0, 1.0 - cv))
            return {
                "periodic": bot_conf > 0.7,
                "cv": round(float(cv), 4),
                "dominant_period_ms": round(float(period_ms), 2),
                "bot_confidence": round(float(bot_conf), 3),
            }

        def calculate_similarity(seq_a: List[str], seq_b: List[str]) -> float:
            """Jaccard similarity between two endpoint sequences."""
            if not seq_a or not seq_b:
                return 0.0
            a, b = set(seq_a), set(seq_b)
            return round(len(a & b) / len(a | b), 4)

        # ── SOCIAL TOOLS ────────────────────────────────────────────────────

        def post_to_evidence_board(
            posted_by: str,
            key: str,
            value: Any,
            confidence: float = 0.5,
            tags: Optional[List[str]] = None,
        ) -> None:
            entry = EvidenceEntry(
                posted_by=posted_by,
                key=key,
                value=value,
                confidence=confidence,
                tags=tags or [],
            )
            m.board.post(entry)

        def read_evidence_board(
            key_filter: Optional[str] = None,
            min_confidence: float = 0.0,
        ) -> List[Dict[str, Any]]:
            entries = m.board.read(key_filter=key_filter, min_confidence=min_confidence)
            return [
                {"key": e.key, "value": e.value, "confidence": e.confidence, "posted_by": e.posted_by}
                for e in entries
            ]

        def query_agent(agent_name: str) -> List[Dict[str, Any]]:
            """Read all evidence posted by a specific agent."""
            entries = m.board.read(agent_filter=agent_name)
            return [
                {"key": e.key, "value": e.value, "confidence": e.confidence}
                for e in entries
            ]

        # ── REGISTER ────────────────────────────────────────────────────────
        self._tools = {
            "query_historical_baseline": query_historical_baseline,
            "get_session_history": get_session_history,
            "query_ip_reputation": query_ip_reputation,
            "run_statistical_test": run_statistical_test,
            "compute_entropy": compute_entropy,
            "detect_periodicity": detect_periodicity,
            "calculate_similarity": calculate_similarity,
            "post_to_evidence_board": post_to_evidence_board,
            "read_evidence_board": read_evidence_board,
            "query_agent": query_agent,
        }
