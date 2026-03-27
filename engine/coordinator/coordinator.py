from dataclasses import dataclass, field
from typing import List, Dict, Optional
from schemas.agent_result import AgentResult


# Risk classification thresholds
THRESHOLD_SAFE = 0.3
THRESHOLD_SUSPICIOUS = 0.6
THRESHOLD_ATTACK = 0.8


@dataclass
class CoordinatorResult:
    """Final verdict produced by the coordinator for one user/session."""
    user_id: str
    final_score: float                          # Weighted combination of all agents
    verdict: str                                # "normal", "suspicious", "attack"
    confidence: float                           # How sure we are (0.0–1.0)
    contributing_agents: List[str]              # Which agents flagged this
    all_flags: List[str]                        # Combined flags from all agents
    explanation: str                            # Human-readable summary
    agent_scores: Dict[str, float] = field(default_factory=dict)  # Per-agent breakdown


class Coordinator:
    """
    Combines results from all agents into a single final verdict.

    Weights reflect how much we trust each agent:
    - Behavioral: 0.5  (most reliable, well validated)
    - Semantic:   0.35 (good but depends on spec coverage)
    - Spatiotemporal: 0.15 (scaffold only for now)
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or {
            "behavioral": 0.5,
            "semantic": 0.35,
            "spatiotemporal": 0.15,
        }

    def combine(
        self,
        behavioral_results: List[AgentResult],
        semantic_results: Dict[str, Dict],
        spatiotemporal_results: Optional[List[AgentResult]] = None,
    ) -> List[CoordinatorResult]:
        """
        Combines all agent outputs into final verdicts.

        Args:
            behavioral_results:      List of AgentResult from behavioral agent
            semantic_results:        Dict of user_id → report from semantic agent
            spatiotemporal_results:  List of AgentResult (optional, scaffold)

        Returns:
            List of CoordinatorResult — one per user/session
        """

        # Index behavioral results by user_id
        # (behavioral works on sessions, semantic on users — merge by user_id)
        behavioral_by_user: Dict[str, List[AgentResult]] = {}
        for result in behavioral_results:
            uid = result.metadata.get("user_id", result.explanation.split("Session ")[1].rsplit("_session_", 1)[0])
            behavioral_by_user.setdefault(uid, []).append(result)

        # Index spatiotemporal by user_id (if provided)
        spatio_by_user: Dict[str, AgentResult] = {}
        if spatiotemporal_results:
            for result in spatiotemporal_results:
                uid = result.metadata.get("user_id", "unknown")
                spatio_by_user[uid] = result

        # Get all unique user IDs across all agents
        all_users = set(behavioral_by_user.keys()) | set(semantic_results.keys())

        final_results = []
        for user_id in all_users:
            agent_scores = {}
            all_flags = []
            contributing_agents = []

            # ---- Behavioral score ----
            # If user has multiple sessions, take the highest risk score
            b_results = behavioral_by_user.get(user_id, [])
            if b_results:
                b_score = max(r.risk_score for r in b_results)
                b_flags = []
                for r in b_results:
                    b_flags.extend(r.flags)
                agent_scores["behavioral"] = b_score
                all_flags.extend(b_flags)
                if b_score > THRESHOLD_SAFE:
                    contributing_agents.append("behavioral")

            # ---- Semantic score ----
            s_report = semantic_results.get(user_id, {})
            if s_report:
                s_score = s_report.get("semantic_risk_score", 0.0)
                s_confidence = s_report.get("confidence", 1.0)
                # Dampen semantic score by its own confidence
                # Low spec coverage → lower effective weight
                s_effective = s_score * s_confidence
                agent_scores["semantic"] = s_effective
                breakdown = s_report.get("rule_breakdown", {})
                for rule, score in breakdown.items():
                    if score > 0.3:
                        all_flags.append(f"semantic_{rule}")
                if s_effective > THRESHOLD_SAFE:
                    contributing_agents.append("semantic")

            # ---- Spatiotemporal score ----
            st_result = spatio_by_user.get(user_id)
            if st_result:
                agent_scores["spatiotemporal"] = st_result.risk_score
                all_flags.extend(st_result.flags)
                if st_result.risk_score > THRESHOLD_SAFE:
                    contributing_agents.append("spatiotemporal")

            # ---- Weighted combination ----
            total_weight = 0.0
            weighted_sum = 0.0
            for agent_name, score in agent_scores.items():
                w = self.weights.get(agent_name, 0.0)
                weighted_sum += w * score
                total_weight += w

            final_score = weighted_sum / total_weight if total_weight > 0 else 0.0
            final_score = round(min(1.0, max(0.0, final_score)), 3)

            # ---- Confidence ----
            # More agents reporting = higher confidence
            confidence = round(len(agent_scores) / len(self.weights), 2)

            # ---- Verdict ----
            if final_score >= THRESHOLD_ATTACK:
                verdict = "attack"
            elif final_score >= THRESHOLD_SUSPICIOUS:
                verdict = "suspicious"
            else:
                verdict = "normal"

            # ---- Explanation ----
            unique_flags = list(dict.fromkeys(all_flags))  # deduplicate, preserve order
            if contributing_agents:
                explanation = (
                    f"User {user_id} flagged by: {', '.join(contributing_agents)}. "
                    f"Signals: {', '.join(unique_flags) or 'none'}. "
                    f"Final score: {final_score}"
                )
            else:
                explanation = f"User {user_id}: no anomalies detected. Final score: {final_score}"

            final_results.append(CoordinatorResult(
                user_id=user_id,
                final_score=final_score,
                verdict=verdict,
                confidence=confidence,
                contributing_agents=contributing_agents,
                all_flags=unique_flags,
                explanation=explanation,
                agent_scores=agent_scores,
            ))

        # Sort by final score descending (worst offenders first)
        final_results.sort(key=lambda r: r.final_score, reverse=True)
        return final_results