import json
from datetime import timedelta
from engine.normalization.normalizer import normalize
from engine.pipeline.sessionizer import sessionize
from engine.agents.behavioral import analyze as behavioral_analyze
from engine.agents.semantic import SemanticGuardAgent
from engine.coordinator.coordinator import Coordinator


def dummy_owner_resolver(obj_id, tenant):
    """Placeholder: in production this queries your DB."""
    return None


def main():
    # ── 1. Load ──────────────────────────────────────────────────
    print("Loading raw logs...")
    with open("datasets/mock_logs.json", "r") as f:
        raw_logs = json.load(f)
    print(f"  Loaded {len(raw_logs)} raw log entries")

    # ── 2. Normalize ─────────────────────────────────────────────
    print("\nNormalizing...")
    events = normalize(raw_logs)
    print(f"  Normalized into {len(events)} canonical events")

    # ── 3. Sessionize ─────────────────────────────────────────────
    print("\nSessionizing...")
    sessions = sessionize(events)
    print(f"  Created {len(sessions)} sessions")

    # ── 4. Behavioral Agent ───────────────────────────────────────
    print("\n" + "=" * 60)
    print("BEHAVIORAL AGENT")
    print("=" * 60)
    behavioral_results = behavioral_analyze(sessions)
    for r in behavioral_results:
        print(f"  {r.explanation}")
        print(f"    risk={r.risk_score}  flags={r.flags}")

    # ── 5. Semantic Agent ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SEMANTIC AGENT")
    print("=" * 60)
    semantic_config = {
        "admin_users": [],
        "weights": {
            "ownership_violation": 0.4,
            "enumeration": 0.2,
            "volume_mismatch": 0.2,
            "parameter_tampering": 0.1,
            "probing": 0.1,
        },
        "volume_low_threshold": 5,
        "volume_medium_threshold": 10,
        "volume_high_threshold": 20,
    }
    semantic_agent = SemanticGuardAgent("spec.yaml", dummy_owner_resolver, semantic_config)

    all_times = [e.timestamp for e in events]
    window_start = min(all_times) - timedelta(minutes=1)
    window_end = max(all_times) + timedelta(minutes=1)
    semantic_results = semantic_agent.process_window(events, window_start, window_end)

    for user_id, report in semantic_results.items():
        print(f"  {user_id}: risk={report['semantic_risk_score']:.2f}  confidence={report['confidence']:.2f}")
        print(f"    breakdown={report['rule_breakdown']}")

    # ── 6. Coordinator ────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("COORDINATOR — FINAL VERDICTS")
    print("=" * 60)
    coordinator = Coordinator()
    final_results = coordinator.combine(behavioral_results, semantic_results)

    for result in final_results:
        verdict_symbol = {"normal": "✅", "suspicious": "⚠️", "attack": "🚨"}.get(result.verdict, "?")
        print(f"\n  {verdict_symbol} {result.user_id}")
        print(f"    Verdict:    {result.verdict.upper()}")
        print(f"    Score:      {result.final_score}")
        print(f"    Confidence: {result.confidence}")
        print(f"    Agents:     {result.agent_scores}")
        print(f"    Flags:      {result.all_flags}")

    # ── 7. Summary ────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    attacks = [r for r in final_results if r.verdict == "attack"]
    suspicious = [r for r in final_results if r.verdict == "suspicious"]
    normal = [r for r in final_results if r.verdict == "normal"]
    print(f"  🚨 Attacks:    {len(attacks)}")
    print(f"  ⚠️  Suspicious: {len(suspicious)}")
    print(f"  ✅ Normal:     {len(normal)}")


if __name__ == "__main__":
    main()