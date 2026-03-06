import json
from engine.normalization.normalizer import normalize
from engine.pipeline.sessionizer import sessionize
from engine.agents.behavioral import analyze as behavioral_analyze


def main():
    # Step 1: Load raw logs
    print("Loading raw logs...")
    with open("datasets/mock_logs.json", "r") as f:
        raw_logs = json.load(f)
    print(f"  Loaded {len(raw_logs)} raw log entries")

    # Step 2: Normalize into CanonicalEvents
    print("\nNormalizing...")
    events = normalize(raw_logs)
    print(f"  Normalized into {len(events)} canonical events")

    # Step 3: Group into sessions
    print("\nSessionizing...")
    sessions = sessionize(events)
    print(f"  Created {len(sessions)} sessions")

    # Step 4: Run behavioral agent
    print("\n" + "=" * 60)
    print("BEHAVIORAL AGENT RESULTS")
    print("=" * 60)
    results = behavioral_analyze(sessions)

    for result in results:
        print(f"\n  Session:   {result.explanation}")
        print(f"  Risk:      {result.risk_score}")
        print(f"  Flags:     {result.flags}")
        print(f"  Requests:  {result.metadata.get('request_count', 0)}")
        print(f"  Avg Gap:   {result.metadata.get('avg_interval', 0):.2f}s")
        print(f"  Seq Score: {result.metadata.get('sequential_id_score', 0):.2f}")

    # Step 5: Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    flagged = [r for r in results if r.risk_score > 0.3]
    safe = [r for r in results if r.risk_score <= 0.3]
    print(f"  Total sessions:   {len(results)}")
    print(f"  Flagged (risky):  {len(flagged)}")
    print(f"  Safe:             {len(safe)}")

    # TODO: Run semantic agent (Developer B)
    # semantic_results = semantic_analyze(events)

    # TODO: Coordinator aggregation (later)
    # final = coordinate(behavioral_results, semantic_results)


if __name__ == "__main__":
    main()