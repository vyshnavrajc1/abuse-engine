
"""
evaluate_agent.py

Loads the synthetic dataset, runs the SemanticGuardAgent,
and compares its output with the ground truth.
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict
from engine.agents.semantic import SemanticGuardAgent
from schemas.event_schema import CanonicalEvent
from typing import Optional
# Import your agent and CanonicalEvent from your module

# ------------------------------------------------------------
# 1. Load the generated data
# ------------------------------------------------------------
with open("events.json", "r") as f:
    events_data = json.load(f)

with open("ground_truth.json", "r") as f:
    ground_truth = json.load(f)

# Convert events to CanonicalEvent objects
# The generator stored timestamps as ISO strings, so we need to parse them
events = []
for e in events_data:
    e["timestamp"] = datetime.fromisoformat(e["timestamp"])
    events.append(CanonicalEvent(**e))

# ------------------------------------------------------------
# 2. Define the owner resolver
# ------------------------------------------------------------
# The generator assigned each object ID to a user in a round‑robin fashion.
# We need to reconstruct that mapping from the events themselves,
# or we could load it from a file if the generator saved it.
# For simplicity, we derive it from all events that have a known object owner.
# We'll assume that any successful (200) access to a single_object endpoint
# gives the correct owner.
owner_map = {}  # obj_id -> user_id
for e in events:
    if e.method == "GET" and e.status_code == 200 and e.path_params:
        # For endpoints like /api/users/{id}, the path param is the object id
        # We assume the endpoint is single_object and the owner field is "id"
        obj_id = e.path_params.get("id")
        if obj_id:
            owner_map[obj_id] = e.user_id

def owner_resolver(obj_id: str, tenant_id: str) -> Optional[str]:
    """Return the owner of the object, or None if unknown."""
    return owner_map.get(obj_id)

# ------------------------------------------------------------
# 3. Configure the agent
# ------------------------------------------------------------
config = {
    "admin_users": [],  # no admin users in synthetic data
    "weights": {
        "ownership_violation": 0.4,
        "enumeration": 0.2,
        "volume_mismatch": 0.2,
        "parameter_tampering": 0.1,
        "probing": 0.1
    },
    "volume_low_threshold": 5,
    "volume_medium_threshold": 10,
    "volume_high_threshold": 20,
    # optional: add any other configuration keys your agent expects
}

# ------------------------------------------------------------
# 4. Instantiate the agent and process the window
# ------------------------------------------------------------
agent = SemanticGuardAgent("spec2.yaml", owner_resolver, config)

# The entire dataset is already within a 60‑minute window (by construction)
# We'll use the min and max timestamps from the events.
timestamps = [e.timestamp for e in events]
window_start = min(timestamps)
window_end = max(timestamps) + timedelta(seconds=1)  # add a tiny margin

print(f"Processing window from {window_start} to {window_end}")
results = agent.process_window(events, window_start, window_end)

# ------------------------------------------------------------
# 5. Compare with ground truth
# ------------------------------------------------------------
# The ground truth gives expected risk category ("low", "medium", "high")
# We need to map the agent's continuous score to a category.
# We'll use thresholds: 0.0-0.33 -> low, 0.33-0.66 -> medium, 0.66-1.0 -> high.
def score_to_category(score):
    if score < 0.33:
        return "low"
    elif score < 0.66:
        return "medium"
    else:
        return "high"

correct = 0
total = 0
confusion = defaultdict(lambda: defaultdict(int))

for user_id, expected in ground_truth.items():
    if user_id in results:
        agent_score = results[user_id]["semantic_risk_score"]
        agent_category = score_to_category(agent_score)
        expected_category = expected["risk"]
        total += 1
        if agent_category == expected_category:
            correct += 1
        confusion[expected_category][agent_category] += 1
    else:
        # User had no events? In our dataset all users have events.
        print(f"Warning: user {user_id} not in results")

accuracy = correct / total if total > 0 else 0.0
print(f"\nAccuracy (category match): {accuracy:.2%} ({correct}/{total})")

print("\nConfusion Matrix (expected vs predicted):")
print("          Predicted")
print("          low  medium  high")
for exp in ["low", "medium", "high"]:
    row = confusion[exp]
    print(f"{exp:8} {row['low']:3}   {row['medium']:3}   {row['high']:3}")

# Optional: print detailed results for each user
print("\nDetailed per‑user results:")
for user_id, expected in ground_truth.items():
    if user_id in results:
        r = results[user_id]
        print(f"{user_id:10} expected: {expected['risk']:6} ({expected['attack_type'] or 'benign':10}) "
              f"score: {r['semantic_risk_score']:.3f}  category: {score_to_category(r['semantic_risk_score'])}")
    else:
        print(f"{user_id:10} no events in results")