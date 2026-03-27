# Abuse Engine — Project Documentation

## 1. Project Overview

### What is this?
A **multi-agent AI system** that passively monitors API traffic logs and detects abuse patterns like bot scraping, brute force attacks, and endpoint enumeration — without modifying the API itself.

### Why does it matter?
Traditional API security (rate limiting, WAFs) uses static rules that are easy to bypass. This system uses **behavioral analysis + machine learning** to detect abuse that mimics normal traffic.

### How does it work?
```
Raw API Logs → Normalize → Sessionize → Agents Analyze → Coordinator Decides → Verdict
```

Multiple specialized agents each analyze the traffic from a different angle. A coordinator combines their opinions into a final verdict with an explainable output.

---

## 2. Architecture

### Pipeline Flow
```
                    ┌──────────────────────────────────────────┐
                    │           datasets/mock_logs.json         │
                    │         (raw API traffic logs)            │
                    └────────────────┬─────────────────────────┘
                                     ↓
                    ┌──────────────────────────────────────────┐
                    │   engine/normalization/normalizer.py      │
                    │   Raw JSON → CanonicalEvent objects       │
                    │   • Parses timestamps                    │
                    │   • Extracts path parameters             │
                    │   • Standardizes all fields              │
                    └────────────────┬─────────────────────────┘
                                     ↓
                    ┌──────────────────────────────────────────┐
                    │   engine/pipeline/sessionizer.py          │
                    │   Events → Sessions (grouped by user)    │
                    │   • Groups by user_id or IP              │
                    │   • 30 min gap = new session             │
                    └────────────────┬─────────────────────────┘
                                     ↓
              ┌──────────────────────┼──────────────────────┐
              ↓                      ↓                      ↓
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
│  Behavioral Agent   │ │  Semantic Agent      │ │  Spatiotemporal     │
│  (behavioral.py)    │ │  (semantic.py)       │ │  (spatiotemporal.py)│
│                     │ │                      │ │                     │
│  HOW users behave   │ │  WHAT users access   │ │  WHERE/WHEN users   │
│  • Timing patterns  │ │  • API contract      │ │  access from        │
│  • Request rates    │ │    violations        │ │  (not implemented)  │
│  • Sequential IDs   │ │  • Ownership checks  │ │                     │
│  • Error rates      │ │  • Enumeration       │ │                     │
│  • Isolation Forest │ │  • Parameter tamper   │ │                     │
│                     │ │                      │ │                     │
│  Output: AgentResult│ │  Output: Dict/user   │ │  Output: AgentResult│
└────────┬────────────┘ └────────┬─────────────┘ └────────┬────────────┘
         └──────────────────────┼──────────────────────────┘
                                ↓
                    ┌──────────────────────────────────────────┐
                    │   engine/coordinator/coordinator.py       │
                    │                                          │
                    │   Weighted combination of all agents:    │
                    │   behavioral=0.5, semantic=0.35,         │
                    │   spatiotemporal=0.15                    │
                    │                                          │
                    │   Output: CoordinatorResult              │
                    │   • final_score (0.0–1.0)               │
                    │   • verdict (normal/suspicious/attack)   │
                    │   • contributing_agents                  │
                    │   • all_flags (explainable reasons)      │
                    │   • confidence score                     │
                    └──────────────────────────────────────────┘
```

### Agent Responsibilities

| Agent | Question it answers | Technique | Status |
|---|---|---|---|
| **Behavioral** | Is this session behaving like a human or a machine? | Feature extraction + Isolation Forest (unsupervised ML) | ✅ Complete |
| **Semantic** | Is this user violating the API's intended contract? | OpenAPI spec comparison + rule engine | ✅ Complete (validation pending) |
| **Spatiotemporal** | Is this user accessing from unusual locations/times? | Geo/time anomaly detection | ⏳ Not started |

---

## 3. Shared Components (Both Developers)

### 3.1 Canonical Event Schema — schemas/event_schema.py

The **universal data format** that all agents consume. Every raw log gets converted into this before anything else touches it.

```python
@dataclass
class CanonicalEvent:
    timestamp: datetime             # When the request happened
    ip: str                          # IP address of the requester
    user_id: Optional[str]           # Who made the request
    tenant_id: Optional[str]         # Tenant context (multi-tenant systems)
    session_id: Optional[str]        # Session identifier
    endpoint: str                    # API path template, e.g. "/api/users/{id}"
    method: str                      # HTTP method: GET, POST, etc.
    status_code: int                 # HTTP response code
    user_agent: str                  # Client identifier
    response_time: Optional[float]   # Server processing time (ms)
    path_params: Dict                # Extracted from URL, e.g. {"id": "123"}
    query_params: Dict               # Query string parameters
    request_body: Optional[Dict]     # Parsed body (if applicable)
```

**Why this matters**: Both agents read the same format. If one developer changes the schema, both agents break — this forces coordination.

### 3.2 Agent Result Schema — schemas/agent_result.py

The **universal output format** that all agents produce. The coordinator consumes these.

```python
@dataclass
class AgentResult:
    agent: str                  # "behavioral", "semantic", "spatiotemporal"
    risk_score: float           # 0.0 (safe) to 1.0 (dangerous)
    flags: List[str]            # What was detected, e.g. ["high_request_rate"]
    explanation: str            # Human-readable summary
    metadata: Dict              # Extra data like feature values
```

### 3.3 Normalizer — engine/normalization/normalizer.py

Converts raw JSON log entries into `CanonicalEvent` objects.

Key responsibilities:
- Parses ISO timestamp strings → `datetime` objects
- Extracts path parameters from concrete URLs (e.g. `/api/users/123` → `path_params={"id": "123"}`, `endpoint="/api/users/{id}"`)
- Maps all raw fields to the canonical schema
- Handles missing fields with safe defaults

### 3.4 Sessionizer — engine/pipeline/sessionizer.py

Groups normalized events into sessions by user.

Logic:
1. Group all events by `user_id` (or IP if no user_id)
2. Sort each group by timestamp
3. Walk through events — if gap > 30 minutes, start a new session

Each `Session` object contains:
- `session_id`: unique identifier (e.g. `bot_user_1_session_0`)
- `events`: list of `CanonicalEvent` objects in that session
- `duration`: total seconds from first to last event
- `request_count`: number of events
- `endpoint_sequence`: ordered list of endpoints visited

### 3.5 Synthetic Data Generator — scripts/generate_synthetic_data.py

Generates fake but realistic API traffic for development and testing.

User types generated:
| Type | Count | Behavior |
|---|---|---|
| `normal_user_0` to `4` | 10 requests each | Random endpoints, 2–30s gaps, 200 status |
| `bot_user_1` | 200 requests | Sequential `/api/users/1,2,3...`, 0.1–0.5s gaps |
| `brute_user_1` | 50 requests | `/api/login` only, 0.2–1.0s gaps, mostly 401 status |
| `enum_user_1` | 100 requests | Sequential `/api/products/1,2,3...`, 0.3–1.5s gaps |

Output: `datasets/mock_logs.json` (400 entries, git-ignored)

---

## 4. Behavioral Agent (Developer A) — engine/agents/behavioral.py

### What it detects
Automated/machine-like behavior patterns in API sessions.

### Feature Extraction

8 features are extracted from each session:

| Feature | What it measures | Normal value | Suspicious value |
|---|---|---|---|
| `request_count` | Total requests in session | 5–20 | 50–200+ |
| `avg_interval` | Average seconds between requests | 2–30s | 0.1–0.5s |
| `std_interval` | How varied the timing is | High (humans vary) | Low (bots are consistent) |
| `endpoint_entropy` | Shannon entropy of endpoint diversity | High (varied browsing) | Low (same endpoint repeated) |
| `error_rate` | Percentage of 4xx/5xx responses | ~0% | >50% (brute force) |
| `burstiness` | Max requests in any 5-second window | 2–3 | 20+ |
| `unique_endpoints` | How many different endpoints visited | 3–10 | 1–2 |
| `sequential_id_score` | Detects `/users/1, /users/2, /users/3` patterns | ~0 | ~1.0 |

### Scoring — Two Layers

**Layer 1: Isolation Forest (unsupervised ML)**
- Trained on ALL sessions (normal + abnormal)
- Learns what "normal" looks like in feature space
- Scores each session by how far it deviates from normal
- Output: anomaly score normalized to 0.0–1.0
- `contamination=0.3` means it expects ~30% of sessions to be anomalous

**Layer 2: Rule-based flags (explainability)**
Even though the model produces the score, we also check specific rules to explain WHY:

| Rule | Condition | Flag | Score contribution |
|---|---|---|---|
| Fast + many requests | `avg_interval < 1.0` AND `count > 10` | `high_request_rate` | Explainability |
| Consistent timing | `std_interval < 0.2` AND `count > 10` | `consistent_timing` | Explainability |
| Sequential IDs | `sequential_id_score > 0.5` | `sequential_id_access` | Explainability |
| High error rate | `error_rate > 0.5` | `high_error_rate` | Explainability |
| Burst detected | `burstiness > 20` | `burst_detected` | Explainability |
| Model says anomaly | `prediction == -1` | `model_anomaly` | Explainability |

The **risk_score comes from the Isolation Forest**, the **flags come from rules**. This gives you both a numerical score AND a human-readable explanation.

### How Isolation Forest works conceptually

```
1. Take all sessions as feature vectors in 8-dimensional space
2. Randomly partition the data using decision trees
3. Normal points: deep in the tree (hard to isolate)
4. Anomalies: shallow in the tree (easy to isolate)
5. Anomaly score = average path length across all trees
6. Shorter path = more anomalous
```

### Attack detection mapping

| Attack | Primary features that trigger detection |
|---|---|
| **Bot scraping** | `avg_interval` ↓, `sequential_id_score` ↑, `request_count` ↑, `endpoint_entropy` ↓ |
| **Brute force** | `error_rate` ↑, `avg_interval` ↓, `unique_endpoints` ↓ (same endpoint repeated) |
| **Enumeration** | `sequential_id_score` ↑, `avg_interval` ↓, `std_interval` ↓ |
| **Credential stuffing** | `error_rate` ↑, `avg_interval` ↓, `request_count` ↑ |

---

## 5. Semantic Agent (Developer B) — engine/agents/semantic.py

### What it detects
Violations of the API's declared intent and object-level authorization abuse.

### How it works
1. Loads an OpenAPI spec (`spec.yaml`) to understand what the API expects
2. Classifies each endpoint as: `single_object`, `collection`, `search`, `admin`, `mutation`, `bulk_operation`
3. Applies 5 semantic rules per user per time window

### Rules

| Rule | What it detects | Example |
|---|---|---|
| **Ownership violation** | User A accessing User B's data | User 5 reads `/api/users/12` (not their data) |
| **Enumeration** | Sequential object ID access | `/api/users/1`, `/api/users/2`, `/api/users/3`... |
| **Volume mismatch** | Accessing more objects than expected | 50 unique user profiles in 1 minute |
| **Parameter tampering** | Sending unexpected parameters | Adding `?admin=true` to a normal endpoint |
| **Probing** | 403/404 on object access | Trying IDs until one works |

### Confidence system
The semantic agent knows its own reliability:
- **Spec coverage**: what % of endpoints in traffic are defined in `spec.yaml`
- **Data completeness**: what % of events have path_params and query_params
- `confidence = (spec_coverage + data_completeness) / 2`
- Low confidence = the coordinator reduces the semantic agent's influence

### Current limitation
`spec.yaml` only defines `/api/users/{id}`. Endpoints like `/api/login`, `/api/products`, `/api/search` are NOT in the spec, so the semantic agent has low confidence and low coverage on our synthetic data. This is why validation is difficult for this agent without a real API spec.

---

## 6. Coordinator — engine/coordinator/coordinator.py

### What it does
Combines all agent scores into a single final verdict per user.

### Scoring formula

$$\text{final\_score} = \frac{\sum_{i} w_i \cdot s_i}{\sum_{i} w_i}$$

Where:
- $w_i$ = weight of agent $i$
- $s_i$ = risk score from agent $i$

Current weights:
| Agent | Weight | Reason |
|---|---|---|
| Behavioral | 0.50 | Most reliable, ML-backed, validated |
| Semantic | 0.35 | Good but depends on spec coverage |
| Spatiotemporal | 0.15 | Not implemented yet |

### Verdict classification

| Final Score | Verdict | Meaning |
|---|---|---|
| `>= 0.8` | 🚨 **ATTACK** | High confidence malicious activity |
| `>= 0.6` | ⚠️ **SUSPICIOUS** | Unusual behavior, needs review |
| `< 0.3` | ✅ **NORMAL** | No anomalies detected |

### Confidence calculation
- Based on how many agents contributed data
- 1 agent reporting = 0.33 confidence
- 2 agents reporting = 0.67 confidence
- 3 agents reporting = 1.0 confidence

### Explainability
Every `CoordinatorResult` contains:
- `contributing_agents`: which agents flagged this user
- `all_flags`: combined list of signals from all agents
- `explanation`: human-readable sentence explaining the verdict
- `agent_scores`: per-agent breakdown so you can see which agent contributed most

---

## 7. Validation Strategy

### Level 1: Synthetic data (development)
- We know exactly which users are attackers (we generated them)
- Compute precision, recall, F1 against known labels
- Expected: near-perfect scores (we designed the patterns)
- Purpose: verify the pipeline works end-to-end

### Level 2: Public datasets (research validation)
- Download labeled datasets like CICIDS2017
- Convert to CanonicalEvent format using a converter script
- Run the same pipeline
- Compare predictions against dataset labels
- This is **real validation** — data we didn't design

### Level 3: Live traffic (production validation)
- Deploy the system on a real API
- Flag sessions, have a human review them
- Compute precision/recall based on human labels
- This is the **ground truth**

### Metrics we measure

| Metric | Formula | What it means |
|---|---|---|
| **Precision** | $\frac{TP}{TP + FP}$ | Of all users we flagged, how many were real attacks? |
| **Recall** | $\frac{TP}{TP + FN}$ | Of all real attacks, how many did we catch? |
| **F1 Score** | $\frac{2 \cdot P \cdot R}{P + R}$ | Balance between precision and recall |

Target benchmarks on real data:
| Metric | Acceptable | Good | Great |
|---|---|---|---|
| Precision | >0.70 | >0.85 | >0.95 |
| Recall | >0.60 | >0.75 | >0.90 |
| F1 | >0.65 | >0.80 | >0.92 |

---

## 8. File Reference

| File | Purpose | Owner |
|---|---|---|
| `main.py` | Entry point, runs full pipeline | Shared |
| `schemas/event_schema.py` | CanonicalEvent data format | Shared |
| `schemas/agent_result.py` | AgentResult output format | Shared |
| `engine/normalization/normalizer.py` | Raw logs → CanonicalEvent | Shared |
| `engine/pipeline/sessionizer.py` | Events → Sessions | Shared |
| `engine/agents/behavioral.py` | Behavioral analysis agent | Developer A |
| `engine/agents/semantic.py` | Semantic analysis agent | Developer B |
| `engine/agents/spatiotemporal.py` | Spatiotemporal agent (stub) | TBD |
| `engine/coordinator/coordinator.py` | Combines agent outputs → verdict | Shared |
| `scripts/generate_synthetic_data.py` | Generates test data | Shared |
| `spec.yaml` | OpenAPI spec (for semantic agent) | Developer B |
| `configs/` | Thresholds, weights (planned) | Shared |
| `evaluation/` | Validation scripts (planned) | Shared |
| `tests/` | Unit tests (planned) | Shared |
| `datasets/` | Generated data (git-ignored) | Local only |

---

## 9. How to Run

```sh
# Setup
cd /path/to/abuse-engine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Generate synthetic data
python scripts/generate_synthetic_data.py

# Run full pipeline
python main.py
```

---

## 10. Current Status & Next Steps

### Done
- [x] Canonical event schema
- [x] Agent result schema
- [x] Normalizer (with path param extraction)
- [x] Sessionizer (30 min gap logic)
- [x] Synthetic data generator (4 attack types)
- [x] Behavioral agent (8 features + Isolation Forest + rule flags)
- [x] Semantic agent (5 rules + confidence system)
- [x] Coordinator (weighted combination + verdict classification)
- [x] Main pipeline wiring

### Next
- [ ] Validate behavioral agent on synthetic data (precision/recall/F1)
- [ ] Add supervised classifier (Random Forest) to label attack TYPE
- [ ] Download CICIDS2017 + build converter for real data validation
- [ ] Save/load trained model to models/ directory
- [ ] Move thresholds to configs/config.yaml
- [ ] Build spatiotemporal agent
- [ ] Unit tests
- [ ] Expand spec.yaml for better semantic coverage