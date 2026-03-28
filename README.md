# Abuse Engine

A multi-agent API abuse detection engine built for research with a roadmap toward a production API security platform. The system passively analyzes API gateway logs — no SDK, no proxy, no code changes required.

---

## Table of Contents

1. [What This Is](#1-what-this-is)
2. [Architecture Overview](#2-architecture-overview)
3. [Repository Structure](#3-repository-structure)
4. [Shared Data Contracts](#4-shared-data-contracts)
5. [Pipeline Components](#5-pipeline-components)
6. [Agents](#6-agents)
7. [Coordinator](#7-coordinator)
8. [Synthetic Data Generator](#8-synthetic-data-generator)
9. [How to Run](#9-how-to-run)
10. [Validation Strategy](#10-validation-strategy)
11. [Current Status](#11-current-status)
12. [Roadmap](#12-roadmap)
13. [LLM / Architect Context](#13-llm--architect-context)

---

## 1. What This Is

Abuse Engine detects **logic-level API abuse** that traditional security tools miss:

| Attack | Example |
|---|---|
| **Bot scraping** | Automated enumeration of `/api/users/1, /2, /3...` |
| **Brute force** | Hundreds of failed login attempts per minute |
| **Data exfiltration** | Pagination-crawling through entire datasets |
| **BOLA/IDOR** | User A accessing User B's private resources |
| **API contract violation** | Sending undocumented parameters to bypass access controls |
| **Impossible travel** | Same API key used from New York and Singapore within minutes |

It does this **without touching the API itself** — it reads logs from your existing API gateway (AWS API Gateway, Kong, Nginx, etc.) and produces risk verdicts per user per session.

---

## 2. Architecture Overview

```
API Gateway Logs (JSON)
        │
        ▼
┌───────────────────────────────┐
│  engine/normalization/        │
│  normalizer.py                │  Raw dict → CanonicalEvent
│  - parse timestamps           │  Standardize all field names
│  - extract path params        │  Handle missing fields safely
│  - map all fields             │
└───────────────┬───────────────┘
                │  List[CanonicalEvent]
                ▼
┌───────────────────────────────┐
│  engine/pipeline/             │
│  sessionizer.py               │  Group events by user
│  - group by user_id / IP      │  30-minute inactivity gap = new session
│  - sort by timestamp          │
│  - split on 30-min gap        │
└───────┬───────────────────────┘
        │  List[Session]         List[CanonicalEvent]
        ▼                               ▼
┌──────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│ Behavioral Agent │     │   Semantic Agent      │     │ Spatiotemporal Agent │
│ behavioral.py    │     │   semantic.py         │     │ spatio temporal/     │
│                  │     │                       │     │                      │
│ HOW they behave  │     │ WHAT they access      │     │ WHERE / WHEN         │
│ - timing         │     │ - API spec violations │     │ - geo-velocity       │
│ - request rates  │     │ - ownership checks    │     │ - impossible travel  │
│ - sequential IDs │     │ - enumeration rules   │     │ - graph topology     │
│ - Isolation      │     │ - parameter tampering │     │ - sliding windows    │
│   Forest (ML)    │     │ - probing patterns    │     │ - Isolation Forest   │
│                  │     │                       │     │   + optional LLM     │
└────────┬─────────┘     └──────────┬────────────┘     └──────────┬───────────┘
         │  AgentResult             │  Dict[user→report]           │  AgentResult
         └──────────────────────────┼──────────────────────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │ engine/coordinator/            │
                    │ coordinator.py                 │
                    │                                │
                    │ Weighted fusion of all agents  │
                    │ behavioral=0.5 semantic=0.35   │
                    │ spatiotemporal=0.15             │
                    │                                │
                    │ Output: CoordinatorResult      │
                    │  - final_score (0.0–1.0)       │
                    │  - verdict: normal/suspicious/ │
                    │            attack              │
                    │  - contributing_agents         │
                    │  - all_flags (explainable)     │
                    │  - confidence                  │
                    └───────────────────────────────┘
```

---

## 3. Repository Structure

```
abuse-engine/
│
├── main.py                          Entry point — runs full pipeline
├── spec.yaml                        OpenAPI spec consumed by semantic agent
├── requirements.txt                 Python dependencies
├── .gitignore
│
├── schemas/
│   ├── event_schema.py              CanonicalEvent — shared input format
│   └── agent_result.py              AgentResult — shared output format
│
├── engine/
│   ├── normalization/
│   │   └── normalizer.py            Raw JSON → CanonicalEvent
│   │
│   ├── pipeline/
│   │   └── sessionizer.py           CanonicalEvent list → Session list
│   │
│   ├── agents/
│   │   ├── behavioral.py            Behavioral analysis (yours)
│   │   ├── semantic.py              Semantic/contract analysis (friend's)
│   │   └── spatio temporal/         Spatiotemporal agent (flagship)
│   │       ├── spatio_temporal_agent.py   Main agent + pipeline façade
│   │       ├── agent_framework.py         Lightweight graph execution engine
│   │       ├── models.py                  Agent-local data models
│   │       ├── model_registry.py          IsolationForest lifecycle manager
│   │       ├── sliding_window.py          Thread-safe time-windowed event buffer
│   │       ├── llm_agent_node.py          Optional Gemini LLM reasoning layer
│   │       ├── run_agent.py               CLI entry for the spatiotemporal agent
│   │       └── tests.py                   Unit tests for the spatiotemporal module
│   │
│   └── coordinator/
│       └── coordinator.py           Combines agent results → final verdict
│
├── scripts/
│   └── generate_synthetic_data.py   Generates mock_logs.json for testing
│
├── datasets/                        Generated data (git-ignored, recreate locally)
│   └── mock_logs.json
│
├── configs/                         Agent weights, thresholds (planned)
├── evaluation/                      Precision/recall/F1 scripts (planned)
└── tests/                           Unit tests (planned)
```

---

## 4. Shared Data Contracts

All components communicate through two shared schemas defined in `schemas/`. **Never bypass these — all agents must consume and produce these types.**

### CanonicalEvent — `schemas/event_schema.py`

The universal input format. Every raw log entry is converted into this before any agent touches it.

```python
@dataclass
class CanonicalEvent:
    timestamp: datetime              # Parsed datetime (not a string)
    ip: str                          # Source IP
    user_id: Optional[str]           # Authenticated user, or None
    tenant_id: Optional[str]         # Tenant context for multi-tenant SaaS
    session_id: Optional[str]        # Pre-existing session ID if available
    endpoint: str                    # Templated path: "/api/users/{id}"
    method: str                      # HTTP method: GET, POST, etc.
    status_code: int                 # HTTP response code
    user_agent: str                  # Client identifier string
    response_time: Optional[float]   # Server latency in ms
    path_params: Dict                # Extracted params: {"id": "123"}
    query_params: Dict               # Query string as dict
    request_body: Optional[Dict]     # Parsed request body
```

Key design decisions:
- `timestamp` is a `datetime` object everywhere in the pipeline — never a string after normalization
- `endpoint` is a **template** (`/api/users/{id}`), not a concrete URL — the normalizer extracts path params into `path_params`
- `tenant_id` is a first-class field because cross-tenant isolation is a critical detection signal

### AgentResult — `schemas/agent_result.py`

The universal output format. Every agent (behavioral, semantic, spatiotemporal) returns this. The coordinator consumes it.

```python
@dataclass
class AgentResult:
    agent: str           # "behavioral", "semantic", "spatiotemporal"
    risk_score: float    # 0.0 (safe) to 1.0 (dangerous)
    flags: List[str]     # Human-readable signals: ["high_request_rate", "sequential_id_access"]
    explanation: str     # One-sentence summary of why this score was assigned
    metadata: Dict       # Raw feature values and debug info
```

> **Note for LLMs**: The semantic agent currently returns `Dict[user_id, report]` instead of `List[AgentResult]`. This is a known inconsistency. When integrating the semantic agent into the coordinator, the coordinator handles this divergence internally. A future refactor should normalize the semantic agent's output to match `AgentResult`.

---

## 5. Pipeline Components

### Normalizer — `engine/normalization/normalizer.py`

**Input**: `List[Dict]` (raw JSON log entries)
**Output**: `List[CanonicalEvent]`

Responsibilities:
- Converts ISO timestamp strings to `datetime` objects
- Detects and extracts path parameters from concrete URLs using regex patterns:
  - `/api/users/123` → `endpoint="/api/users/{id}"`, `path_params={"id": "123"}`
  - `/api/products/456` → `endpoint="/api/products/{id}"`, `path_params={"id": "456"}`
- Provides safe defaults for all missing fields

To extend with a new URL pattern, add to `_extract_path_params()`:
```python
(r"^(/api/orders/)(\d+)(.*)$", "/api/orders/{id}", "id"),
```

### Sessionizer — `engine/pipeline/sessionizer.py`

**Input**: `List[CanonicalEvent]`
**Output**: `List[Session]`

Groups events into sessions using:
1. Group by `user_id` (or IP if anonymous)
2. Sort by `timestamp` (already `datetime`, no parsing needed)
3. Split into a new session when gap between consecutive events exceeds `gap_seconds` (default: 1800s = 30 minutes)

`Session` object properties (computed, not stored):
- `duration`: float — seconds from first to last event
- `request_count`: int — number of events
- `endpoint_sequence`: List[str] — ordered list of endpoints visited

The behavioral agent operates on `Session` objects. The semantic agent operates directly on `List[CanonicalEvent]`.

---

## 6. Agents

### Behavioral Agent — `engine/agents/behavioral.py`

**Developer**: Developer A
**Input**: `List[Session]`
**Output**: `List[AgentResult]`

Answers: *Is this session behaving like a human or an automated system?*

#### Feature Extraction

8 features per session:

| Feature | Formula | What it captures |
|---|---|---|
| `request_count` | `len(events)` | Session volume |
| `avg_interval` | `mean(time gaps)` | Speed — bots are fast |
| `std_interval` | `stdev(time gaps)` | Consistency — bots are regular |
| `endpoint_entropy` | Shannon entropy of endpoint frequency | Diversity — bots repeat |
| `error_rate` | `4xx+5xx / total` | Brute force indicator |
| `burstiness` | Max events in any 5-second window | Burst attack indicator |
| `unique_endpoints` | Distinct endpoint count | Breadth of access |
| `sequential_id_score` | Fraction of consecutive path param IDs differing by 1 | Enumeration detector |

Sequential ID detection uses `path_params` (not endpoint string), so it works correctly after normalization.

#### Scoring — Two Layers

**Layer 1 — Isolation Forest (ML)**
- Trains on all sessions in the current batch
- `contamination=0.3` (30% expected anomaly rate in synthetic data; lower in production)
- `random_state=42` for reproducibility
- Raw decision scores normalized to [0.0, 1.0]: most anomalous → 1.0

**Layer 2 — Rule-based flags (explainability)**
Rules fire independently of the model score and populate `flags`:

| Rule | Condition | Flag |
|---|---|---|
| Fast + high volume | `avg_interval < 1.0s` AND `count > 10` | `high_request_rate` |
| Machine-like timing | `std_interval < 0.2` AND `count > 10` | `consistent_timing` |
| ID enumeration | `sequential_id_score > 0.5` | `sequential_id_access` |
| Credential stuffing | `error_rate > 0.5` | `high_error_rate` |
| Request burst | `burstiness > 20` | `burst_detected` |
| Model agrees | `IsolationForest prediction == -1` | `model_anomaly` |

The risk score comes from the model. The flags explain why.

#### Known Limitations
- Model trains and scores on the same batch (no train/test split) — acceptable for MVP, needs fixing for production
- `contamination=0.3` is too high for production traffic; set to `0.01–0.05` when deploying against real traffic

---

### Semantic Agent — `engine/agents/semantic.py`

**Developer**: Developer B
**Input**: `List[CanonicalEvent]`, time window bounds, OpenAPI spec path
**Output**: `Dict[user_id, report]`

Answers: *Is this user violating the declared intent of the API?*

#### Architecture

```
spec.yaml
    ↓
SpecLoader → EndpointRegistry
                ↓
         SemanticRuleEngine
                ↓ (per user, per time window)
         SemanticGuardAgent.process_window()
                ↓
         Dict[user_id → {
             semantic_risk_score: float,
             confidence: float,
             rule_breakdown: Dict[rule_name, score]
         }]
```

#### Endpoint Classification

Endpoints in `spec.yaml` are classified into types:
`single_object`, `collection`, `search`, `admin`, `mutation`, `bulk_operation`

Classification logic in `SpecLoader._classify_endpoint()`:
- Has `{id}` in last segment → `single_object`
- `admin` tag → `admin`
- `POST/PUT/PATCH/DELETE` → `mutation`
- `GET` collection → `collection` or `search`

#### Rules

| Rule | What it detects | Weight (default) |
|---|---|---|
| `ownership_violation` | User accessing object they don't own | 0.4 |
| `enumeration` | Sequential object ID access | 0.2 |
| `volume_mismatch` | Accessing more unique objects than expected | 0.2 |
| `parameter_tampering` | Unexpected query/body parameters | 0.1 |
| `probing` | 403/404 responses on object-access endpoints | 0.1 |

#### Confidence System

The agent scores its own reliability before scoring users:
- **Spec coverage**: what fraction of observed endpoints are defined in `spec.yaml`
- **Data completeness**: what fraction of events have path_params and query_params populated
- `confidence = (spec_coverage + data_completeness) / 2`

The coordinator multiplies the semantic score by this confidence value, so a poorly-covered spec reduces the semantic agent's influence automatically.

#### Current Limitation

`spec.yaml` only defines `/api/users/{id}`. The endpoints generated by `generate_synthetic_data.py` (`/api/login`, `/api/products`, `/api/search`) are not in the spec, so spec coverage is low on synthetic data. Expand `spec.yaml` to improve semantic agent recall.

---

### Spatiotemporal Agent — `engine/agents/spatio temporal/`

**Status**: Implemented (flagship agent)
**Input**: `List[CanonicalEvent]` (with optional geo enrichment: `country`, `asn`)
**Output**: `AgentResult`

Answers: *Are there suspicious patterns in WHEN and WHERE this traffic comes from, relative to graph-topology relationships?*

This is the most technically sophisticated agent. It uses a **graph + sliding window + IsolationForest + optional LLM reasoning** pipeline.

#### Module Breakdown

| File | Responsibility |
|---|---|
| `spatio_temporal_agent.py` | Main agent + `SpatioTemporalPipeline` façade |
| `agent_framework.py` | Lightweight directed graph execution engine (LangGraph-compatible interface) |
| `models.py` | Agent-local `CanonicalEvent`, `AgentResult`, `AgentState`, `Severity` |
| `model_registry.py` | IsolationForest lifecycle: train, save, load, retrain on schedule |
| `sliding_window.py` | Thread-safe deque-backed rolling time window |
| `llm_agent_node.py` | Optional Gemini LLM reasoning layer (LangChain + tool-calling) |
| `run_agent.py` | CLI entry point |
| `tests.py` | Unit tests |

#### Execution Graph

Without LLM:
```
validate → score → severity → END
        ↘ skip → END          (if too few events)
```

With LLM (`LLMConfig` provided):
```
validate → score → severity → llm_analysis → END
        ↘ skip → END
```

#### Sliding Window Processing

Events are scored in overlapping time windows:
- Default window: 5 minutes
- Default stride: 2.5 minutes
- Windows with fewer than `min_window_events` (default 5) are skipped
- Final score = max risk score across all windows

#### Graph Features (8 per window)

The `WindowFeatureExtractor` computes these from a set of `CanonicalEvent` objects:

| Feature | What it captures |
|---|---|
| `ip_fan_out` | Avg users served per IP — high = shared/proxy IP |
| `user_ip_count` | Avg IPs per user — high = distributed attack |
| `max_user_ip_count` | Max IPs by any single user — outlier signal |
| `graph_density` | Edges/nodes ratio — dense = many cross-connections |
| `shared_endpoint_ips` | Max IPs hitting same endpoint — coordinated attack signal |
| `request_synchrony` | Min std-dev of request timestamps per endpoint — synchronized bots |
| `ip_endpoint_spread` | Avg endpoints per IP — low = focused attack |
| `edge_count` | Total graph edges — raw scale signal |

#### IsolationForest Lifecycle (`model_registry.py`)

- Singleton — all agent instances share one model
- Persists to `models/isolation_forest.joblib`
- Validates training data: minimum 50 samples, non-zero variance per feature
- Supports scheduled background retraining (daily/weekly via background thread)
- Thread-safe scoring interface

#### Optional LLM Layer (`llm_agent_node.py`)

When `LLMConfig(api_key="GEMINI_KEY")` is passed to `SpatioTemporalPipeline`, the graph gains an `llm_analysis` node that:

1. Reads the scored `AgentResult`
2. Calls three tools in a ReAct loop:
   - `lookup_ip_reputation` — checks known threat lists
   - `query_threat_intel` — searches a mock threat-intel feed
   - `explain_window_features` — translates feature values to plain English
3. Produces a structured verdict: `confirmed_threat | likely_fp | uncertain`
4. Stores result in `state.metadata["llm_analysis"]`

> **Note**: The spatiotemporal agent uses its own internal `models.py` with a `CanonicalEvent` that has `source_ip`, `request_path`, `country`, `asn` fields instead of the shared schema. When integrating with the main pipeline, a field-mapping adapter is needed between `schemas/event_schema.py` and `engine/agents/spatio temporal/models.py`.

---

## 7. Coordinator

**File**: `engine/coordinator/coordinator.py`

**Input**: Results from all agents
**Output**: `List[CoordinatorResult]` — one per user, sorted by risk descending

### Scoring Formula

$$\text{final\_score} = \frac{\sum_i w_i \cdot s_i}{\sum_i w_i}$$

Default weights:
```python
{
    "behavioral": 0.5,       # most validated agent
    "semantic": 0.35,        # dampened by semantic agent's own confidence
    "spatiotemporal": 0.15,  # scaffold weight, increase as it gets validated
}
```

Semantic score is multiplied by the semantic agent's `confidence` field before weighting, so low spec coverage automatically reduces its influence.

### Verdict Thresholds

| Final Score | Verdict |
|---|---|
| `>= 0.8` | `attack` |
| `>= 0.6` | `suspicious` |
| `< 0.3` | `normal` |

### CoordinatorResult

```python
@dataclass
class CoordinatorResult:
    user_id: str
    final_score: float
    verdict: str                    # "normal", "suspicious", "attack"
    confidence: float               # fraction of agents that reported
    contributing_agents: List[str]  # which agents flagged this user
    all_flags: List[str]            # deduplicated flags from all agents
    explanation: str                # human-readable one-sentence summary
    agent_scores: Dict[str, float]  # per-agent breakdown
```

---

## 8. Synthetic Data Generator

**File**: `scripts/generate_synthetic_data.py`
**Output**: `datasets/mock_logs.json` (git-ignored; regenerate locally)

Generates 4 user types:

| User Type | Count | Pattern | Behavioral signal |
|---|---|---|---|
| `normal_user_0` to `4` | 10 req each | Random endpoints, 2–30s gaps | Low risk — baseline |
| `bot_user_1` | 200 requests | `/api/users/1,2,3...` sequential, 0.1–0.5s gaps | `high_request_rate`, `sequential_id_access`, `consistent_timing` |
| `brute_user_1` | 50 requests | `/api/login` only, mostly 401, 0.2–1.0s gaps | `high_request_rate`, `high_error_rate` |
| `enum_user_1` | 100 requests | `/api/products/1,2,3...` sequential, 0.3–1.5s gaps | `sequential_id_access`, `high_request_rate` |

All events include: `tenant_id`, `session_id`, `query_params`, `request_body` fields required by both agents.

---

## 9. How to Run

### Setup

```sh
cd /path/to/abuse-engine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Generate test data

```sh
python scripts/generate_synthetic_data.py
# Output: datasets/mock_logs.json (400 events)
```

### Run the full pipeline

```sh
python main.py
```

Expected output:
```
Loading raw logs...
  Loaded 400 raw log entries

Normalizing...
  Normalized into 400 canonical events

Sessionizing...
  Created 8 sessions

============================================================
BEHAVIORAL AGENT
============================================================
  Session bot_user_1_session_5: high_request_rate, consistent_timing, sequential_id_access, burst_detected, model_anomaly
    risk=1.0  flags=['high_request_rate', 'consistent_timing', 'sequential_id_access', 'burst_detected', 'model_anomaly']
  Session normal_user_0_session_0: normal
    risk=0.05  flags=[]
  ...

============================================================
COORDINATOR — FINAL VERDICTS
============================================================

  🚨 bot_user_1
    Verdict:    ATTACK
    Score:      0.87
    Confidence: 0.67
    Flags:      ['high_request_rate', 'sequential_id_access', ...]

  ✅ normal_user_0
    Verdict:    NORMAL
    Score:      0.04
```

---

## 10. Validation Strategy

### Level 1 — Synthetic (current)

Known ground truth from the generator. Run:
```sh
python evaluation/validate_behavioral.py  # (to be built)
```

| User | Label |
|---|---|
| `normal_user_0` to `4` | `normal` |
| `bot_user_1` | `attack` |
| `brute_user_1` | `attack` |
| `enum_user_1` | `attack` |

### Level 2 — Public datasets (next step)

Download CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html

Contains labeled attack types that map to behavioral features:

| CICIDS2017 Label | Behavioral signal |
|---|---|
| `Bot` | `high_request_rate`, `consistent_timing` |
| `Brute Force` | `high_error_rate`, `high_request_rate` |
| `Web Attack - SQL Injection` | `parameter_tampering` (semantic) |
| `BENIGN` | Normal baseline |

Converter script: `scripts/convert_cicids.py` (to be built)

### Metrics

$$\text{Precision} = \frac{TP}{TP + FP} \quad \text{Recall} = \frac{TP}{TP + FN} \quad F_1 = \frac{2 \cdot P \cdot R}{P + R}$$

Target benchmarks on real data:

| Metric | Acceptable | Good | Great |
|---|---|---|---|
| Precision | > 0.70 | > 0.85 | > 0.95 |
| Recall | > 0.60 | > 0.75 | > 0.90 |
| F1 | > 0.65 | > 0.80 | > 0.92 |

---

## 11. Current Status

```
✅ schemas/event_schema.py               Shared CanonicalEvent
✅ schemas/agent_result.py               Shared AgentResult
✅ engine/normalization/normalizer.py    Raw JSON → CanonicalEvent
✅ engine/pipeline/sessionizer.py        Events → Sessions
✅ engine/agents/behavioral.py           Feature extraction + Isolation Forest
✅ engine/agents/semantic.py             5-rule semantic engine + confidence
✅ engine/agents/spatio temporal/        Full graph-based agent with optional LLM
✅ engine/coordinator/coordinator.py     Weighted fusion + verdict
✅ scripts/generate_synthetic_data.py    4 attack scenario generator
✅ main.py                               Full pipeline wired

⬜ evaluation/validate_behavioral.py     Precision/recall/F1 on synthetic data
⬜ scripts/convert_cicids.py             CICIDS2017 → CanonicalEvent
⬜ evaluation/validate_real.py           Validation on real labeled data
⬜ Schema adapter for spatiotemporal     Map shared schema → agent-local models
⬜ Integrate spatiotemporal into main.py Wire into coordinator
⬜ Save/load trained model               Don't retrain Isolation Forest every run
⬜ configs/config.yaml                   Move thresholds out of source code
⬜ tests/                                Unit tests for all components
⬜ Dashboard                             Streamlit or similar for demo
```

---

## 12. Roadmap

```
Phase 1 — Validate (this week)
├── Build evaluation/validate_behavioral.py
├── Download CICIDS2017
├── Build CICIDS converter
└── Get real F1 score for behavioral agent

Phase 2 — Integrate Spatiotemporal (next)
├── Build schema adapter (shared schema ↔ spatio temporal models)
├── Wire spatiotemporal into main.py
├── Generate synthetic geo-attack data (impossible travel scenarios)
└── Validate spatiotemporal agent

Phase 3 — Additional Agents
├── Tenant Isolation Agent (cross-tenant access detection)
├── Data Exfiltration Agent (pagination crawl, bulk export)
└── Agent Detection Agent (TLS fingerprint, UA consistency)

Phase 4 — Demo & Distribution
├── Streamlit dashboard
├── Live attack simulation mode
├── Docker container / pip install story
└── One design partner (real SaaS company testing it)
```

---

## 13. LLM / Architect Context

This section is for LLMs and engineers onboarding to this codebase.

### Critical rules

1. **All agents must consume `schemas.CanonicalEvent`** — do not create new event types in agent code. The spatiotemporal agent has its own `models.py` as a historical artifact; bridge it with an adapter.

2. **All agents must return `schemas.AgentResult`** — the coordinator depends on this. The semantic agent currently returns `Dict[user_id, report]`; the coordinator handles this divergence internally but this should be normalized in a future refactor.

3. **`timestamp` is always a `datetime` object** after normalization — never call `datetime.fromisoformat()` downstream of the normalizer.

4. **`endpoint` is always a template** after normalization — `/api/users/{id}` not `/api/users/123`. Path parameters are in `path_params`.

5. **Agent weights in the coordinator are not final** — they are research parameters. As each agent gets validated on real data, its weight should be updated in `coordinator.py`.

### Key design decisions and why

| Decision | Reasoning |
|---|---|
| Isolation Forest for behavioral | Unsupervised — no labeled data needed to train. Appropriate for MVP. Replace with supervised model when labels are available. |
| Semantic agent confidence dampening | Avoids over-trusting an agent whose spec coverage is poor. The coordinator multiplies semantic score by `confidence`. |
| Spatiotemporal has its own agent framework | Built independently with a LangGraph-compatible interface. Intentionally decoupled so it can be extracted into its own service. |
| `gap_seconds=1800` in sessionizer | Standard web session timeout. Configurable — pass a different value to `sessionize()`. |
| `contamination=0.3` in behavioral | Set high because synthetic data has 3/8 users as attackers. Production value should be `0.01–0.05`. |
| Coordinator uses `max()` across sessions | A user with one very suspicious session and three normal ones is still a threat. |

### Integration points for new agents

To add a new agent:

1. Create `engine/agents/your_agent.py`
2. Implement `analyze(sessions_or_events) -> List[AgentResult]`
3. Set `AgentResult.agent = "your_agent_name"`
4. Add it to the coordinator's `self.weights` dict
5. Call it in `main.py` and pass results to `coordinator.combine()`

### Known schema inconsistency to fix

The spatiotemporal agent's `models.py` defines its own `CanonicalEvent`:
```python
# engine/agents/spatio temporal/models.py
class CanonicalEvent:
    source_ip: str          # ← different field name
    request_path: str       # ← different field name
    country: Optional[str]  # ← extra field (geo enrichment)
    asn: Optional[str]      # ← extra field
```

The shared schema uses:
```python
# schemas/event_schema.py
class CanonicalEvent:
    ip: str
    endpoint: str
```

A thin adapter is needed before passing shared events to the spatiotemporal pipeline:
```python
def adapt_event(e: SharedCanonicalEvent) -> SpatioCanonicalEvent:
    return SpatioCanonicalEvent(
        timestamp=e.timestamp,
        source_ip=e.ip,
        user_id=e.user_id,
        request_path=e.endpoint,
        http_method=e.method,
        response_code=e.status_code,
    )
```