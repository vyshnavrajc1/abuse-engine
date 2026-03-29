# APISentry / Abuse Engine — Full Architecture & Project Context

> **For LLMs reading this:** This file is the authoritative context for the abuse-engine project.
> Read it fully before making any code suggestions. The research path is the current priority.
> Do not suggest product-layer features until the research validation loop is complete.

---

## 0. What This Project Is (60-Second Version)

A **multi-agent API abuse detection system** that reads API gateway logs and produces per-user risk verdicts. Three specialized agents (behavioral, semantic, spatiotemporal) each analyze different dimensions of API traffic, then a weighted coordinator fuses their scores into a final verdict (normal / suspicious / attack).

**Current priority:** Complete academic validation for IEEE paper submission (target: May 2026).  
**After paper:** Convert to B2B SaaS product (APISentry) targeting Series A/B API-first startups.  
**Stack:** Python, scikit-learn, OpenAPI spec parsing, optional LLM reasoning (Claude Haiku/Sonnet).

---

## 1. Product Overview — How It Works End to End

```
Customer's API Gateway (AWS / Kong / Nginx)
         │
         │  writes logs to
         ▼
    S3 Bucket / Kafka Stream
         │
         │  ingested by
         ▼
┌─────────────────────────────────────────────────────┐
│                  ABUSE ENGINE PIPELINE              │
│                                                     │
│  Raw Logs → Normalizer → CanonicalEvents            │
│                               │                    │
│                          Sessionizer               │
│                               │                    │
│              ┌────────────────┼────────────────┐   │
│              ▼                ▼                ▼   │
│         Behavioral        Semantic      Spatiotemporal│
│           Agent            Agent           Agent   │
│         (HOW they        (WHAT they      (WHERE/WHEN)│
│          behave)          access)                  │
│              │                │                │   │
│              └────────────────┼────────────────┘   │
│                               ▼                    │
│                          Coordinator               │
│                      (weighted fusion)             │
│                               │                    │
│                    CoordinatorResult               │
│              verdict: normal/suspicious/attack      │
└─────────────────────────────────────────────────────┘
         │
         ▼
   Dashboard / Alert / Block (product layer, post-paper)
```

**Zero-integration design:** Customers never change their API code. They only grant read access to their existing gateway logs. This is the primary differentiator vs enterprise competitors (Salt Security, Noname/Akamai, Traceable) who require inline proxy deployment.

---

## 2. Shared Data Contracts — Never Change These Without Updating All Agents

### CanonicalEvent (`schemas/event_schema.py`)
```python
@dataclass
class CanonicalEvent:
    timestamp: datetime          # Always datetime object, never string
    ip: str
    user_id: Optional[str]
    tenant_id: Optional[str]     # First-class field — critical for multi-tenant
    session_id: Optional[str]
    endpoint: str                # ALWAYS a template: /api/users/{id}
    method: str
    status_code: int
    user_agent: str
    response_time: Optional[float]
    path_params: Dict            # Extracted by normalizer: {"id": "123"}
    query_params: Dict
    request_body: Optional[Dict]
```

### AgentResult (`schemas/agent_result.py`)
```python
@dataclass
class AgentResult:
    agent: str           # "behavioral" | "semantic" | "spatiotemporal"
    risk_score: float    # 0.0 to 1.0
    flags: List[str]     # ["high_request_rate", "sequential_id_access"]
    explanation: str     # One sentence
    metadata: Dict       # Raw feature values for debugging
```

### Known Inconsistency
The semantic agent returns `Dict[user_id, report]` instead of `List[AgentResult]`.
The coordinator handles this internally. Fix this in a future refactor — do not work around it elsewhere.

The spatiotemporal agent uses its own internal `models.py` with different field names (`source_ip` vs `ip`, `request_path` vs `endpoint`). An adapter is needed before passing shared events to it — see Section 5.

---

## 3. Research Path — Current Priority

### Goal
Publish an IEEE paper demonstrating that a multi-agent coordinator architecture detects API abuse better than any single-agent baseline.

**Target venues (May 2026 submission):** IEEE TrustCom, IEEE ISCC, or IEEE ICTSS.

### What the Paper Needs to Prove
1. The multi-agent coordinator achieves higher F1 than any individual agent alone (ablation study).
2. The system works on a real/public labeled dataset, not just synthetic data.
3. The explainability layer (human-readable flags + LLM explanation) is a research contribution, not just engineering.

### Dataset Strategy

**Layer 1 — Synthetic (ready now)**
- Source: `scripts/generate_synthetic_data.py`
- Ground truth: known labels (normal, bot, brute, enum)
- Use for: ablation study, architecture diagrams, demo
- NOT sufficient alone for paper acceptance

**Layer 2 — CICIDS2017 (build converter now)**
- Source: https://www.unb.ca/cic/datasets/ids-2017.html — free download
- Contains labeled: Bot, BruteForce, Web Attack, BENIGN
- Use for: primary external validation — this is what gets the paper accepted
- Build: `scripts/convert_cicids.py` — maps CICIDS flow-level features to CanonicalEvent fields
- CICIDS is network-level, not application-level. The mapping is imperfect but sufficient:
  - Source IP → `ip`
  - Flow duration + packet count → behavioral features (request_count proxy)
  - Destination port 80/443 → assume API traffic
  - Label → ground truth for F1 calculation

**CICIDS label mapping:**
| CICIDS Label | Abuse Engine Attack Type | Primary Agent |
|---|---|---|
| Bot | automated scraping, enumeration | Behavioral |
| Brute Force | credential stuffing | Behavioral |
| Web Attack - SQL Injection | parameter tampering | Semantic |
| Web Attack - XSS | parameter tampering | Semantic |
| BENIGN | normal | all agents |

### Validation Metrics Required for Paper

$$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad F_1 = \frac{2PR}{P+R}$$

**Target benchmarks:**
| Metric | Acceptable | Good | Great |
|---|---|---|---|
| Precision | > 0.70 | > 0.85 | > 0.95 |
| Recall | > 0.60 | > 0.75 | > 0.90 |
| F1 | > 0.65 | > 0.80 | > 0.92 |

**Required ablation table (this is the core paper contribution):**

| Configuration | Precision | Recall | F1 |
|---|---|---|---|
| Isolation Forest alone (baseline) | X.XX | X.XX | X.XX |
| Behavioral agent alone | X.XX | X.XX | X.XX |
| Semantic agent alone | X.XX | X.XX | X.XX |
| Spatiotemporal alone | X.XX | X.XX | X.XX |
| Behavioral + Semantic | X.XX | X.XX | X.XX |
| All three (coordinator) | X.XX | X.XX | X.XX |

The coordinator row must beat every individual row. If it doesn't, adjust weights in `coordinator.py`.

### Research Validation Build Order

```
1. evaluation/validate_behavioral.py     ← build first
   - Load synthetic data
   - Run behavioral agent alone
   - Report precision/recall/F1 vs known labels
   - Compare: IsolationForest alone vs behavioral agent (IF + rules)

2. scripts/convert_cicids.py             ← build second
   - Download CICIDS2017
   - Map flow features → CanonicalEvent
   - Output: datasets/cicids_canonical.json

3. evaluation/validate_full_pipeline.py  ← build third
   - Run all three agents + coordinator on CICIDS data
   - Generate the ablation table
   - Output: results/ablation_results.csv

4. evaluation/generate_paper_figures.py  ← build last
   - ROC curves, confusion matrices, F1 bar charts
   - Output: figures/ directory for paper inclusion
```

---

## 4. Architecture — Agent Details

### Behavioral Agent (`engine/agents/behavioral.py`)

**Input:** `List[Session]`  
**Output:** `List[AgentResult]`  
**Answers:** Is this session behaving like a human or an automated system?

**8 Features per session:**
| Feature | Formula | What it captures |
|---|---|---|
| request_count | len(events) | Session volume |
| avg_interval | mean(time gaps between events) | Speed — bots are fast |
| std_interval | stdev(time gaps) | Regularity — bots are consistent |
| endpoint_entropy | Shannon entropy of endpoint frequency | Diversity — bots repeat |
| error_rate | (4xx + 5xx) / total | Brute force signal |
| burstiness | max events in any 5-second window | Burst attack signal |
| unique_endpoints | distinct endpoint count | Breadth of access |
| sequential_id_score | fraction of consecutive path_params differing by 1 | Enumeration signal |

**Scoring:**
- Layer 1: IsolationForest (`contamination=0.3` for synthetic, `0.01-0.05` for production)
- Layer 2: Rule-based flags for explainability (fire independently of model score)
- Final risk_score comes from the model; flags explain why

**Known limitation:** Model trains and scores on same batch. Acceptable for research MVP. For production, save the trained model with `joblib.dump()` and load it on subsequent runs — do not retrain every time.

---

### Semantic Agent (`engine/agents/semantic.py`)

**Input:** `List[CanonicalEvent]`, OpenAPI spec path  
**Output:** `Dict[user_id, report]` (known inconsistency — coordinator handles this)  
**Answers:** Is this user violating the declared intent of the API?

**5 Rules:**
| Rule | Detects | Weight |
|---|---|---|
| ownership_violation | User accessing objects they don't own | 0.4 |
| enumeration | Sequential object ID access | 0.2 |
| volume_mismatch | Accessing more unique objects than expected | 0.2 |
| parameter_tampering | Unexpected query/body parameters | 0.1 |
| probing | 403/404 on object-access endpoints | 0.1 |

**Confidence system:** Agent scores its own reliability based on spec coverage and data completeness. Coordinator multiplies semantic score by this confidence value — poor spec coverage automatically reduces the semantic agent's weight. Expand `spec.yaml` to cover all endpoints in test data to improve recall.

---

### Spatiotemporal Agent (`engine/agents/spatio temporal/`)

**Input:** `List[CanonicalEvent]` (with optional geo: country, asn fields)  
**Output:** `AgentResult`  
**Answers:** Are there suspicious patterns in WHEN and WHERE this traffic comes from?

**Key modules:**
- `spatio_temporal_agent.py` — main agent + SpatioTemporalPipeline facade
- `agent_framework.py` — lightweight directed graph execution (LangGraph-compatible)
- `sliding_window.py` — thread-safe deque-backed rolling time window
- `model_registry.py` — IsolationForest lifecycle: train, save, load
- `llm_agent_node.py` — optional LLM reasoning layer (currently Gemini, swap for Claude)

**Schema adapter required** before passing shared events to this agent:
```python
def adapt_event(e: SharedCanonicalEvent) -> SpatioCanonicalEvent:
    return SpatioCanonicalEvent(
        timestamp=e.timestamp,
        source_ip=e.ip,
        user_id=e.user_id,
        request_path=e.endpoint,
        http_method=e.method,
        response_code=e.status_code,
        country=None,   # enrich from MaxMind GeoIP in production
        asn=None,
    )
```

**8 Graph features per time window (5-min default, 2.5-min stride):**
| Feature | What it captures |
|---|---|
| ip_fan_out | Avg users per IP — high = shared/proxy |
| user_ip_count | Avg IPs per user — high = distributed attack |
| max_user_ip_count | Max IPs by any single user — outlier |
| graph_density | Edge/node ratio — dense = coordinated attack |
| shared_endpoint_ips | Max IPs hitting same endpoint — synchronized bots |
| request_synchrony | Min stddev of timestamps per endpoint — bot coordination |
| ip_endpoint_spread | Avg endpoints per IP — low = focused attack |
| edge_count | Total graph edges — raw scale signal |

---

### Coordinator (`engine/coordinator/coordinator.py`)

**Input:** Results from all agents  
**Output:** `List[CoordinatorResult]` sorted by risk descending

**Scoring:**
$$\text{final\_score} = \frac{\sum_i w_i \cdot s_i}{\sum_i w_i}$$

**Current weights (research defaults — adjust as agents get validated):**
```python
weights = {
    "behavioral": 0.5,
    "semantic": 0.35,     # multiplied by semantic agent's own confidence value
    "spatiotemporal": 0.15,
}
```

**Verdict thresholds:**
| Score | Verdict |
|---|---|
| >= 0.8 | attack |
| >= 0.6 | suspicious |
| < 0.3 | normal |

---

## 5. Planned Agents (Product Phase — Do Not Build Until Paper Is Submitted)

### AI Agent Detection Agent
Detects LLM-driven bots — distinct from scripted bots.

**Key signals:**
- UA string entropy (LLM agents craft unusual, varied UAs)
- Parameter vocabulary richness (LLM agents use diverse parameter names unlike scripted bots)
- Session graph topology: LLM agents explore breadth-first; scripted bots enumerate depth-first
- Timing distribution: LLM agent timing follows token generation latency, not uniform intervals

### Tenant Isolation Agent
Detects cross-tenant resource probing in multi-tenant SaaS.

**Core logic:**
- Learn per-tenant ID namespace from normal traffic (e.g., tenant A's user IDs are 10000-19999)
- Flag requests where authenticated user in tenant A probes IDs in tenant B's namespace
- Extends semantic agent's `ownership_violation` rule with multi-tenant awareness

**Add to coordinator weights when implemented:**
```python
weights = {
    "behavioral": 0.4,
    "semantic": 0.25,
    "spatiotemporal": 0.15,
    "agent_detection": 0.10,
    "tenant_isolation": 0.10,
}
```

---

## 6. Product Architecture (Post-Paper)

### Deployment Modes

**Mode 1 — Passive (log-based, current)**
- Customer grants IAM read access to their S3 log bucket
- Your worker polls on schedule (hourly for basic tier, real-time Kinesis for premium)
- Zero-integration, no latency impact on customer's API
- Supports: detect + alert

**Mode 2 — Inline (proxy, blocking-capable)**
- Customer CNAME their API subdomain to your proxy endpoint
- Proxy: Envoy or Nginx + Lua filter
- Proxy forwards every request immediately (no latency added to legitimate traffic)
- Proxy mirrors request metadata to your real-time event bus (Kafka / Redis Stream)
- Supports: detect + alert + block

### Fast Path / Slow Path Design (Required for Blocking)

```
Incoming Request
      │
      ▼
Fast Path (< 5ms, synchronous, in-memory Redis)
  ├── Check per-user block key in Redis  →  if exists: return 429
  ├── Increment rate counter (sliding window in Redis)
  ├── Check known-bad IP blocklist
  └── Lightweight heuristic (request rate threshold, sequential ID gap)
      │
      │  if suspicious:
      ▼
Slow Path (async, full multi-agent pipeline, ~seconds)
  ├── Sessionization + Behavioral agent (IsolationForest)
  ├── Semantic agent (OpenAPI spec check)
  ├── Spatiotemporal agent (graph analysis)
  ├── Coordinator (weighted fusion)
  └── If verdict == "attack":
        → Write BLOCK_USER:{user_id}:{ttl} to Redis (fast path reads this next request)
        → Send alert to dashboard
        → Log to audit trail
```

**Critical rule:** Never make a synchronous LLM call in the request path. LLM reasoning is always async. Blocking decisions from LLM take effect on subsequent requests — acceptable because real attacks are sessions, not single requests.

### Tenant Architecture

Each customer is a fully isolated tenant:
- Separate S3 bucket access per tenant (IAM role per tenant)
- All data partitioned by `tenant_id` at rest
- Per-tenant configurable weights and thresholds in `configs/tenant_{id}.yaml`
- Per-tenant alert webhooks (Slack, PagerDuty, email)
- No tenant can see another tenant's data or models

### Pricing Model (SMB-Focused)

| Tier | Price | API Calls/Month | Mode | SLA |
|---|---|---|---|---|
| Starter | $99/mo | 5M | Log-based | Best effort |
| Growth | $299/mo | 50M | Log-based + real-time stream | 99.5% |
| Pro | $799/mo | 500M | Inline proxy + blocking | 99.9% |
| Enterprise | Custom | Unlimited | Everything + dedicated instance | 99.99% |

**COGS estimate at Growth tier (50M calls/month):**
- Storage: ~$1.50 (25GB logs at $0.023/GB S3)
- Compute: ~$3 (shared t3.medium across tenants)
- LLM reasoning (5% flagged, 500 tokens each): ~$10 (Claude Haiku)
- Total: ~$15/month per tenant → ~95% gross margin at $299

---

## 7. Dashboard Design

### Operations View (default landing)
- Live feed of sessions sorted by risk score (high to low)
- Flags expanded per session: `high_request_rate | sequential_id_access | model_anomaly`
- Attack type distribution chart (scraping / brute force / BOLA / impossible travel)
- Alert feed for `attack` verdicts with one-click block action

### Investigation View (click any user/IP)
- Full session timeline: timestamp, endpoint, status, risk contribution per event
- Agent score breakdown: behavioral=0.91, semantic=0.72, spatiotemporal=0.45
- LLM explanation in plain English: "User bot_user_1 accessed /api/users/1 through /api/users/847 sequentially over 4 minutes at 2.3 req/s, consistent with automated scraping."
- Historical sessions for that user/IP

### Policy View
- Block/alert/log thresholds per attack type (slider per verdict type)
- Allowlist management (trusted IPs, internal services)
- False positive log with one-click "mark as benign" to retrain
- Historical false positive rate chart

**For research demo:** Build in Streamlit.  
**For product:** Rebuild in React + FastAPI backend. Do not invest in the product dashboard until paper is submitted.

---

## 8. Implementation Checklist — Research Phase

```
IMMEDIATE (needed for paper):
[ ] evaluation/validate_behavioral.py         — F1 on synthetic data, IsoForest vs full agent
[ ] scripts/convert_cicids.py                 — CICIDS2017 → CanonicalEvent
[ ] evaluation/validate_full_pipeline.py      — ablation table on CICIDS data
[ ] Wire spatiotemporal into main.py          — build schema adapter, add to coordinator
[ ] Save/load trained IsolationForest         — joblib.dump/load, no retraining each run
[ ] Expand spec.yaml                          — add /api/login, /api/products, /api/search

PAPER CONTENT:
[ ] Ablation table (all 6 configurations)
[ ] ROC curves per agent + coordinator
[ ] Confusion matrix on CICIDS test split
[ ] Latency benchmark (time to verdict per session)
[ ] Comparison vs single IsolationForest baseline

PRODUCT (after paper submission):
[ ] Redis fast-path rule engine
[ ] Schema adapter for spatiotemporal agent
[ ] Streamlit dashboard for demo
[ ] configs/config.yaml — move thresholds out of source code
[ ] AI Agent Detection Agent
[ ] Tenant Isolation Agent
[ ] Inline proxy (Envoy/Nginx)
[ ] Blocking layer (Redis block keys)
```

---

## 9. Key Design Rules — For LLMs and New Contributors

1. **All agents consume `schemas.CanonicalEvent`** — do not create new event types in agent files.
2. **All agents return `schemas.AgentResult`** — coordinator depends on this. The semantic agent's `Dict` output is handled by coordinator internally; do not normalize it elsewhere yet.
3. **`timestamp` is always a `datetime` object** after normalization — never call `datetime.fromisoformat()` downstream of `normalizer.py`.
4. **`endpoint` is always a template** — `/api/users/{id}` not `/api/users/123`. Path params are in `path_params`.
5. **Agent weights are research parameters** — do not hardcode assumptions about them. Update in `coordinator.py` as validation results come in.
6. **LLM reasoning is always async** — never synchronous in any request path.
7. **`contamination=0.3` in behavioral agent is for synthetic data** — set to `0.01–0.05` for real traffic.
8. **Research first** — do not add product-layer features (blocking, proxy, dashboard) until `evaluation/validate_full_pipeline.py` produces an ablation table with real F1 scores.

---

## 10. File Map — What Each File Does

```
abuse-engine/
├── main.py                          Full pipeline entry point
├── spec.yaml                        OpenAPI spec for semantic agent — EXPAND THIS
├── LLM_CONTEXT.md                   This file — authoritative project context
│
├── schemas/
│   ├── event_schema.py              CanonicalEvent — shared input, never bypass
│   └── agent_result.py              AgentResult — shared output, never bypass
│
├── engine/
│   ├── normalization/normalizer.py  Raw JSON → CanonicalEvent
│   ├── pipeline/sessionizer.py      Events → Sessions (30-min gap = new session)
│   ├── agents/
│   │   ├── behavioral.py            IsolationForest + 6 rule flags
│   │   ├── semantic.py              5-rule OpenAPI spec checker + confidence system
│   │   └── spatio temporal/
│   │       ├── spatio_temporal_agent.py   Main + SpatioTemporalPipeline facade
│   │       ├── agent_framework.py         Directed graph execution engine
│   │       ├── models.py                  LOCAL CanonicalEvent (different field names — needs adapter)
│   │       ├── model_registry.py          IsolationForest lifecycle
│   │       ├── sliding_window.py          Thread-safe rolling time window
│   │       └── llm_agent_node.py          Optional LLM reasoning (swap Gemini → Claude)
│   └── coordinator/coordinator.py   Weighted fusion → CoordinatorResult
│
├── scripts/
│   ├── generate_synthetic_data.py   400-event mock dataset (4 attack types)
│   └── convert_cicids.py            [TO BUILD] CICIDS2017 → CanonicalEvent
│
├── evaluation/
│   ├── validate_behavioral.py       [TO BUILD] F1 on synthetic — IsoForest vs full agent
│   ├── validate_full_pipeline.py    [TO BUILD] Ablation table on CICIDS
│   └── generate_paper_figures.py    [TO BUILD] ROC curves, confusion matrices
│
├── datasets/                        git-ignored — regenerate locally
│   ├── mock_logs.json               synthetic data
│   └── cicids_canonical.json        [TO BUILD] converted CICIDS data
│
└── configs/                         [TO BUILD] move thresholds here from source
    └── config.yaml
```

---

*Last updated: March 2026. Maintained by Jeff Emerson Mathew, NIT Puducherry.*  
*Contact: jeff.emerson.mathew@gmail.com | Portfolio: aza3l.vercel.app*
