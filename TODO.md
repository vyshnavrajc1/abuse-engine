# APISentry — Project Roadmap

Target: B2B SaaS API abuse detection · IEEE paper as credibility vehicle.
Detection engine is the product. Everything here builds toward a self-calibrating,
multi-agent framework that does not require manual threshold tuning per deployment.

Current state: 3 agents (Volume, Temporal, Auth) · 32/32 tests · 92.22% accuracy
on CICIDS 2017 · 0% FPR · 7 FNs on mixed batches.

---

## Phase 1 — Self-learning foundation
> Goal: eliminate all hardcoded calibration constants. Every threshold the system
> enforces should be derived from the data it has seen, not set by hand.

### 1.1 — LTM batch-level distribution tracking
**File:** `engine/memory/shared_memory.py`

LTM currently tracks per-endpoint rates and per-IP counts but has no aggregate
batch-level statistics. Agents need the distribution of their own key metrics
(dom_ratio, top_count, off_hours_ratio, etc.) over historical batches to set
adaptive thresholds.

- Add `record_batch_stats(agent_name: str, stats: Dict[str, float])` to LTM
  — stores a rolling window of batch-level metric vectors per agent (cap at 500 batches)
- Add `get_batch_distribution(agent_name: str, metric: str) → (mean, std)` to LTM
  — returns mean and std of a named metric across stored batches
- Add variance stabilization check: `is_distribution_stable(agent_name: str) → bool`
  — returns True when rolling variance of key metrics has not changed > 5% for
  the last 10 batches. This replaces the hardcoded `WARMUP_BATCHES = 10` guard.
  When stable, warmup is complete regardless of batch count.

### 1.2 — Per-agent adaptive thresholds
**Files:** `engine/agents/volume_agent.py`, `engine/agents/temporal_agent.py`

Replace hardcoded calibration constants with data-derived values computed after
warmup. Domain-definition constants (BRUTE_FORCE_FAILURE_STREAK, OFF_HOURS hours,
STUFFING_SUCCESS_RATE ranges) stay fixed — those encode threat semantics, not
traffic profiles. Everything else adapts.

**VolumeAgent — add `_update_adaptive_thresholds()`:**
- `DOMINANT_IP_RATIO`     ← `ltm_dom_ratio_mean + 2.0 * ltm_dom_ratio_std`
- `HIGH_RATE_ABSOLUTE`    ← `ltm_top_count_mean  + 2.0 * ltm_top_count_std`
- `HIGH_LATENCY_BENIGN_MS`← `ltm_avg_latency_mean + 3.0 * ltm_avg_latency_std`
- Hardcoded values become cold-start fallbacks only.
- Call after each batch once `ltm.is_distribution_stable("VolumeAgent")` is True.

**TemporalAgent — add `_update_adaptive_thresholds()`:**
- `OFF_HOURS_DOMINANT_RATIO` ← `ltm_off_hours_mean + 2.0 * ltm_off_hours_std`
- `BOT_CONFIDENCE_THRESHOLD` stays fixed (semantic: what counts as bot-like)
  but `MIN_PERIODIC_IPS` ← derived from observed periodicity rate in benign batches.

**AuthAgent — no calibration constants need adapting** (all are domain definitions
or literature-backed ranges). Leave as-is.

### 1.3 — Self-determined agent weights in MetaAgent
**File:** `engine/coordinator/meta_agent.py`

The hardcoded `_AGENT_WEIGHTS = {VolumeAgent: 1.0, TemporalAgent: 0.9, AuthAgent: 1.0}`
must go. Weights should reflect each agent's actual precision on this deployment's traffic.

- Add `record_agent_outcome(agent_name, predicted_attack, final_verdict_attack)` to LTM
  — called by MetaAgent after each batch using the LLM-confirmed verdict as pseudo-label
  (in evaluation mode: use ground truth label)
- Add `get_agent_precision(agent_name) → float` to LTM
  — rolling precision over last 100 batches where agent fired
- In MetaAgent `_fuse()`: replace `_AGENT_WEIGHTS` dict lookup with
  `self.memory.ltm.get_agent_precision(f.agent_name)` dynamically
- Fallback: uniform weight (1.0) until agent has ≥ 20 outcome records

### 1.4 — KnowledgeAgent (infrastructure, not a detector)
**File:** `engine/agents/knowledge_agent.py` (new)

Passive advisory agent. Produces no verdicts. Answers queries from other agents
during their `orient()` step. Runs async background warm-up on startup.

**Data it holds (in LTM, keyed by `knowledge:*`):**
- Known-bad IPs (seeded from local cache file, future: AbuseIPDB/GreyNoise API)
- Per-IP threat history: how many times flagged, last seen, confidence trajectory
- Per-batch cross-agent pattern synthesis: escalating dom_ratio over 3+ batches = emerging attack
- OWASP API Top 10 pattern library (static, loaded from JSON at startup)

**Interface other agents use:**
```python
# In any agent's orient():
prior = self.tools.call("query_knowledge_base", ip=top_ip)
# Returns: {"known_bad": bool, "prior_confidence": float, "history_summary": str}
```

**Background warm-up (async thread on SharedMemory init):**
- Loads `datasets/threat_intel_cache.json` if present (offline-first)
- Optionally hits AbuseIPDB/GreyNoise if API key configured (env var)
- Posts pre-emptive evidence to board before batch processing starts:
  `knowledge:known_bad:{ip}` with confidence from history

**Cross-tenant stub (interface only, implementation deferred):**
- `get_cross_tenant_reputation(ip)` → stub returning None
- Designed so future shared Redis call slots in here without touching agent code

**Tools to register in ToolRegistry:**
- `query_knowledge_base(ip, endpoint=None)` → prior dict
- `update_knowledge_base(ip, outcome, confidence)` → updates history

---

## Phase 2 — Orchestrator as a reasoning agent
> Goal: the orchestrator stops being a static router and becomes the planning agent
> in the system. It observes the batch, decides which agents are warranted, and
> explains its dispatch decision.

### 2.1 — Smart dispatch with triage step
**File:** `engine/coordinator/meta_agent.py`

Add a `_triage(records) → DispatchPlan` method that fires before `_dispatch()`.

**Triage observations (< 1ms):**
- `n_4xx`: count of 401/403 status codes
- `rough_dom_ratio`: top IP count / total (fast, no full Counter needed — sample first 50 records)
- `ts_span_ms`: max(timestamp) - min(timestamp)
- `distinct_endpoints`: set size of endpoint field (fast cardinality estimate)
- `known_bad_present`: KnowledgeAgent.has_known_bad_in_batch(batch) — O(n) bloom filter check

**Dispatch rules (thresholds from LTM, not hardcoded):**
```
n_4xx > 0                          → dispatch AuthAgent
rough_dom_ratio > ltm_dispatch_vol → dispatch VolumeAgent
ts_span_ms > 200 AND any_ip_dense  → dispatch TemporalAgent
distinct_endpoints > ltm_dispatch_ep → dispatch PayloadAgent (Phase 3)
known_bad_present                  → dispatch ALL agents regardless
```
`ltm_dispatch_vol` starts at 0.50 (lower than the detection threshold — warrant
investigation sooner) and adapts to `ltm_dom_ratio_mean + 1σ` after warmup.

**DispatchPlan dataclass:**
```python
@dataclass
class DispatchPlan:
    agents: List[str]           # names of agents to dispatch
    reasoning: List[str]        # one line per decision (included in FusionVerdict trace)
    skip_reasons: Dict[str,str] # agent_name → reason skipped
```

**Changes to `run()`:**
- Call `_triage()` first
- Pass `plan` to `_dispatch()` which only submits listed agents
- Include `plan.reasoning` + `plan.skip_reasons` in `FusionVerdict.explanation`

### 2.2 — LangGraph orchestrator (preparatory refactor, not replacement)
**File:** `engine/coordinator/meta_agent.py`

`langgraph` is already installed. The current ThreadPoolExecutor dispatch works fine
for Phase 1/2. This item is about structuring `MetaAgentOrchestrator` so that
migrating to a LangGraph `StateGraph` in Phase 4 requires only wiring, not rewriting.

- Define `OrchestratorState` TypedDict with fields matching what `run()` accumulates:
  `(records, triage_plan, findings, evidence, verdict)`
- Document which methods map to which LangGraph nodes (triage → dispatch → fuse →
  conflict → llm_fuse) so the migration path is explicit
- **No actual LangGraph wiring yet** — that belongs in Phase 4

---

## Phase 3 — New detection agents
> Add agents in this order. Each inherits Phase 1's adaptive threshold framework
> automatically — they call `self.memory.ltm.get_batch_distribution()` the same
> way existing agents do.

### 3.1 — PayloadAgent (port scan / endpoint enumeration)
**File:** `engine/agents/payload_agent.py` (new)
**Priority: HIGH — validates immediately on CICIDS PortScan (158k records, currently undetected)**

CICIDS-compatible signal: count distinct endpoint targets per IP per batch.
A single IP hitting `/port_22`, `/port_80`, `/port_443`, `/port_8080`, `/port_3306`
in a single window = systematic port enumeration = Port Scan.

Key metric: `endpoint_entropy_per_ip` — Shannon entropy of endpoint distribution for each IP.
High entropy (many unique targets) + high request count → scan.
Adaptive threshold: `ltm_entropy_mean + 2σ` for flagging.

Production extension: URL query-param injection detection (SQLi, path traversal).
No new dependencies needed (regex patterns, no external dataset required for Phase 3).

New ThreatType to add to `schemas/models.py`: `PORT_SCAN`, `ENUMERATION`.

**Compound rule to add in MetaAgent:**
`PORT_SCAN + DOS → NETWORK_SWEEP` (high volume + systematic port enumeration)

### 3.2 — SequenceAgent (endpoint sequence / BOLA detection)
**File:** `engine/agents/sequence_agent.py` (new)
**Priority: MEDIUM — BOLA is OWASP API #1 but needs session stitching**

Per-IP endpoint transition sequences within a batch. Build a Markov-style
transition frequency map: `{(endpoint_a, endpoint_b): count}`.

Flag IPs whose transition sequences show:
- Low-probability transitions (never seen in benign LTM)
- Sequential numeric resource enumeration: `/port_20` → `/port_21` → `/port_22`
- High self-loop ratio on the same endpoint (hammering one resource)

Requires: session grouping by IP within the batch (already available via STM).
Does NOT require cross-batch session stitching for CICIDS (IP is stable per attack).

LTM stores: transition probability table per endpoint pair (benign baseline).
Adaptive: probabilities update from benign batches during warmup.

New ThreatType: `ENUMERATION` (shared with PayloadAgent), `SEQUENCE_ABUSE`.

### 3.3 — GeoIPAgent (skeleton + RFC1918 heuristics)
**File:** `engine/agents/geoip_agent.py` (new)
**Priority: LOW for CICIDS, HIGH for production**

`maxminddb` is already installed. Needs MaxMind GeoLite2 DB file (free download).

CICIDS behavior: all source IPs are RFC1918 (192.168.x.x / 172.16.x.x).
Agent correctly produces near-zero confidence on CICIDS — that is correct behavior.

Production signals: datacenter ASN, Tor exit node, impossible travel
(same API key from two continents < 10 min apart), new country for established key.

Compound rule addition: `GEO_DATACENTER + VOLUME_DOS → DISTRIBUTED_DATACENTER_ATTACK`.
New ThreatType: `GEO_ANOMALY`.

---

## Phase 4 — ML layer
> Replace hand-tuned fusion and detection with trained models.
> All of these require Phase 1 (adaptive thresholds) to be complete first —
> the ML models train on the same LTM distributions the thresholds use.

### 4.1 — Isolation Forest in VolumeAgent
**Targets the 7 remaining false negatives on mixed batches.**

During warmup: accumulate `(dom_ratio, top_count, unique_ips, avg_latency)` feature
vectors from benign batches (identified by low confidence score + no indicators).
After warmup: fit `sklearn.ensemble.IsolationForest` on these vectors.
Per batch: compute anomaly score. Negative score adds `+0.15` to `ctx.confidence_score`
even when rule thresholds aren't crossed.

Store fitted model in LTM (serialize with `joblib`, already installed).

### 4.2 — XGBoost stacking fusion in MetaAgent
**Replaces the weighted average. Paper's ablation contribution.**

Feature vector: `(vol_conf, temp_conf, auth_conf, payload_conf, seq_conf, n_active_agents,
compound_flag_scraping, compound_flag_stuffing, compound_flag_brute, known_bad_prior)`.

Training: evaluation mode accumulates `(feature_vector, ground_truth_label)` pairs.
After 50+ labeled batches, fit `sklearn.ensemble.HistGradientBoostingClassifier`
(equivalent to XGBoost, no extra dependency).

Fallback: if model not yet trained, use existing weighted average.
Serialize trained model to `results/fusion_model.pkl`.

Ablation study: run CICIDS with rules-only / rules+LTM-adaptive / full-ML and
compare precision/recall/F1 — this is the paper's Table 3.

### 4.3 — CUSUM change-point detection in TemporalAgent
**Removes the last static bot-confidence threshold.**

Replace the static `BOT_CONFIDENCE_THRESHOLD` guard with a CUSUM detector on
per-IP IAT sequences. CUSUM detects a sustained downward shift in IAT mean
(requests getting faster = automation accelerating) without requiring a hard threshold.

`scipy.stats` already available. Manual CUSUM: 2 parameters (`k` slack, `h` threshold)
both derived from LTM IAT baseline distribution.

---

## Phase 5 — Paper completion
> Run order matters: 4.2 (XGBoost) must be done before running the full dataset,
> so the ablation table is complete in one pass.

### 5.1 — Full 2.8M record evaluation
**Pre-requisites:** Bug F fix done ✓ (endpoints are now /port_X), all Phase 1–4 complete.

Run `main.py --max-records 0` (no limit) against the regenerated CSV.
This exposes: Brute Force (15k), Botnet (2k), Web Attack (673), Infiltration (36),
Heartbleed (11) — categories the current 50k run never reaches.

Expected: AuthAgent recall improves significantly on Brute Force.
PayloadAgent catches most Port Scan. SequenceAgent catches sequential enumeration.

### 5.2 — Ablation study
Three runs, same 2.8M dataset:
1. Rules-only (disable LLM, disable ML, use cold-start thresholds)
2. Rules + adaptive thresholds + smart dispatch (Phase 1–2)
3. Full system (Phase 1–4, all agents, ML fusion)

Metrics per run: Accuracy, Precision, Recall, F1, FPR, per-category breakdown.
This table is the paper's core empirical contribution.

### 5.3 — Paper sections that map to code
- Section 3 (Architecture): OODA loop, CONTEXT.md diagrams, agent domain table
- Section 4 (Adaptive Framework): LTM distribution tracking, threshold derivation,
  agent weight self-determination, smart dispatch
- Section 5 (Evaluation): 5.2 ablation table, CICIDS 2017 setup, batch-level eval methodology
- Section 6 (Limitations): CICIDS timestamp resolution, GeoIP CICIDS gap, LLM latency on critical path

---

## Implementation order (recommended)

| # | Item | Effort | Unlocks |
|---|---|---|---|
| 1 | LTM batch stats + variance stabilization (1.1) | 3 hr | everything adaptive |
| 2 | VolumeAgent adaptive thresholds (1.2) | 2 hr | removes 3 hardcoded constants |
| 3 | TemporalAgent adaptive thresholds (1.2) | 1 hr | removes 2 hardcoded constants |
| 4 | Self-determined agent weights (1.3) | 2 hr | removes _AGENT_WEIGHTS |
| 5 | KnowledgeAgent skeleton + tools (1.4) | 4 hr | smart dispatch priors, data moat foundation |
| 6 | Smart orchestrator dispatch (2.1) | 3 hr | latency improvement, agentic orchestrator |
| 7 | PayloadAgent — port scan / enumeration (3.1) | 3 hr | detects 158k CICIDS PortScan records |
| 8 | SequenceAgent — Markov transitions (3.2) | 4 hr | BOLA detection, paper novelty |
| 9 | Isolation Forest in VolumeAgent (4.1) | 3 hr | fixes 7 remaining FNs |
| 10 | XGBoost stacking fusion (4.2) | 4 hr | paper ablation table |
| 11 | CUSUM in TemporalAgent (4.3) | 2 hr | removes last static threshold |
| 12 | GeoIPAgent skeleton (3.3) | 2 hr | production credibility |
| 13 | Full 2.8M run (5.1) | setup | paper metrics |
| 14 | Ablation study (5.2) | 1 day | paper Table 3 |

---

## Constants that must never be adaptive (domain definitions — cite, don't tune)
| Constant | Agent | Rationale |
|---|---|---|
| `BRUTE_FORCE_FAILURE_STREAK = 10` | AuthAgent | Semantic definition of brute force |
| `STUFFING_SUCCESS_RATE_MIN/MAX = 1–8%` | AuthAgent | Published threat intel (3.2% known rate) |
| `OFF_HOURS = 00:00–05:59 UTC` | TemporalAgent | Time-of-day definition |
| `MIN_EVENTS_FOR_ANALYSIS = 10` | TemporalAgent | Statistical minimum (not traffic-profile specific) |
| `MAX_ITERATIONS = 3` | BaseAgent | OODA loop guard — architectural |
| `_ATTACK_THRESHOLD = 0.60` | MetaAgent | Kept as floor; XGBoost supersedes it in Phase 4 |
