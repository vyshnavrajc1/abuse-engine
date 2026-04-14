# Abuse Engine

Multi-agent API abuse detection system. Detects DoS, credential stuffing, bot activity, and other API-level attacks by analysing gateway logs — no inline proxy, no code changes required by API owners.

Built as a research prototype for IEEE paper validation, with a production SaaS path planned post-publication.

---

## What It Does

Abuse Engine runs autonomous detection agents that each follow an OODA reasoning loop (Observe → Orient → Hypothesize → Investigate → Evaluate → Conclude). Agents share an evidence board, call statistical tools dynamically, and optionally consult a local LLM to produce a final verdict. A MetaAgent orchestrator fuses all agent findings into a single `FusionVerdict`.

**Agents implemented (Phase 1):**
- **VolumeAgent** — DoS / DDoS / scraping via rate and dominance analysis
- **TemporalAgent** — Bot periodicity detection via FFT/KS-test on inter-arrival times
- **AuthAgent** — Credential stuffing and brute force via auth failure pattern analysis

**Optional LLM integration:** any OpenAI-compatible endpoint (Ollama, vLLM, etc.). Falls back to rule-based detection if unavailable.

---

## Architecture

### Research Prototype — Phase 1 (current)

```
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                    CICIDS 2017 — Processed CSV                          │
 │              50 000 records  ·  100 batches  ·  Phase 1                 │
 └───────────────────────────┬─────────────────────────────────────────────┘
                             │
                             ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │  CICIDSIngestion  —  sliding window · 500 records / batch                 │
 └──────────────────┬────────────────────────────────────────────────────────┘
                    │ each batch
        ┌───────────┴──────────────────────────────────────────┐
        │                                                      │
        ▼                                                      ▼
 ┌──────────────────────────────────────┐    ┌────────────────────────────────────────────────────────────┐
 │   Shared Memory  (in-process dicts)  │    │   Detection Agents  —  ThreadPoolExecutor (parallel)        │
 │                                      │    │                                                            │
 │  STM  sliding window counters        │◄──►│  ┌─────────────────────────────────────────────────────┐  │
 │  LTM  per-IP rate baselines          │    │  │ VolumeAgent          OODA loop · max 3 iterations   │  │
 │  EB   Evidence Board (blackboard)    │◄──►│  │ dom_ratio · rate · latency guard                    │  │
 └──────────────────────────────────────┘    │  │ Detects: DoS · DDoS · Scraping                      │  │
                                             │  ├─────────────────────────────────────────────────────┤  │
 ┌──────────────────────────────────────┐    │  │ TemporalAgent        OODA loop · max 3 iterations   │  │
 │   Tool Registry                      │    │  │ FFT · KS-test · IAT resolution guard                │  │
 │                                      │◄···│  │ Detects: Bot activity · Off-hours access            │  │
 │  run_statistical_test                │    │  ├─────────────────────────────────────────────────────┤  │
 │  detect_periodicity                  │    │  │ AuthAgent            OODA loop · max 3 iterations   │  │
 │  query_historical_baseline           │    │  │ Failure streaks · success rate ratio                │  │
 │  post/read_evidence_board            │    │  │ Detects: Brute force · Credential stuffing          │  │
 └──────────────────────────────────────┘    │  └─────────────────────────────────────────────────────┘  │
                                             └───────────────────────────┬────────────────────────────────┘
 ┌──────────────────────────────────────┐                                │ AgentFinding ×3
 │   LLM  (optional)                    │◄·······························┤ per-agent conclude override
 │   Ollama · qwen2.5:7b                │◄·······························┐ meta-fusion override
 │   Falls back to rules on error       │                                │
 └──────────────────────────────────────┘                                ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │   MetaAgentOrchestrator                                                   │
 │                                                                           │
 │   1  Compound Signal Detection   (DoS + Bot Timing → Scraping Bot …)      │
 │         └─► 2  Weighted Confidence Fusion                                 │
 │                   attack thresh 0.60  ·  single-agent thresh 0.80         │
 │                   └─► 3  LLM Meta-Fusion  (optional, falls back on error) │
 └───────────────────────────────────────┬───────────────────────────────────┘
                                         │ FusionVerdict
                                         ▼
 ┌──────────────────────────┐
 │   Evaluator              │
 │   batch majority-label   │
 └──────────┬───────────────┘
            ▼
 ┌────────────────────────────────────────────────────────┐
 │  results/phase1.json                                   │
 │  Accuracy 92.22%  ·  Precision 1.00  ·  Recall 0.923  │
 │  F1 0.96  ·  FPR 0%  ·  32/32 tests passing           │
 └────────────────────────────────────────────────────────┘

 Legend:  ──►  data flow     ◄──►  read + write     ···►  optional / async
```

### Product Vision — Full System (future)

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │  ①  INGESTION                                                                   │
 │     AWS API Gateway  ·  Kong Gateway  ·  Nginx  ──►  Kafka Stream (real-time)   │
 └──────────────────────────────────────┬──────────────────────────────────────────┘
                                        │
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │  ②  PARSE & ENRICH                                                              │
 │     Universal Log Parser  ──►  Feature Extractor  ──►  Session Stitcher         │
 │     (rate counters · entropy · auth streaks)           (IP + UA + API Key)      │
 └───────────────────────┬─────────────────────────────────────────────────────────┘
                         │
          ┌──────────────┴──────────────────────────────┐
          │                                             │
          ▼                                             ▼ (async, hourly)
 ┌────────────────────────────────────┐   ┌─────────────────────────────────────┐
 │  ③  SHARED MEMORY — THREE TIERS   │   │  ④  ThreatIntelSyncer               │
 │                                    │   │     Background async task            │
 │  Redis  — STM                      │   │     AbuseIPDB · AlienVault OTX       │
 │    Active sessions · Evidence Board│   │     Feodo Tracker · GreyNoise        │
 │    TTL 1h · latency <1ms           │   │     → warms LTM reputation cache     │
 │                                    │   └──────────────┬──────────────────────┘
 │  PostgreSQL  — LTM                 │◄─────────────────┘  writes reputation
 │    IP/key/endpoint baselines       │
 │    Geo profiles · latency <10ms    │
 │                                    │
 │  S3 / Parquet  — Archive           │
 │    90-day log history              │
 │    Model training data             │
 └──────────────┬─────────────────────┘
                │  read + write
                ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │  ⑤  DETECTION AGENTS  —  parallel, trigger-based                               │
 │                                                                                 │
 │  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐  │
 │  │ VolumeAgent          │  │ TemporalAgent         │  │ AuthAgent            │  │
 │  │ DoS · DDoS · Scraping│  │ Bot Periodicity       │  │ Brute Force          │  │
 │  │ Isolation Forest     │  │ Off-hours access      │  │ Credential Stuffing  │  │
 │  │ EWMA · Z-score       │  │ FFT · KS-test · CUSUM │  │ Token sharing        │  │
 │  └──────────────────────┘  └──────────────────────┘  └──────────────────────┘  │
 │  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐  │
 │  │ SequenceAgent        │  │ PayloadAgent          │  │ GeoIPAgent           │  │
 │  │ BOLA · BFLA          │  │ SQLi · Path Traversal │  │ Impossible Travel    │  │
 │  │ Enumeration          │  │ XSS · Response size   │  │ VPN/Tor/Datacenter   │  │
 │  │ Markov · LSTM/GRU    │  │ anomaly               │  │ MaxMind GeoLite2     │  │
 │  └──────────────────────┘  └──────────────────────┘  └──────────────────────┘  │
 │  ┌──────────────────────────────────────────────────────────────────────────┐   │
 │  │ KnowledgeAgent  (passive — answers queries, does not produce verdicts)   │   │
 │  │ Active threat memory · cross-batch pattern synthesis                     │   │
 │  │ Confidence-gated write (conf > 0.85) · time-decay on old signatures      │   │
 │  └──────────────────────────────────────────────────────────────────────────┘   │
 └─────────────────────────────┬───────────────────────────────────────────────────┘
          ▲                    │ AgentFinding ×6
          │  ···  ⑥  Tool Registry  (dynamic calls during investigate())
          │       run_statistical_test · detect_periodicity · lookup_geoip
          │       query_ip_reputation · calculate_similarity · get_session_history
          │       query_knowledge_base · update_knowledge_base
          │
          │  ···  LLM  (GPU server — Ollama / vLLM · qwen2.5:7b)
          │       Per-agent verdict override · falls back to rules on error
          │
          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │  ⑦  MetaAgentOrchestrator  —  LangGraph                                        │
 │                                                                                 │
 │   Compound Signal Detection  (5+ compound rules)                                │
 │         └─►  XGBoost Stacking Fusion  (trained on agent confidence vectors)     │
 │                   └─►  Conflict Resolution + Active Re-investigation            │
 │                               └─►  LLM Authoritative Verdict                   │
 └───────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ FusionVerdict
                    ┌────────────────────┼─────────────────────┐
                    │                    │                      │
                    ▼                    ▼                      ▼
 ┌──────────────────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐
 │  ⑧a  ALERTING            │  │  ⑧b  ENFORCEMENT    │  │  ⑧c  STORAGE            │
 │                          │  │                     │  │                          │
 │  Dashboard               │  │  WAF Rule Injection │  │  Threat DB               │
 │  (Next.js + D3.js)       │  │  AWS WAF · Cloudflare  │  Case history            │
 │                          │  │  5–30s to block     │  │  Evidence chains         │
 │  Alerts                  │  │                     │  │  Agent performance logs  │
 │  Slack · PagerDuty       │  │  Redis Blocklist    │  │                          │
 │  Email                   │  │  Gateway plugin     │  │                          │
 │                          │  │  <1ms enforcement   │  │                          │
 └──────────────────────────┘  └─────────────────────┘  └──────────────────────────┘

 Legend:  ──►  data flow     ◄──►  read + write     ···  optional / async / dynamic
```

---

## Directory Structure

```
abuse-engine/
├── datasets/
│   ├── CICIDS2017/              # Raw CICIDS 2017 CSVs (not in git)
│   ├── CICIDS2017-ML/           # ML-ready variant CSVs (not in git)
│   └── processed/               # API-normalised output from prepare script
│       └── cicids2017_api_logs.csv
├── engine/
│   ├── agents/                  # VolumeAgent, TemporalAgent, AuthAgent, BaseAgent
│   ├── coordinator/             # MetaAgentOrchestrator
│   ├── ingestion/               # CICIDSIngestion — batch iterator over processed CSV
│   ├── llm/                     # LLMClient + prompt templates (Ollama / OpenAI-compat)
│   ├── memory/                  # SharedMemory: STM, LTM, EvidenceBoard
│   ├── normalization/           # (stub — future universal log parser)
│   ├── pipeline/                # (stub — future streaming pipeline)
│   ├── tests/                   # run_tests.py — 32 tests, no pytest dependency
│   └── tools/                   # ToolRegistry (statistical tests, periodicity, evidence board)
├── evaluation/
│   └── evaluator.py             # Batch-level majority-label metrics
├── results/                     # JSON output from evaluation runs
├── schemas/
│   └── models.py                # Pydantic schemas (LogRecord, AgentFinding, FusionVerdict)
├── scripts/
│   └── prepare_cicids_dataset.py  # Converts raw CICIDS CSVs to API-normalised format
├── main.py                      # CLI entry point
├── requirements.txt
├── CONTEXT.md                   # Full implementation + architecture reference (keep updated)
└── NOTES.md                     # Code review findings and decisions log
```

---

## Dataset

Uses **CICIDS 2017** — 2.83M network flow records converted to API-like log format.

**Prepare the dataset** (run once after downloading raw CSVs into `datasets/CICIDS2017/`):
```bash
python scripts/prepare_cicids_dataset.py
```
This produces `datasets/processed/cicids2017_api_logs.csv` with fields: `timestamp`, `ip`, `method`, `endpoint`, `status`, `response_size`, `latency`, `user_agent`, `attack_category`, `is_attack`.

**Class distribution (full 2.83M records):**

| Category | Count |
|---|---|
| Benign | 2,273,097 |
| DoS | 380,688 |
| Port Scan | 158,930 |
| Brute Force | 15,342 |
| Botnet | 1,966 |
| Web Attack | 673 |
| Infiltration | 36 |
| Heartbleed | 11 |

---

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Running

**Rule-based detection (no dependencies beyond pip install):**
```bash
python main.py \
  --data datasets/processed/ \
  --window 500 \
  --max-records 50000 \
  --output results/phase1.json \
  --warmup-batches 10
```

**With local LLM via Ollama:**
```bash
# Install Ollama and pull model (once)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b

python main.py \
  --data datasets/processed/ \
  --window 500 \
  --max-records 50000 \
  --output results/phase1_llm.json \
  --warmup-batches 10 \
  --llm-url http://localhost:11434/v1 \
  --llm-model qwen2.5:7b
```

**CLI flags:**

| Flag | Default | Description |
|---|---|---|
| `--data` | `datasets/processed/` | Path to processed CSV directory |
| `--window` | `500` | Records per batch |
| `--max-records` | `0` (all) | Limit total records processed |
| `--output` | `results/phase1.json` | Path for metrics JSON output |
| `--warmup-batches` | `10` | First N batches used for baseline learning only (not scored) |
| `--llm-url` | *(none)* | OpenAI-compatible LLM endpoint — omit for rule-based only |
| `--llm-model` | `qwen2.5:7b` | Model name for LLM endpoint |
| `--verbose` / `-v` | off | Debug logging + print all verdicts |

**Run the test suite:**
```bash
python -m engine.tests.run_tests
```

---

## Current Results (Phase 1 — rule-based, 50k records)

| Metric | Value |
|---|---|
| Accuracy | 92.22% |
| Precision | 1.0000 |
| Recall | 0.9231 |
| F1 | 0.9600 |
| False Positive Rate | 0% |
| Test suite | 32/32 passing |