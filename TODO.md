# Abuse Engine — TODO

> Current baseline (full 2.8M, majority-label eval):
> Overall F1=0.679 | Precision=0.606 | Recall=0.772 | AUC=0.93
> Agent contribution: VolumeAgent=895, PayloadAgent=447, AuthAgent=299, TemporalAgent=131, SequenceAgent=1, GeoIPAgent=0

---

## Phase 5 — Dataset & Detection Fixes

### P5-1 — Fix DDoS substring bug in prepare script  `scripts/prepare_cicids_dataset.py`
**Bug:** `"DoS" in label` is checked before `"DDoS"`, so all 128,027 DDoS records silently
fall into the DoS bucket. The DDoS branch is dead code.  
**Fix:** Check `"DDoS"` first, then `"DoS"`.  
**Impact:** DDoS becomes a distinct category in the processed CSV; VolumeAgent can be
trained/evaluated against it separately.

### P5-2 — Add distributed flood detection to VolumeAgent  `engine/agents/volume_agent.py`
**Bug:** In `hypothesize()`, the guard `if unique_ips > MAX_IP_DIVERSITY(5) and dominant_ratio < DOMINANT_IP_RATIO(0.90)` returns `distributed_traffic_benign` and exits immediately — before any rate-based check runs. DDoS traffic with 14 source IPs (unique_ips=14 > 5) and dom_ratio=0.52 (< 0.90) hits this guard every time.  
**Fix two things:**
1. Relax the early guard: only return `distributed_traffic_benign` if per-IP rate is also low (e.g. no single IP has >50 requests). High per-IP rate with moderate diversity = distributed flood, not normal spread.
2. Add a secondary path: if total window request count is anomalously high AND it comes from a small cluster of IPs (e.g. 2–20), flag as `distributed_dos`. Confidence scaled by total rate z-score vs LTM baseline.  
**Impact:** Recovers ~161 missed DDoS attack batches; eliminates the FN cluster at batch ≥5000 in the detection timeline.

### P5-3 — Add Botnet detection  `engine/agents/`
**Situation:** 1,966 Botnet records exist in the processed CSV (Friday morning, batch ~5000).
Bot C2 traffic has low volume, regular intervals (keepalive), and unusual endpoints.  
**Fix:** TemporalAgent already scans for bot-like timing (regular inter-request intervals);
ensure its `BOT_ACTIVITY` finding is mapped correctly. Verify `_THREAT_LABEL_MAP` maps
`BOT_ACTIVITY → "Botnet"` (it does). The gap is likely that Botnet records are always a
minority in their batches — same majority-label evaluation artifact as Brute Force.  
**Action:** Confirm with a targeted batch analysis; may be resolved by P5-5 alone.

### P5-4 — Regenerate processed CSV  `scripts/prepare_cicids_dataset.py`
After P5-1 is fixed, re-run the prepare script to regenerate
`datasets/processed/cicids2017_api_logs.csv` with correct DDoS category.  
**Command:** `python scripts/prepare_cicids_dataset.py`

### P5-5 — Add secondary evaluation mode  `evaluation/evaluator.py` + standalone rescore script
**Problem:** Majority-label evaluation penalizes AuthAgent (brute force always minority),
Botnet detection, and any short-burst attack. 84 AuthAgent TP detections score as FP.  
**Key insight:** `verdicts_log` in the existing results JSON already stores
`ground_truth_attack_ratio` per batch. A standalone rescore script can compute the
secondary metric from `results/full_2.8M_phase4.json` without re-running the pipeline.  
**Fix:**
1. Add `scripts/rescore.py` — reads verdicts_log JSON, recomputes metrics at ≥5% threshold, prints comparison table, regenerates plots.
2. Add dual reporting to evaluator output so future runs show both modes inline.
Report both in the main output:
  - **Primary:** majority-label (conservative, standard IDS benchmark)
  - **Secondary:** any-attack ≥5% (breadth metric, shows short-burst detection, adds Brute Force as 4th category)  
**Note:** This is a measurement ruler change, not a detection change.

### P5-6 — Re-run full 2.8M pipeline after P5-1 through P5-5
**Command:** `python main.py --data datasets/processed/ --window 500 --max-records 0 --output results/full_2.8M_phase5.json`  
**Expected improvements:**
- DDoS FNs at batch 5000+ eliminated by distributed flood detection
- Brute Force appears as 4th threat category under ≥5% eval
- Botnet confirmed or shown to need P5-3 follow-up
- Overall F1 (primary) should recover toward ~0.82+
- F1 (secondary) should be higher still, showing AuthAgent credit

---

## Phase 6 — GeoIPAgent & SequenceAgent Validation (Separate Dataset)

### P6-1 — Source UNSW-NB15 dataset
CICIDS 2017 uses private IPs (172.16.x.x, 192.168.x.x) so GeoIPAgent always returns
NONE — by design, documented in `geo_agent.py`. UNSW-NB15 uses routable public IPs
from a live capture testbed and includes purpose-built sequential scan traffic.  
**Action:**
1. Download from https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. Write an ingestion adapter (similar to `cicids_ingestion.py`)
3. Download GeoLite2-City.mmdb from MaxMind (free with registration)

### P6-2 — Write UNSW-NB15 ingestion adapter  `engine/ingestion/unswnb15_ingestion.py`
Map UNSW-NB15 columns to `LogRecord` schema. Key columns: `srcip`, `sport`, `dstip`,
`dport`, `proto`, `state`, `dur`, `sbytes`, `label`, `attack_cat`.

### P6-3 — Run targeted evaluation on UNSW-NB15
Show GeoIPAgent and SequenceAgent firing. Frame in paper as:
*"Agent-specific validation: GeoIPAgent and SequenceAgent validated on UNSW-NB15
(n=X batches) which contains routable IPs and deliberate sequential scan traffic."*

---

## Evaluator Enhancements

### E-1 — Add per-agent precision/TP/FP to output  `evaluation/evaluator.py`
Show for each agent how many of their contributing batches were true positives.
Output format:
```
Agent Contribution Accuracy:
  VolumeAgent    TP=810  FP=85   precision=0.905
  PayloadAgent   TP=402  FP=45   precision=0.899
  AuthAgent      TP=... (majority-label)  /  TP=... (≥5% label)
```

### E-2 — Add DDoS to _THREAT_LABEL_MAP  `evaluation/evaluator.py`
Once P5-1 is done and the processed CSV has a genuine "DDoS" category, add:
`"DDOS": "DDoS"` to `_THREAT_LABEL_MAP` and add `DDOS` to ThreatType enum in `schemas/models.py`.
Also update `_AGENT_DOMAINS` in `meta_agent.py` to include `DDOS` under VolumeAgent.

### E-3 — Web Attack gap  `evaluation/evaluator.py`
673 Web Attack records (XSS + SQL injection) exist but no agent detects them and
`_THREAT_LABEL_MAP` has no entry for them. Currently silently scores as P=0 R=0 F1=0
in per-threat breakdown without any warning. Two options:
  a. Add `"WEB_ATTACK"` to ThreatType enum and teach PayloadAgent to detect
     unusual HTTP methods / XSS patterns in endpoints (future work)
  b. Add an explicit note in summary output: "Web Attack: no agent coverage (future work)"
Recommend (b) for now — document the gap explicitly rather than ignoring it.

---

## Code Quality

### Q-1 — XGBClassifier deprecated parameter  `engine/coordinator/meta_agent.py`
`XGBClassifier(use_label_encoder=False)` is deprecated in XGBoost ≥ 1.6 and removed
in XGBoost 2.x. Remove this parameter to prevent DeprecationWarning / crash on
newer XGBoost versions.

### Q-2 — prepare_cicids_dataset.py default path  `scripts/prepare_cicids_dataset.py`
`DATASET_DIR = "datasets"` but the script's `os.listdir()` is non-recursive — running
with default args finds zero CSVs (they're in `datasets/CICIDS2017/` subdirectory).
Default should be `"datasets/CICIDS2017"` or add a comment explaining the required
`--input_dir` argument.

---

## Paper / Documentation

### D-1 — Update CONTEXT.md with Phase 5 results
After P5-6 completes, update the results table with new F1 numbers (both eval modes).

### D-2 — Document dual evaluation methodology in CONTEXT.md
Explain why majority-label is primary and ≥5% is secondary. Reference Kitsune/FlowLens.

### D-3 — Note GeoIPAgent CICIDS limitation explicitly
Already in `geo_agent.py` docstring — surface this in paper as intentional graceful
degradation, validated separately on UNSW-NB15 (P6-3).

---

## Completed

- [x] Phase 4: PayloadAgent port scan detection (5 bugs fixed)
- [x] Phase 4: VolumeAgent IF threshold (-0.25)
- [x] Phase 4: Evaluator PORT_SCAN label map
- [x] Full 2.8M run completed: F1=0.679, AUC=0.93, 5 agents firing
- [x] Identified root cause of 557 FPs (AuthAgent majority-label artifact)
- [x] Identified root cause of FN cluster at batch 5000+ (DDoS multi-IP + substring bug)
- [x] **P5-1** — DDoS substring bug fixed in `scripts/prepare_cicids_dataset.py`
- [x] **Q-2** — `DATASET_DIR` default path fixed to `datasets/CICIDS2017`
- [x] **E-2** — `DDOS` added to `ThreatType` enum, `_AGENT_DOMAINS`, evaluator `_THREAT_LABEL_MAP`, and new compound rule (DDoS+BOT → botnet-driven DDoS)
- [x] **P5-2** — VolumeAgent 3-way benign guard; `distributed_dos_flood` hypothesis + investigate handler; new class constants `DDOS_MAX_UNIQUE_IPS=50`, `MAX_BENIGN_TOP_COUNT_DISTRIBUTED=25`
- [x] **P5-5** — Secondary ≥5% evaluation mode added to `Evaluator` (populates `precision_5pct`, `recall_5pct`, `f1_5pct`, `per_threat_5pct`) + `scripts/rescore.py` for rescoring existing result JSONs
- [x] **E-1** — Per-agent accuracy (`per_agent_accuracy`) computed in `Evaluator.compute()` and displayed in `summary()`
- [x] **E-3** — Web Attack gap note added to `summary()` per-threat section
- [x] **Q-1** — `use_label_encoder=False` removed from `XGBClassifier` in `meta_agent.py`
- [x] **P6-2** — UNSW-NB15 ingestion adapter created at `engine/ingestion/unswnb15_ingestion.py`
- [x] `main.py` updated to store `metrics_5pct`, `per_threat_5pct`, `per_agent_accuracy` in results JSON

**Pending user action:**
- [ ] **P5-4** — `python scripts/prepare_cicids_dataset.py` (regenerate CSV with DDoS fix)
- [ ] **P5-6** — `python main.py --data datasets/processed/ --window 500 --max-records 0 --output results/full_2.8M_phase5.json`
- [ ] **P5-3** — Post-run: verify Botnet batches in per-threat breakdown
- [ ] **P6-1** — Download UNSW-NB15 dataset + GeoLite2-City.mmdb
- [ ] **P6-3** — Run targeted UNSW-NB15 evaluation
- [ ] **D-1/D-2/D-3** — Update CONTEXT.md with Phase 5 results
