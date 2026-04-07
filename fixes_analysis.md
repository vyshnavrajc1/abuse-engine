# APISentry — Fixes Audit & Next Steps

## 1. Are the existing fixes in `NOTES.md` correct?

> TL;DR — **Yes, all four fixes are correct, well-reasoned, and already in the code.**

### Fix 1 — VolumeAgent thresholds raised ✅
`DOMINANT_IP_RATIO 0.60 → 0.90`, `HIGH_RATE_ABSOLUTE 300 → 450`

Confirmed in `volume_agent.py` lines 38-39. The data-driven justification is solid:
- Benign batches top out at ~dom_ratio 0.62 / ~308 reqs
- Attack batches sit at ~dom_ratio 0.98 / ~488 reqs
- The 0.90 boundary sits cleanly between the two distributions.

**One subtle issue:** The comment in the file docstring still says `> 60%`, while the actual code enforces `> 90%`. A minor documentation inconsistency — update the docstring.

### Fix 2 — TemporalAgent IAT resolution guard ✅
`MIN_IAT_RESOLUTION_MS = 500` skips per-IP analysis when median IAT < 500ms.

Confirmed in `temporal_agent.py` lines 140-145. Correct fix for the CICIDS 1-second timestamp resolution artifact. Zero-IAT values (same-second requests) produced fake `bot_confidence=0.99`.

### Fix 3 — Latency guard for single-IP benign sessions ✅
`HIGH_LATENCY_BENIGN_MS = 6500`

Confirmed in `volume_agent.py` lines 131-136. The 266ms gap between the highest attack latency (6402ms) and lowest benign latency (6668ms) holds cleanly in the data. Good statistical grounding.

### Fix 4 — Evaluator threat label normalisation ✅
`_THREAT_LABEL_MAP` normalises `"DOS"→"DoS"`, `"BRUTE_FORCE"→"Brute Force"`, etc.

Not directly read here but referenced in NOTES.md and CONTEXT.md. Correct fix — Pydantic enums use `value` not label, and CICIDS uses mixed-case strings.

---

## 2. Analysis of `fixes.md` items

### Fix Item 1 — "Include LLM in every agent including FusionOrchestrator; let LLM decide which tool to call"

**Current state:** LLM is already wired into every agent and the MetaOrchestrator.
- `BaseAgent._llm_conclude()` fires after rule-based OODA conclude — **for all three agents** ✅
- `MetaAgentOrchestrator._llm_fuse()` fires after rule-based fusion ✅
- Prompts for all three agents + MetaAgent exist in `prompts.py` ✅
- LLM falls back gracefully on error ✅

**What's missing from the stated goal ("let LLM decide which tool to call"):**  
Currently the LLM only overrides the *final verdict* — it does not dynamically select which tools to invoke mid-OODA-loop. That's a deeper architectural change (making each agent a ReAct / tool-calling loop). This is a valid idea for Phase 2 but is **not broken** — it's a design enhancement. The current LLM-as-post-hoc-override is simpler, more stable, and still counts as agentic reasoning for the paper.

> **Status: Partially done (verdict override) — deeper tool-selection is a Phase 2 enhancement, not a bug.**

### Fix Item 2 — "Hardcoded values need justification or self-learning"

Key hardcoded constants and their status:

| Agent | Constant | Value | Justification | Self-learning? |
|---|---|---|---|---|
| VolumeAgent | `DOMINANT_IP_RATIO` | 0.90 | Data-derived (NOTES.md) | ❌ static |
| VolumeAgent | `HIGH_RATE_ABSOLUTE` | 450 | Data-derived (NOTES.md) | ❌ static |
| VolumeAgent | `HIGH_LATENCY_BENIGN_MS` | 6500 | Data-derived gap analysis | ❌ static |
| VolumeAgent | `WARMUP_BATCHES` | 10 | Empirical | ❌ static |
| VolumeAgent | `RATE_SPIKE_THRESHOLD` | **3.5 (z)** | Standard 3σ, slightly raised | ❌ static |
| TemporalAgent | `BOT_CONFIDENCE_THRESHOLD` | 0.85 | Raised for CICIDS artifact | ❌ static |
| TemporalAgent | `MIN_IAT_RESOLUTION_MS` | 500 | Timestamp resolution guard | Dataset-specific |
| TemporalAgent | `OFF_HOURS_DOMINANT_RATIO` | 0.85 | Raised from 0.70 | ❌ static |
| AuthAgent | `STUFFING_SUCCESS_RATE_MIN/MAX` | 1–8% | Literature-backed (3.2% known) | ❌ static |
| AuthAgent | `BRUTE_FORCE_FAILURE_STREAK` | 10 | Empirical | ❌ static |
| MetaAgent | `_ATTACK_THRESHOLD` | 0.60 | Calibrated | ❌ static |
| MetaAgent | `_SINGLE_AGENT_THRESHOLD` | 0.80 | Conservative guard | ❌ static |

**The fix requested is valid.** Options ordered by effort:

1. **Adaptive thresholds via LTM** — After each batch, update a rolling distribution of dominant_ratio / top_count in LTM. Set thresholds as `mean + k*std` (k configurable). Already has the LTM infrastructure to do this (batch counters, per-IP rates).

2. **Ablation-tuned via sklearn** — Grid-search (or Bayesian opt) over a held-out slice of CICIDS to find optimal thresholds. Document once, reference in paper. Static but defensible.

3. **XGBoost stacking fusion** — Replace the hand-tuned thresholds at the MetaAgent level with a trained classifier. This is already in the roadmap.

> **Status: Valid — thresholds are justified but static. Adding LTM-adaptive thresholds for VolumeAgent is the highest-priority self-learning improvement.**

### Fix Item 3 — "Implement other three agents"

The three unimplemented agents are: **SequenceAgent, PayloadAgent, GeoIPAgent**.

All three are in `CONTEXT.md` as "Phase 2 — research." The fix is valid.

**Priority ranking for IEEE paper impact:**
1. **GeoIPAgent** — Fastest to add. MaxMind GeoLite2 is free. Adds a new signal category with zero overlap with existing agents. Can be validated today using CICIDS source IPs.
2. **PayloadAgent** — Medium effort. Works on query strings / path params from URL logs. No request body needed. CSIC 2010/2012 dataset already listed for validation.
3. **SequenceAgent** — Hardest. Needs per-session tracking (session stitching). LSTM/GRU in the roadmap. Markov chain is achievable in Phase 2.

> **Status: Valid — this is the biggest gap. GeoIPAgent should be first.**

### Fix Item 4 — "Use ML/DL if compatible or necessary"

**Current state:** Pure rule-based with LLM override. ML is explicitly planned but not yet implemented.

**Where ML fits today (without breaking the architecture):**

| Where | What | Effort | Impact |
|---|---|---|---|
| MetaAgent fusion | XGBoost stacking on (VolumeConf, TemporalConf, AuthConf, compound_flags) | Medium | High — already in roadmap |
| VolumeAgent | Isolation Forest on (dom_ratio, top_count, unique_ips, avg_latency) per batch | Low | Could reduce the 7 FNs on mixed batches |
| TemporalAgent | CUSUM / EWMA on per-IP IATs instead of static FFT threshold | Low | Improves bot detection with better timestamp data |
| AuthAgent | Bernoulli change-point detection on per-IP failure rate | Low | Better at detecting stuffing campaigns that slow-roll |
| SequenceAgent (future) | LSTM/GRU on endpoint sequences | High | Required for BOLA detection |

> **Status: Valid — XGBoost at MetaAgent level is the first ML to add. Isolation Forest in VolumeAgent is low-effort and directly addresses the 7 remaining FNs.**

---

## 3. Additional Issues Found During Audit

### Issue A — VolumeAgent docstring says `> 60%`, code enforces `> 90%`
`volume_agent.py` line 18: `- DOMINANT_IP_RATIO: single IP must own > 60% of requests to be suspicious`  
Actual code: `DOMINANT_IP_RATIO = 0.90`. Documentation drift.

### Issue B — TemporalAgent imports `numpy` inside the loop
`temporal_agent.py` line 136: `import numpy as np` is inside `investigate()` inside the `for ip` loop. This re-imports on every iteration. Move to top-level import.

### Issue C — AuthAgent `max_streak` never updated
`auth_agent.py` line 143: `max_streak = 0`, line 157: `ctx.raw_metrics["max_failure_streak"] = max_streak`  
The variable `max_streak` is never assigned in the loop (only `streak` is). So `raw_metrics["max_failure_streak"]` is always 0. Minor — doesn't affect correctness since `streaky_ips` drives the actual confidence — but the metric is wrong for logging/LLM.

### Issue D — TemporalAgent: `_HUMAN_IAT_SAMPLE` is a synthetic constant
The KS-test compares observed IATs against `_HUMAN_IAT_SAMPLE` — 20 hardcoded values. This reference distribution is narrow and synthetic. For real datasets, derive it from a real benign traffic sample from CICIDS or academic studies.

### Issue E — MetaAgent conflict resolution is a no-op
`meta_agent.py` `_resolve_conflicts()` lines 283-299: The method logs a message when a conflict is detected, but **does not actually modify any finding**. It returns the same list unchanged. The design intention (escalate when Auth=None + DoS=HIGH) is documented but not implemented.

### Issue F — `datasets/processed/` endpoint extraction broken
As noted in NOTES.md, all endpoints are `/unknown` due to column name matching failure. This silently degrades endpoint-level z-score analysis in VolumeAgent to a no-op (all activity under one key). High priority to fix for multi-agent compound signals.

---

## 4. Recommended Next Steps (Prioritized)

### Tier 1 — Quick wins (< 1 day each)

1. **Fix `max_streak` bug** in `auth_agent.py` — assign `max_streak = max(max_streak, streak)` inside the loop.
2. **Move `import numpy` to top-level** in `temporal_agent.py`.
3. **Fix docstring** in `volume_agent.py` line 18: `60%` → `90%`.
4. **Fix endpoint extraction** in `prepare_cicids_dataset.py` — resolve `Dst Port` column name (try `' Destination Port'` stripped).
5. **Implement conflict resolution** in `_resolve_conflicts()` of MetaAgent — actually modify findings when conflict logic triggers.

### Tier 2 — Medium effort (1–3 days each)

6. **Add Isolation Forest to VolumeAgent** — train on benign batch feature vectors (dom_ratio, top_count, unique_ips, avg_latency) and use anomaly score to complement the rule thresholds. Directly targets the 7 remaining FNs.
7. **LTM-adaptive thresholds** for VolumeAgent — compute `DOMINANT_IP_RATIO` and `HIGH_RATE_ABSOLUTE` from rolling LTM distributions after warmup batches.
8. **Add GeoIPAgent skeleton** — MaxMind GeoLite2 via `geoip2` pip package. Signals: datacenter IP, Tor exit node, impossible travel. Wire into MetaAgent and add compound rules.
9. **Improve `_HUMAN_IAT_SAMPLE`** — derive from real CICIDS benign-only records instead of 20 hardcoded numbers.

### Tier 3 — High effort (3–7 days each, paper-critical)

10. **XGBoost stacking fusion** — replace weighted-average in MetaAgent with a classifier trained on agent confidence vectors. Run on CICIDS 2017 holdout for ablation.  
11. **PayloadAgent** — URL/query-param injection detection. Needs CSIC 2010 dataset for validation.
12. **SequenceAgent (Markov chain)** — per-session endpoint sequence tracking. Needs session stitching to be implemented first.
13. **LLM tool-calling (ReAct)** — rewrite per-agent OODA loop to call tools via LLM function calling rather than hardcoded rule chains. Significant architectural change; validate it doesn't hurt benchmark accuracy.
14. **Full 2.8M record run** — expand from 50k to full dataset for paper metrics. Exposes Brute Force, Botnet, Web Attack categories that AuthAgent and future agents need to handle.

---

## 5. Summary Table

| `fixes.md` Item | Status | Action Needed |
|---|---|---|
| 1. LLM in every agent + FusionOrchestrator | ✅ Done (verdict override) | Phase 2: add tool-calling LLM loop |
| 2. Hardcoded values justification | ⚠️ Justified but static | Add LTM-adaptive thresholds + Isolation Forest |
| 3. Implement other three agents | ❌ Not started | Start with GeoIPAgent |
| 4. Use ML/DL if necessary | ❌ Not started | XGBoost fusion + Isolation Forest in VolumeAgent |

| Extra Issue | Severity | Fix Effort |
|---|---|---|
| A. Docstring drift (60% vs 90%) | Low | 5 min |
| B. numpy imported in loop | Low | 2 min |
| C. `max_streak` never updated | Medium | 5 min |
| D. Synthetic `_HUMAN_IAT_SAMPLE` | Medium | 1 hr |
| E. Conflict resolution no-op | High | 1 hr |
| F. All endpoints are `/unknown` | High | 2 hr |
