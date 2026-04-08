# APISentry — Fixed Issues

All fixes applied on 2026-04-08. Test suite: **32/32 passing** after every change.

---

## Bug A — VolumeAgent docstring had two stale values
**File:** `engine/agents/volume_agent.py`  
**Problem:** Docstring said `HIGH_RATE_ABSOLUTE raised to 300` and `DOMINANT_IP_RATIO > 60%`. Actual code enforced 450 and 90% respectively. Documentation drift — the LLM prompt and any human reader would see wrong calibration values.  
**Fix:** Updated both numbers in the module docstring to match the code (`450`, `> 90%`).

---

## Bug B — TemporalAgent imported numpy inside the per-IP loop
**File:** `engine/agents/temporal_agent.py`  
**Problem:** `import numpy as np` was inside `investigate()`, inside `for ip, timestamps in ip_timestamps.items()`. Python caches module imports after the first call but the lookup overhead on every iteration is wasteful, and the code pattern is fragile — any import error would surface mid-loop rather than at startup.  
**Fix:** Removed the inline import; added `import numpy as np` at the top of the file with the other imports.

---

## Bug C — AuthAgent `max_streak` metric was always 0
**File:** `engine/agents/auth_agent.py`  
**Problem:** `max_streak = 0` was set before the loop. The inner loop tracked a local variable `streak` but never assigned back to `max_streak`. Result: `ctx.raw_metrics["max_failure_streak"]` was always 0 regardless of actual streak lengths. The LLM verdict prompt and any logging received a permanently wrong metric. Detection was not affected (the `streaky_ips` list drove confidence correctly), but observability was broken.  
**Fix:** Added `max_streak = max(max_streak, streak)` at the end of the per-IP inner loop body, so the metric correctly reflects the longest streak seen in the batch.

---

## Bug D — TemporalAgent KS-test reference distribution was 20 synthetic values
**File:** `engine/agents/temporal_agent.py`, `engine/memory/shared_memory.py`  
**Problem:** `_HUMAN_IAT_SAMPLE` was a module-level list of 20 hand-written millisecond values. The KS-test comparing observed inter-arrival times against this distribution produced unreliable p-values — a 20-sample reference lacks statistical power. For CICIDS the `MIN_IAT_RESOLUTION_MS` guard fired first so this did not affect the current benchmark, but it would produce wrong results on real traffic.  
**Fix (two-part):**
1. **LTM:** Added `add_iat_samples()`, `get_iat_reference()`, and `has_iat_reference()` to `LongTermMemory`. The pool caps at 2 000 samples and requires ≥ 200 before it is considered ready.
2. **TemporalAgent `orient()`:** After each batch, computes all per-IP inter-arrival times and stores them in the LTM pool as a side effect.  
3. **TemporalAgent `investigate()`:** Uses `self.memory.ltm.get_iat_reference()` as the KS-test reference once 200+ samples have accumulated; falls back to `_HUMAN_IAT_SAMPLE` until then. The synthetic constant is retained as a cold-start fallback and is no longer the permanent reference.

---

## Bug E — MetaAgent conflict resolution was a no-op
**File:** `engine/coordinator/meta_agent.py`  
**Problem:** `_resolve_conflicts()` built `resolved = list(findings)`, detected conflict conditions, logged a debug message, and returned `resolved` completely unchanged. The docstring described escalating findings but nothing was actually modified. The compound signal rules still worked (they run before this method), but edge cases where one agent fired HIGH and a related agent was silent were never resolved.  
**Fix (three-part):**
1. Added `import dataclasses` to imports.
2. Added `_AGENT_DOMAINS` dict mapping each agent to its responsible threat types, and `_RELATED_THREATS` dict mapping each active threat to the set of co-occurring threats a silent agent may have missed. `BRUTE_FORCE` is intentionally excluded from `_RELATED_THREATS` — a targeted auth attack at low volume does not imply a volume or timing anomaly.
3. Rewrote `_resolve_conflicts()`: when an agent returns `threat_detected=False` at LOW confidence AND another agent returned a related threat at HIGH confidence, the silent agent's finding is replaced (via `dataclasses.replace`) with a MEDIUM-confidence escalation at 45% of the active threat's score. An `conflict_escalation:` indicator is appended to explain why the finding was modified. One escalation per silent agent per batch.

**Regression note:** The first implementation included `BRUTE_FORCE → {DOS}` in `_RELATED_THREATS`, which incorrectly escalated VolumeAgent in brute-force-only batches, turning the single-agent path into a diluted multi-agent fusion (fused conf 0.58 < threshold 0.60 → false negative). Removing that mapping restored 32/32 tests.

---

## Bug F — All endpoints in the processed CSV were `/unknown`
**File:** `scripts/prepare_cicids_dataset.py`  
**CSVs regenerated:** `datasets/processed/cicids2017_api_logs.csv`  
**Problem:** The script strips leading/trailing spaces from column names (`df.columns = [col.strip() for col in df.columns]`), so `' Destination Port'` becomes `'Destination Port'`. But `DST_PORT_CANDIDATES` only contained `'Dst Port'`, `' Destination Port'` (leading space, never matches after strip), and a duplicate `' Destination Port'`. The stripped form `'Destination Port'` was absent. Result: `dst_port_col = None` → every record's endpoint was assigned `/unknown`. All endpoint-level z-score analysis in VolumeAgent was silently a no-op (one bucket for all traffic), and compound signal detection lost the endpoint dimension entirely.  
**Fix:** Replaced `DST_PORT_CANDIDATES` with `['Destination Port', 'Dst Port', 'Port']` (stripped forms, no duplicates), then regenerated `cicids2017_api_logs.csv`. First data row is now `GET /port_22` instead of `GET /unknown`. All 2 830 743 records regenerated with correct port-based endpoints.

---

## Test result after all fixes

```
32/32 passed — all green ✓
```
