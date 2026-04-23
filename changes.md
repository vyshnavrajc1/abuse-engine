# Changes Made to Improve GeoIP Detection

This document summarizes the changes made to the Abuse Engine to improve the detection capabilities of the `GeoIPAgent` on the CTU-13 dataset, specifically fixing the issue where it was contributing 0 True Positives (TPs) and missing the botnet spatial spread. It also includes the integration of user-provided changes.

## 1. Engine & Schema Fixes (Agent Refinements)

### `schemas/models.py`
- **Added:** `tenant_home_country: str = ""` field to the `LogRecord` dataclass.
- **Why:** This ensures the dataset's native home country (e.g., `'CZ'` for CTU13) can propagate natively down to the agents even if it isn't specified as a command-line argument.

### `engine/ingestion/cicids_ingestion.py`
- **Modified:** `_row_to_record` function now extracts `"tenant_home_country"` from the raw pandas DataFrame row.
- **Why:** Safely loads the `tenant_home_country` from the CSV into the `LogRecord` while remaining backward-compatible with CICIDS CSVs that omit this column.

### `engine/agents/geo_agent.py`
- **Decreased Thresholds:**
  - `FOREIGN_CONCENTRATION_THRESHOLD` lowered from 0.60 to 0.40.
  - `DISTRIBUTED_FOREIGN_THRESHOLD` lowered from 0.70 to 0.20.
  - **Why:** To make the agent sensitive enough to catch botnet traffic that is highly distributed but where the home country (like CZ in CTU13) still makes up a large proportion of the batch.
- **Added Botnet Spatial Diversity Check in `investigate()`:**
  - Added new configurable constants (`BOTNET_SPREAD_MIN_UNIQUE_IPS`, `BOTNET_SPREAD_MIN_COUNTRIES`, `BOTNET_SPREAD_DIVERSITY_RATIO`).
  - Added a check to detect highly widespread, coordinated traffic characteristic of botnets (many unique IPs spread across multiple countries).
  - **Why:** Address the architectural blindness where Czech botnet IPs were incorrectly evaluated purely on total percentage metrics rather than spatial diversity.
- **Auto-Detection in `orient()`:**
  - Updated the logic to dynamically fall back to reading `tenant_home_country` from the `LogRecord` if `memory.ltm._tenant_home_country` is empty/not set.

---

## 2. Main Runner Changes (User Provided)

### `main.py`
- **Added `--home-country` argument parsing:**
  - Added CLI flag `--home-country` with default `""` (Lines 246-251).
  - Passed `home_country=args.home_country` to the internal `run` call (Line 264).
- **Added parameter to `run` function:**
  - Added `home_country: str = ""` to the `run` signature (Line 58).
- **Added Logging and LTM Registration:**
  - Added logging output to confirm the tenant home country (Lines 69-70 `logger.info("  Tenant home country: %s", home_country)`).
  - Directly sets the shared memory (LTM) value `memory.ltm._tenant_home_country = home_country` if provided, allowing the `GeoIPAgent` to pick it up on its very first `orient` cycle (Lines 75-76).
  - **Why:** This adds explicit top-level control over the tenant's expected location. It complements the auto-detection perfectly.

---

## 3. Dataset Preprocessing

### `scripts/prepare_ctu13_dataset.py` (New / Updated by User)
- **Included script for CTU13 processing:**
  - Transforms the raw `capture20110818.binetflow` into a structured CSV format matching the `cicids_ingestion` schema.
  - Hardcodes the `tenant_home_country` to `"CZ"` for the CVUT network since the dataset revolves predominantly around Czech university botnet traffic.
  - Adds ground-truth mapping for `is_attack`, `label`, and `attack_category` (flagging "Botnet" labels).
