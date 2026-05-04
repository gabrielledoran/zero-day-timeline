# Notebooks

## 01 — Data Collection (`01_data_collection.ipynb`)

Builds the master CVE dataset by fetching and merging three public data sources.

**Process:**
1. Fetches the full CISA KEV catalog via `src/collect_kev.py` — 1,568 entries at time of collection
2. Batch-fetches NVD metadata for each KEV CVE via `src/collect_nvd.py` — CVSS v3.1 scores, attack vector, complexity, privilege requirements, user interaction, scope, CWE
3. Fetches EPSS scores and percentile rankings for each CVE via `src/collect_epss.py`
4. Merges the three sources on CVE ID, computes `days_to_exploit` (NVD publish → KEV date added), and filters out 195 records where NVD publish date was after the KEV exploitation date (data quality artifacts)

**Output:** `data/processed/cve_master.csv` — 1,371 CVEs, all confirmed exploited

**NVD rate limits:** Without an API key, data collection takes ~2 hours (5 req/30s). With a free key, ~12 minutes.

## 02 — EDA (`02_eda.ipynb`)

Exploratory analysis of the time-to-exploit distribution and its relationship to CVE characteristics.

- Days-to-exploit distribution (linear and log scale) — highly right-skewed, spans from 1 day to 6,000+ days
- Median exploitation window by CVSS severity tier
- Median exploitation window by attack vector (NETWORK vs. LOCAL vs. other)
- EPSS score distribution across the dataset
- Correlation between CVSS score and log(days_to_exploit)

## 03 — Modeling (`03_modeling.ipynb`)

Trains an XGBoost regressor to predict time-to-exploitation from CVE features available at disclosure.

**Features:** CVSS score, EPSS score, EPSS percentile, attack vector, attack complexity, privileges required, user interaction, scope, CVSS severity (categorical features label-encoded)

**Target:** `log(1 + days_to_exploit)` — log-transformed to reduce skew

**Split:** 1,096 training / 275 test (80/20)

**Results:**
- R² = 0.083
- MAE = 854 days (on original scale)

Feature importance analysis shows which CVE properties best predict exploitation speed. EPSS contributes the strongest signal, followed by CVSS-derived features.
