# Zero-Day Weaponization Timeline

**Research question:** Given a CVE's publicly available characteristics at the time of disclosure, how long until it is actively exploited in the wild — and what factors drive that window?

## Results

| Metric | Value |
|---|---|
| Dataset | 1,371 confirmed exploited CVEs |
| Sources | NVD API, CISA KEV, FIRST EPSS |
| Model | XGBoost regression |
| R² (test set) | 0.083 |
| MAE | 854 days |

The low R² is itself a finding. CVE metadata available at disclosure time — CVSS scores, attack vector, complexity, scope — explains only ~8% of the variance in how quickly a vulnerability gets exploited. The remaining variance is driven by factors outside the data: threat actor priorities, exploit kit development timelines, target sector exposure, and geopolitical context. This has a direct implication for defenders: metadata-based scoring systems like CVSS are necessary but not sufficient for prioritizing patch urgency.

EPSS (the machine-learned exploitation probability score from FIRST.org) contributes the most predictive signal of any single feature, which is consistent with its design as a purpose-built exploit forecasting system.

## Data Sources

| Source | What It Provides | Access |
|---|---|---|
| [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) | CVSS v3.1 scores, attack vector, complexity, privilege requirements, scope, CWE | Free REST API; optional API key for higher rate limits |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploitation dates for ~1,200+ CVEs | Public JSON feed |
| [FIRST EPSS API](https://www.first.org/epss/api) | Daily probability of exploitation within 30 days + percentile ranking | Free REST API |

## Pipeline

```
CISA KEV  ──┐
NVD API   ──┼──▶  src/collect_*.py  ──▶  data/processed/cve_master.csv  ──▶  notebooks/
EPSS API  ──┘
```

1. `src/collect_kev.py` fetches the full CISA KEV catalog (confirmed exploited CVEs with dates)
2. `src/collect_nvd.py` batch-fetches NVD metadata for each KEV CVE
3. `src/collect_epss.py` fetches current EPSS scores for each CVE
4. `01_data_collection.ipynb` merges the three sources, filters for data quality, and outputs `cve_master.csv`
5. `02_eda.ipynb` explores the distribution of time-to-exploit by severity, attack vector, and EPSS tier
6. `03_modeling.ipynb` trains and evaluates an XGBoost regressor

## Notebooks

| Notebook | Description |
|---|---|
| [`01_data_collection.ipynb`](notebooks/01_data_collection.ipynb) | Fetches and merges NVD, KEV, and EPSS data into a single master table. Final dataset: 1,371 CVEs after removing 195 records where NVD publish date was after KEV exploitation date. |
| [`02_eda.ipynb`](notebooks/02_eda.ipynb) | Distributions of days-to-exploit (linear and log scale), breakdowns by CVSS severity tier and attack vector, EPSS score patterns across the dataset. |
| [`03_modeling.ipynb`](notebooks/03_modeling.ipynb) | Feature engineering, XGBoost training on log-transformed target, evaluation on held-out test set, feature importance analysis. |

## Repository Structure

```
zero-day-timeline/
├── notebooks/
│   ├── 01_data_collection.ipynb
│   ├── 02_eda.ipynb
│   └── 03_modeling.ipynb
├── src/
│   ├── collect_nvd.py      # NVD API client
│   ├── collect_kev.py      # CISA KEV fetcher
│   └── collect_epss.py     # EPSS API client
├── data/
│   ├── raw/                # Raw API responses (gitignored)
│   └── processed/          # cve_master.csv (gitignored)
├── research/
│   └── Comprehensive Review of Machine Learning for Cybersecurity.pdf
├── requirements.txt
└── README.md
```

## Setup

```bash
conda create -n zerodaytl python=3.11
conda activate zerodaytl
pip install -r requirements.txt
```

No API keys required — all three data sources are publicly accessible without authentication. Adding a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) reduces the full data collection run from ~2 hours to ~12 minutes.

## Methodology Notes

**Dataset scope:** The dataset contains only CVEs confirmed exploited in CISA KEV. It does not include the full population of CVEs, most of which are never exploited. This means the model predicts *how fast* exploitation occurs given that it will occur, not *whether* it will occur. A survival model (Weibull or Cox PH) with right-censored unexploited CVEs would be a natural extension.

**Outcome variable:** `days_to_exploit` = NVD publish date → CISA KEV `date_added`. This is a conservative measure; actual first exploitation likely precedes KEV cataloging.

**EPSS timing:** EPSS scores are fetched at analysis time, not at CVE disclosure. For retrospective CVEs, EPSS reflects current (not historical) exploitation probability. Historical EPSS scores by date are available via the EPSS API for future work.
