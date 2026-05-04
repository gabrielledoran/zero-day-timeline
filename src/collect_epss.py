"""
Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org API.
EPSS gives a daily probability score that a CVE will be exploited in the wild.
We want the score at or near the NVD publish date.
"""

import requests
import pandas as pd
from datetime import date

EPSS_BASE = "https://api.first.org/data/v1/epss"


def fetch_epss_current(cve_ids: list) -> pd.DataFrame:
    """Fetch current EPSS scores for a list of CVE IDs (batched)."""
    records = []
    # API supports up to 100 CVEs per request
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i+100]
        params = {"cve": ",".join(batch)}
        response = requests.get(EPSS_BASE, params=params, timeout=30)
        response.raise_for_status()
        data = response.json().get("data", [])
        records.extend(data)

    df = pd.DataFrame(records)
    if df.empty:
        return df
    df = df.rename(columns={"cve": "cve_id", "epss": "epss_score", "percentile": "epss_percentile"})
    df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce")
    df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce")
    return df[["cve_id", "epss_score", "epss_percentile"]]


if __name__ == "__main__":
    sample = ["CVE-2021-44228", "CVE-2022-26134"]
    df = fetch_epss_current(sample)
    print(df)
