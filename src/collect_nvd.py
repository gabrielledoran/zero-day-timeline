"""
Fetch CVE metadata from NVD API v2 for a list of CVE IDs.
NVD rate limit: 5 requests/30s without API key. Add your key to go faster.
Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
"""

import time
import requests
import pandas as pd
from tqdm import tqdm

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str, api_key: str = None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    params = {"cveId": cve_id}
    response = requests.get(NVD_BASE, params=params, headers=headers, timeout=30)
    response.raise_for_status()
    data = response.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return vulns[0]["cve"]


def extract_cvss_v3(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if not cvss_list:
        return {}
    m = cvss_list[0]["cvssData"]
    return {
        "cvss_score": m.get("baseScore"),
        "attack_vector": m.get("attackVector"),
        "attack_complexity": m.get("attackComplexity"),
        "privileges_required": m.get("privilegesRequired"),
        "user_interaction": m.get("userInteraction"),
        "scope": m.get("scope"),
        "cvss_severity": m.get("baseSeverity"),
    }


def fetch_cve_batch(cve_ids: list, api_key: str = None, delay: float = 6.0) -> pd.DataFrame:
    """
    Fetch a list of CVE IDs from NVD. Without an API key, NVD limits to
    5 req/30s — delay=6.0s is safe. With a key, set delay=0.6.
    """
    records = []
    for cve_id in tqdm(cve_ids, desc="Fetching NVD"):
        try:
            cve = fetch_cve(cve_id, api_key)
            if cve is None:
                continue
            published = cve.get("published", "")
            row = {"cve_id": cve_id, "nvd_published": pd.to_datetime(published)}
            row.update(extract_cvss_v3(cve))

            # CWE
            weaknesses = cve.get("weaknesses", [])
            if weaknesses:
                descs = weaknesses[0].get("description", [])
                row["cwe"] = descs[0]["value"] if descs else None

            records.append(row)
        except Exception as e:
            print(f"  Error fetching {cve_id}: {e}")
        time.sleep(delay)

    return pd.DataFrame(records)


if __name__ == "__main__":
    # Quick test with a small sample
    sample_ids = ["CVE-2021-44228", "CVE-2022-26134", "CVE-2023-23397"]
    df = fetch_cve_batch(sample_ids)
    print(df.to_string())
