"""
Fetch CISA Known Exploited Vulnerabilities catalog.
Returns a DataFrame with CVE IDs and confirmed exploitation dates.
"""

import requests
import pandas as pd

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> pd.DataFrame:
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    data = response.json()

    df = pd.DataFrame(data["vulnerabilities"])
    df["dateAdded"] = pd.to_datetime(df["dateAdded"])
    df = df.rename(columns={
        "cveID": "cve_id",
        "dateAdded": "kev_date_added",
        "vulnerabilityName": "vuln_name",
        "shortDescription": "description",
        "requiredAction": "required_action",
        "dueDate": "due_date",
    })
    return df[["cve_id", "kev_date_added", "vuln_name", "description"]]


if __name__ == "__main__":
    df = fetch_kev()
    print(f"Fetched {len(df)} KEV entries")
    df.to_csv("../data/raw/kev.csv", index=False)
    print("Saved to data/raw/kev.csv")
