"""
Fetch the real CISA Known Exploited Vulnerabilities (KEV) catalog and cache it
locally as data/kev_catalog.json.

Source: https://github.com/cisagov/kev-data (official CISA mirror)
"""
import json
import sys
from pathlib import Path

import requests

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
OUT_PATH = Path(__file__).resolve().parent.parent / "data" / "kev_catalog.json"


def fetch_kev() -> dict:
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    print(f"Fetching KEV catalog from {KEV_URL} ...")
    catalog = fetch_kev()
    vulns = catalog.get("vulnerabilities", [])
    print(f"Fetched {len(vulns)} KEV entries (catalogVersion={catalog.get('catalogVersion')}, "
          f"dateReleased={catalog.get('dateReleased')})")

    ransomware_count = sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known")
    print(f"  -> {ransomware_count} entries flagged knownRansomwareCampaignUse=Known")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    print(f"Saved to {OUT_PATH}")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        print(f"ERROR fetching KEV catalog: {e}", file=sys.stderr)
        sys.exit(1)
