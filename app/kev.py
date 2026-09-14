"""
Loads the real, locally cached CISA KEV catalog (fetched by
scripts/fetch_kev.py) and exposes a simple lookup by CVE ID.
"""
import json
from dataclasses import dataclass

from app import config


@dataclass
class KevEntry:
    cve_id: str
    vulnerability_name: str
    date_added: str
    known_ransomware_campaign_use: str
    required_action: str
    due_date: str

    @property
    def is_ransomware_associated(self) -> bool:
        return self.known_ransomware_campaign_use == "Known"


def load_kev_index() -> dict[str, KevEntry]:
    if not config.KEV_CATALOG_JSON.exists():
        raise FileNotFoundError(
            f"{config.KEV_CATALOG_JSON} not found. Run scripts/fetch_kev.py first."
        )
    raw = json.loads(config.KEV_CATALOG_JSON.read_text(encoding="utf-8"))
    index = {}
    for v in raw.get("vulnerabilities", []):
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        index[cve_id] = KevEntry(
            cve_id=cve_id,
            vulnerability_name=v.get("vulnerabilityName", ""),
            date_added=v.get("dateAdded", ""),
            known_ransomware_campaign_use=v.get("knownRansomwareCampaignUse", "Unknown"),
            required_action=v.get("requiredAction", ""),
            due_date=v.get("dueDate", ""),
        )
    return index


if __name__ == "__main__":
    idx = load_kev_index()
    print(f"Loaded {len(idx)} KEV entries")
    ransomware = [k for k, v in idx.items() if v.is_ransomware_associated]
    print(f"{len(ransomware)} are flagged with known ransomware campaign use")

    import pandas as pd

    vulns = pd.read_csv(config.VULNERABILITIES_CSV)
    matched = vulns[vulns["cve"].isin(idx.keys())]
    print(f"\n{len(matched)}/{len(vulns)} vulnerabilities.csv CVEs are confirmed in the real CISA KEV catalog:")
    for _, row in matched.iterrows():
        entry = idx[row["cve"]]
        print(f"  {row['cve']}  ransomware={entry.is_ransomware_associated}  added={entry.date_added}")
