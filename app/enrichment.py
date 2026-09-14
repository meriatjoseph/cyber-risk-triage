"""
Joins the structured CSV records together and cross-references vulnerability
CVEs against two independent sources of "is this actually exploited":

1. The real CISA KEV catalog (government-confirmed active exploitation)
2. threat_intelligence.csv (named campaigns/actors relevant to this
   environment, including the synthetic MDR advisory's five campaigns)

Both are exact-match structured lookups (CVE string equality) -- no
embeddings involved here. A CVE only counts as "campaign matched" if the
threat_intelligence row's matched_cve_or_control field equals a real vuln CVE
in this environment; the 15 intentional noise rows in that CSV target CVEs
that don't exist in vulnerabilities.csv and will correctly produce zero
matches.
"""
from dataclasses import dataclass, field

import pandas as pd

from app import config
from app.ingestion import load_dataframes
from app.kev import KevEntry, load_kev_index


@dataclass
class ThreatMatch:
    intel_id: str
    threat_actor: str
    campaign_name: str
    target_sector: str
    target_region: str
    exploit_maturity: str
    active_last_seen: str
    ransomware_association: bool
    confidence: str
    summary: str


@dataclass
class EnrichedRisk:
    # asset
    asset_id: str
    asset_name: str
    asset_type: str
    environment: str
    owner_team: str
    business_service: str
    internet_exposed: bool
    asset_criticality: str
    data_classification: str
    edr_installed: bool
    last_seen_days: int
    location: str
    vendor_product: str
    # vulnerability
    vuln_id: str
    vulnerability_name: str
    cve: str
    severity: str
    cvss: float
    exploit_available_csv: bool
    patch_available: bool
    days_open: int
    asset_exposure: str
    auth_required: bool
    affected_component: str
    # KEV cross-reference (real catalog)
    kev_listed: bool
    kev_ransomware_known: bool
    kev_date_added: str | None
    kev_required_action: str | None
    # threat intel cross-reference
    threat_matches: list[ThreatMatch] = field(default_factory=list)
    # business service
    business_owner: str = ""
    business_impact: str = ""
    customer_facing: bool = False
    compliance_scope: str = ""
    revenue_impact: str = ""
    rto_hours: float | None = None
    risk_appetite: str = ""

    @property
    def has_campaign_match(self) -> bool:
        return len(self.threat_matches) > 0

    @property
    def any_ransomware_signal(self) -> bool:
        if self.kev_ransomware_known:
            return True
        return any(m.ransomware_association for m in self.threat_matches)


def _yn(val) -> bool:
    return str(val).strip().lower() == "yes"


def build_enriched_risks() -> list[EnrichedRisk]:
    dfs = load_dataframes()
    assets = dfs["assets"]
    vulns = dfs["vulnerabilities"]
    intel = dfs["threat_intelligence"]
    services = dfs["business_services"].set_index("business_service")

    kev_index: dict[str, KevEntry] = {}
    if config.KEV_CATALOG_JSON.exists():
        kev_index = load_kev_index()

    # group threat intel by matched CVE for O(1) lookup (exact string match only)
    intel_by_cve: dict[str, list[pd.Series]] = {}
    for _, row in intel.iterrows():
        cve = str(row["matched_cve_or_control"]).strip()
        intel_by_cve.setdefault(cve, []).append(row)

    risks: list[EnrichedRisk] = []
    for _, v in vulns.iterrows():
        asset_rows = assets[assets["asset_id"] == v["asset_id"]]
        if asset_rows.empty:
            continue  # orphaned vuln row, skip defensively
        a = asset_rows.iloc[0]

        svc = services.loc[a["business_service"]] if a["business_service"] in services.index else None

        cve = str(v["cve"]).strip()
        kev_entry = kev_index.get(cve)

        matches = []
        for row in intel_by_cve.get(cve, []):
            matches.append(
                ThreatMatch(
                    intel_id=row["intel_id"],
                    threat_actor=row["threat_actor"],
                    campaign_name=row["campaign_name"],
                    target_sector=row["target_sector"],
                    target_region=row["target_region"],
                    exploit_maturity=row["exploit_maturity"],
                    active_last_seen=row["active_last_seen"],
                    ransomware_association=_yn(row["ransomware_association"]),
                    confidence=row["confidence"],
                    summary=row["summary"],
                )
            )

        risk = EnrichedRisk(
            asset_id=a["asset_id"],
            asset_name=a["asset_name"],
            asset_type=a["asset_type"],
            environment=a["environment"],
            owner_team=a["owner_team"] if pd.notna(a["owner_team"]) else "(unassigned)",
            business_service=a["business_service"],
            internet_exposed=_yn(a["internet_exposed"]),
            asset_criticality=a["criticality"],
            data_classification=a["data_classification"],
            edr_installed=_yn(a["edr_installed"]),
            last_seen_days=int(a["last_seen_days"]),
            location=a["location"],
            vendor_product=a["vendor_product"],
            vuln_id=v["vuln_id"],
            vulnerability_name=v["vulnerability_name"],
            cve=cve,
            severity=v["severity"],
            cvss=float(v["cvss"]),
            exploit_available_csv=_yn(v["exploit_available"]),
            patch_available=_yn(v["patch_available"]),
            days_open=int(v["days_open"]),
            asset_exposure=v["asset_exposure"],
            auth_required=_yn(v["auth_required"]),
            affected_component=v["affected_component"],
            kev_listed=kev_entry is not None,
            kev_ransomware_known=bool(kev_entry and kev_entry.is_ransomware_associated),
            kev_date_added=kev_entry.date_added if kev_entry else None,
            kev_required_action=kev_entry.required_action if kev_entry else None,
            threat_matches=matches,
            business_owner=svc["business_owner"] if svc is not None else "",
            business_impact=svc["business_impact"] if svc is not None else "",
            customer_facing=_yn(svc["customer_facing"]) if svc is not None else False,
            compliance_scope=svc["compliance_scope"] if svc is not None and pd.notna(svc["compliance_scope"]) else "None",
            revenue_impact=svc["revenue_impact"] if svc is not None else "Unknown",
            rto_hours=float(svc["rto_hours"]) if svc is not None and pd.notna(svc["rto_hours"]) else None,
            risk_appetite=svc["risk_appetite"] if svc is not None else "",
        )
        risks.append(risk)

    return risks


if __name__ == "__main__":
    risks = build_enriched_risks()
    print(f"Built {len(risks)} enriched (asset, vulnerability) risk records")
    kev_hits = [r for r in risks if r.kev_listed]
    print(f"  {len(kev_hits)} are confirmed in the real CISA KEV catalog")
    campaign_hits = [r for r in risks if r.has_campaign_match]
    print(f"  {len(campaign_hits)} have >=1 threat-intelligence campaign match")
    ransomware_hits = [r for r in risks if r.any_ransomware_signal]
    print(f"  {len(ransomware_hits)} carry a ransomware-association signal")
