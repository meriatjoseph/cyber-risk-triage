"""
Joins the structured CSV records together and cross-references vulnerability
CVEs against two independent sources of "is this actually exploited":

1. The real CISA KEV catalog (government-confirmed active exploitation)
2. threat_intelligence.csv (named campaigns/actors relevant to this
   environment, including the synthetic MDR advisory's five campaigns)

Both are structured lookups -- no embeddings involved here. A CVE counts
as "campaign matched" if the threat_intelligence row's matched_cve_or_control
field equals a real vuln CVE in this environment. 16 of the 40 intel rows
don't match anything: 15 are intentional industry noise and correctly
produce zero matches.

The 16th is a near-miss, and it's why exact matching alone isn't enough:
TI-3012 ("HR Data Theft") lists CVE-2025-0333, but the finding on
hr-portal-prod is recorded as CVE-SYN-2025-0333 -- the same bug, the same
"file upload" description, just with the synthetic-ID prefix. Pure string
equality silently dropped it. So a second pass compares normalised IDs
(see normalize_cve) and keeps any hit as a *possible* match: flagged
near_miss=True, shown to the reader as "verify", and scored at reduced
confidence (app/scoring.py) rather than either trusted outright or
thrown away.
"""
import re
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
    # True when the intel row's CVE only matches this finding after
    # normalisation (e.g. CVE-2025-0333 vs CVE-SYN-2025-0333). A human should
    # confirm it's the same vulnerability before acting on it.
    near_miss: bool = False
    listed_cve: str = ""


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
        return any(not m.near_miss for m in self.threat_matches)

    @property
    def has_possible_campaign_match(self) -> bool:
        return any(m.near_miss for m in self.threat_matches)

    @property
    def any_ransomware_signal(self) -> bool:
        if self.kev_ransomware_known:
            return True
        return any(m.ransomware_association for m in self.threat_matches)


def _yn(val) -> bool:
    return str(val).strip().lower() == "yes"


_SYN_PREFIX_RE = re.compile(r"^CVE-SYN-", re.I)


def normalize_cve(cve_id: str) -> str:
    """'CVE-SYN-2025-0333' -> 'CVE-2025-0333'; whitespace/case folded.
    Only used to *suggest* a possible match, never to confirm one."""
    return _SYN_PREFIX_RE.sub("CVE-", str(cve_id).strip().upper())


def find_threat_matches(cve: str, intel: pd.DataFrame) -> list[ThreatMatch]:
    """Exact matches first; then rows whose ID only matches after
    normalize_cve(), flagged near_miss=True."""
    matches = []
    target_norm = normalize_cve(cve)
    for _, row in intel.iterrows():
        listed = str(row["matched_cve_or_control"]).strip()
        if listed == cve:
            near_miss = False
        elif normalize_cve(listed) == target_norm:
            near_miss = True
        else:
            continue
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
                near_miss=near_miss,
                listed_cve=listed,
            )
        )
    matches.sort(key=lambda m: m.near_miss)
    return matches


def build_enriched_risks() -> list[EnrichedRisk]:
    dfs = load_dataframes()
    assets = dfs["assets"]
    vulns = dfs["vulnerabilities"]
    intel = dfs["threat_intelligence"]
    services = dfs["business_services"].set_index("business_service")

    kev_index: dict[str, KevEntry] = {}
    if config.KEV_CATALOG_JSON.exists():
        kev_index = load_kev_index()

    # group threat intel by *normalised* ID so each vuln only scans the rows
    # that could possibly match; find_threat_matches then decides exact vs near-miss
    intel_by_norm: dict[str, pd.DataFrame] = {
        key: grp for key, grp in intel.groupby(intel["matched_cve_or_control"].map(normalize_cve))
    }
    no_rows = intel.iloc[0:0]

    risks: list[EnrichedRisk] = []
    for _, v in vulns.iterrows():
        asset_rows = assets[assets["asset_id"] == v["asset_id"]]
        if asset_rows.empty:
            continue  # orphaned vuln row, skip defensively
        a = asset_rows.iloc[0]

        svc = services.loc[a["business_service"]] if a["business_service"] in services.index else None

        cve = str(v["cve"]).strip()
        kev_entry = kev_index.get(cve)

        matches = find_threat_matches(cve, intel_by_norm.get(normalize_cve(cve), no_rows))

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
    for r in risks:
        for m in r.threat_matches:
            if m.near_miss:
                print(f"  possible match (verify): {r.asset_name} {r.cve} ~ {m.intel_id} lists {m.listed_cve}")
    ransomware_hits = [r for r in risks if r.any_ransomware_signal]
    print(f"  {len(ransomware_hits)} carry a ransomware-association signal")
