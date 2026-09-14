"""
Transparent, explainable risk scoring engine.

Deliberately NOT CVSS-driven. Weights follow the MDR advisory's explicit
analyst prioritisation order (data/synthetic_threat_report.md):

    1. internet exposure
    2. active exploitation in the wild (real CISA KEV + threat-intel maturity)
    3. ransomware association
    4. business criticality / compliance scope
    5. missing compensating controls

CVSS is folded in only as a small tiebreaker (weight 0.05) so it can never
dominate the ranking on its own -- see test_scoring.py for the explicit
CVSS-10-internal vs CVSS-8-exposed-with-active-campaign inversion test.

Every subscore is 0..1 and every weight/threshold below is a plain constant,
so the whole function is auditable line by line -- no hidden model.
"""
from dataclasses import dataclass, field

from app.enrichment import EnrichedRisk

WEIGHTS = {
    "exposure": 0.28,
    "exploitation": 0.24,
    "campaign_ransomware": 0.19,
    "business_criticality": 0.14,
    "missing_controls": 0.10,
    "cvss_tiebreaker": 0.05,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

_LEVEL_SCORE = {"Critical": 1.0, "High": 0.7, "Medium": 0.4, "Low": 0.15}
_CONFIDENCE_SCORE = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
_MATURITY_SCORE = {
    "Weaponized": 0.85,
    "Active Exploitation": 0.9,
    "Commodity Exploit": 0.6,
    "Proof of Concept": 0.45,
    "Social Engineering": 0.35,
    "Not Applicable": 0.15,
}
_MATURITY_PHRASE = {
    "Weaponized": "weaponized exploit code in active use",
    "Active Exploitation": "active exploitation in the wild",
    "Commodity Exploit": "widespread commodity/automated exploitation",
    "Proof of Concept": "proof-of-concept exploitation",
    "Social Engineering": "active social-engineering activity",
    "Not Applicable": "related activity",
}


@dataclass
class ScoreBreakdown:
    exposure_score: float
    exploitation_score: float
    campaign_score: float
    business_score: float
    missing_controls_score: float
    cvss_score: float
    total: float
    reasons: list[str] = field(default_factory=list)


def _exposure_score(risk: EnrichedRisk) -> tuple[float, str | None]:
    if risk.asset_exposure == "Internet":
        reason = f"the vulnerable {risk.affected_component} is directly reachable from the internet"
        return 1.0, reason
    if risk.internet_exposed:
        # asset has some internet-facing surface, but this specific finding isn't on it
        return 0.35, f"{risk.asset_name} has internet-facing surface, though this finding is on an internal path"
    return 0.0, None


def _exploitation_score(risk: EnrichedRisk) -> tuple[float, list[str]]:
    reasons = []
    best = 0.0

    if risk.kev_listed:
        best = max(best, 1.0)
        reasons.append(f"{risk.cve} is confirmed in the CISA Known Exploited Vulnerabilities catalog (added {risk.kev_date_added})")

    for m in risk.threat_matches:
        maturity_score = _MATURITY_SCORE.get(m.exploit_maturity, 0.3)
        conf = _CONFIDENCE_SCORE.get(m.confidence, 0.5)
        score = maturity_score * conf
        if score > best:
            best = score
        if maturity_score >= 0.6:
            phrase = _MATURITY_PHRASE.get(m.exploit_maturity, m.exploit_maturity.lower())
            reasons.append(f"threat intel ({m.confidence} confidence) reports {phrase} by {m.threat_actor}/\"{m.campaign_name}\"")

    if best == 0.0 and risk.exploit_available_csv:
        best = 0.3
        reasons.append("marked exploit-available in the vulnerability record (self-reported, not independently confirmed)")

    return best, reasons


def _campaign_score(risk: EnrichedRisk) -> tuple[float, list[str]]:
    if not risk.threat_matches and not risk.kev_ransomware_known:
        return 0.0, []

    reasons = []
    best = 0.0
    if risk.kev_ransomware_known:
        best = max(best, 1.0)
        reasons.append("CISA KEV flags this CVE with known ransomware campaign use")

    for m in risk.threat_matches:
        conf = _CONFIDENCE_SCORE.get(m.confidence, 0.5)
        if m.ransomware_association:
            score = 1.0 * conf
            reasons.append(f"\"{m.campaign_name}\" ({m.threat_actor}) is a ransomware-associated campaign actively matching this CVE")
        else:
            score = 0.4 * conf
            reasons.append(f"\"{m.campaign_name}\" ({m.threat_actor}) targets this CVE (no ransomware link confirmed)")
        best = max(best, score)

    return best, reasons


def _business_score(risk: EnrichedRisk) -> tuple[float, list[str]]:
    reasons = []
    asset_component = _LEVEL_SCORE.get(risk.asset_criticality, 0.3)

    svc_component = _LEVEL_SCORE.get(risk.revenue_impact, 0.3) * 0.6
    if risk.customer_facing:
        svc_component += 0.15
        reasons.append(f"'{risk.business_service}' is customer-facing")
    if risk.rto_hours is not None:
        if risk.rto_hours <= 2:
            svc_component += 0.15
            reasons.append(f"a {risk.rto_hours:g}-hour RTO leaves almost no tolerance for downtime")
        elif risk.rto_hours <= 8:
            svc_component += 0.08
    if risk.compliance_scope and risk.compliance_scope != "None":
        svc_component += 0.10
        reasons.append(f"in-scope for {risk.compliance_scope}")
    svc_component = min(svc_component, 1.0)

    score = 0.5 * asset_component + 0.5 * svc_component
    if risk.asset_criticality in ("Critical", "High"):
        reasons.insert(0, f"asset criticality is {risk.asset_criticality}")
    return min(score, 1.0), reasons


def _missing_controls_score(risk: EnrichedRisk) -> tuple[float, list[str]]:
    flags = []
    reasons = []
    if not risk.edr_installed:
        flags.append(1.0)
        reasons.append("no EDR installed on the asset")
    else:
        flags.append(0.0)
    if not risk.auth_required:
        flags.append(1.0)
        reasons.append("the vulnerability is exploitable without authentication")
    else:
        flags.append(0.0)
    if not risk.patch_available:
        flags.append(1.0)
        reasons.append("no vendor patch is currently available")
    else:
        flags.append(0.0)
    score = sum(flags) / len(flags)
    return score, reasons


def score_risk(risk: EnrichedRisk) -> ScoreBreakdown:
    exposure, exp_reason = _exposure_score(risk)
    exploitation, exploit_reasons = _exploitation_score(risk)
    campaign, campaign_reasons = _campaign_score(risk)
    business, biz_reasons = _business_score(risk)
    controls, control_reasons = _missing_controls_score(risk)
    cvss_norm = risk.cvss / 10.0

    total = 100 * (
        WEIGHTS["exposure"] * exposure
        + WEIGHTS["exploitation"] * exploitation
        + WEIGHTS["campaign_ransomware"] * campaign
        + WEIGHTS["business_criticality"] * business
        + WEIGHTS["missing_controls"] * controls
        + WEIGHTS["cvss_tiebreaker"] * cvss_norm
    )

    all_reasons = []
    if exp_reason:
        all_reasons.append(exp_reason)
    all_reasons.extend(exploit_reasons)
    all_reasons.extend(campaign_reasons)
    all_reasons.extend(biz_reasons)
    all_reasons.extend(control_reasons)

    return ScoreBreakdown(
        exposure_score=exposure,
        exploitation_score=exploitation,
        campaign_score=campaign,
        business_score=business,
        missing_controls_score=controls,
        cvss_score=cvss_norm,
        total=round(total, 2),
        reasons=all_reasons,
    )


def rank_risks(
    risks: list[EnrichedRisk], top_n: int | None = None, one_per_asset: bool = False
) -> list[tuple[EnrichedRisk, ScoreBreakdown]]:
    """Ranks by total score, descending. Exact ties (e.g. two redundant
    internet-facing gateways with the same CVE profile) are broken
    deterministically by raw CVSS, then vuln_id, so results are reproducible
    across runs rather than depending on dict/list ordering.

    one_per_asset=True keeps only each asset's single highest-scoring finding
    before truncating to top_n. Used for the board-facing top-5 report so it
    surfaces breadth across the estate instead of, e.g., an asset's #2 bug
    filling a slot while a different at-risk system waits just outside the
    cutoff -- a raw per-finding top_n stays available (one_per_asset=False)
    for full-list analysis and tests."""
    scored = [(r, score_risk(r)) for r in risks]
    scored.sort(key=lambda pair: (-pair[1].total, -pair[0].cvss, pair[0].vuln_id))

    if not one_per_asset:
        return scored[:top_n] if top_n else scored

    seen_assets: set[str] = set()
    deduped = []
    for r, s in scored:
        if r.asset_id in seen_assets:
            continue
        seen_assets.add(r.asset_id)
        deduped.append((r, s))
        if top_n and len(deduped) == top_n:
            break
    return deduped


if __name__ == "__main__":
    from app.enrichment import build_enriched_risks

    risks = build_enriched_risks()
    ranked = rank_risks(risks, top_n=10)
    print("Top 10 by risk score (NOT CVSS):")
    for r, s in ranked:
        print(f"  [{s.total:5.1f}] {r.asset_name:<28} {r.cve:<18} cvss={r.cvss:<4} {r.vulnerability_name}")
