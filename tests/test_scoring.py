"""
Unit tests for the risk scoring engine, isolated from the real dataset so
the core claim of the assignment -- "the ranking must not be CVSS alone" --
is verified against constructed, unambiguous inputs, not just observed by
accident in the sample data.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.enrichment import EnrichedRisk, ThreatMatch
from app.scoring import rank_risks, score_risk


def make_internal_high_cvss_dev_server() -> EnrichedRisk:
    """CVSS 10.0, internal-only, low-criticality dev asset, no campaign match."""
    return EnrichedRisk(
        asset_id="A-TEST-1",
        asset_name="dev-scratch-server",
        asset_type="Application Server",
        environment="Development",
        owner_team="Engineering",
        business_service="Testing Platform",
        internet_exposed=False,
        asset_criticality="Low",
        data_classification="Test Data",
        edr_installed=True,
        last_seen_days=5,
        location="India",
        vendor_product="Ubuntu 22.04",
        vuln_id="V-TEST-1",
        vulnerability_name="Local Privilege Escalation in Test Utility",
        cve="CVE-SYN-TEST-0001",
        severity="Critical",
        cvss=10.0,
        exploit_available_csv=False,
        patch_available=True,
        days_open=10,
        asset_exposure="Internal",
        auth_required=True,
        affected_component="Test Utility",
        kev_listed=False,
        kev_ransomware_known=False,
        kev_date_added=None,
        kev_required_action=None,
        threat_matches=[],
        business_owner="VP Engineering",
        business_impact="QA and testing delays only; no production impact",
        customer_facing=False,
        compliance_scope="None",
        revenue_impact="Low",
        rto_hours=48,
        risk_appetite="High",
    )


def make_exposed_payment_gateway_active_campaign() -> EnrichedRisk:
    """CVSS 8.0, internet-exposed payment gateway, active ransomware campaign match."""
    return EnrichedRisk(
        asset_id="A-TEST-2",
        asset_name="payment-api-prod-01",
        asset_type="API Server",
        environment="Production",
        owner_team="Payments Team",
        business_service="Payment Processing",
        internet_exposed=True,
        asset_criticality="Critical",
        data_classification="Payment Card Data",
        edr_installed=True,
        last_seen_days=1,
        location="UAE",
        vendor_product="Node.js 20 / Ubuntu 22.04",
        vuln_id="V-TEST-2",
        vulnerability_name="Payment Gateway Authentication Bypass",
        cve="CVE-2024-99999",
        severity="High",
        cvss=8.0,
        exploit_available_csv=True,
        patch_available=True,
        days_open=5,
        asset_exposure="Internet",
        auth_required=False,
        affected_component="Payment API Gateway",
        kev_listed=True,
        kev_ransomware_known=True,
        kev_date_added="2026-04-01",
        kev_required_action="Apply vendor patch immediately.",
        threat_matches=[
            ThreatMatch(
                intel_id="TI-TEST-1",
                threat_actor="CrimsonJackal",
                campaign_name="Gateway Breaker",
                target_sector="Financial Services",
                target_region="Middle East",
                exploit_maturity="Weaponized",
                active_last_seen="2026-04-22",
                ransomware_association=True,
                confidence="High",
                summary="Active exploitation against fintech payment gateways in the Gulf region.",
            )
        ],
        business_owner="CFO",
        business_impact="Payments and fund transfers fail; PCI DSS breach obligations triggered",
        customer_facing=True,
        compliance_scope="PCI DSS",
        revenue_impact="Critical",
        rto_hours=1,
        risk_appetite="Very Low",
    )


def test_exposure_and_campaign_beat_raw_cvss():
    internal_critical_cvss = make_internal_high_cvss_dev_server()
    exposed_campaign_matched = make_exposed_payment_gateway_active_campaign()

    assert internal_critical_cvss.cvss > exposed_campaign_matched.cvss  # 10.0 > 8.0

    internal_score = score_risk(internal_critical_cvss)
    exposed_score = score_risk(exposed_campaign_matched)

    assert exposed_score.total > internal_score.total, (
        f"Expected the internet-exposed, actively-campaigned CVSS-8 payment gateway "
        f"({exposed_score.total}) to outrank the internal CVSS-10 dev server "
        f"({internal_score.total}), but it did not."
    )

    ranked = rank_risks([internal_critical_cvss, exposed_campaign_matched])
    assert ranked[0][0] is exposed_campaign_matched


def test_no_campaign_match_can_still_reach_top_via_exposure_and_business_impact():
    """A legitimate top-5 entry may have zero threat-intel matches, driven
    instead by exposure + criticality + missing controls."""
    no_intel_but_exposed = EnrichedRisk(
        asset_id="A-TEST-3", asset_name="idv-gateway-prod", asset_type="API Server",
        environment="Production", owner_team="Identity Team", business_service="Identity Verification",
        internet_exposed=True, asset_criticality="Critical", data_classification="Customer PII",
        edr_installed=False, last_seen_days=1, location="UAE", vendor_product="Node.js 18",
        vuln_id="V-TEST-3", vulnerability_name="Unauthenticated API Endpoint Exposure",
        cve="CVE-SYN-TEST-0002", severity="High", cvss=7.5, exploit_available_csv=False,
        patch_available=False, days_open=30, asset_exposure="Internet", auth_required=False,
        affected_component="Identity API", kev_listed=False, kev_ransomware_known=False,
        kev_date_added=None, kev_required_action=None, threat_matches=[],
        business_owner="Chief Digital Officer", business_impact="KYC and onboarding fails",
        customer_facing=True, compliance_scope="GDPR, UAE PDPL", revenue_impact="Critical",
        rto_hours=1, risk_appetite="Very Low",
    )
    score = score_risk(no_intel_but_exposed)
    assert score.campaign_score == 0.0
    assert score.total > 40  # still meaningfully elevated without any campaign match


def test_score_breakdown_is_transparent_and_bounded():
    risk = make_exposed_payment_gateway_active_campaign()
    score = score_risk(risk)
    for value in (
        score.exposure_score, score.exploitation_score, score.campaign_score,
        score.business_score, score.missing_controls_score, score.cvss_score,
    ):
        assert 0.0 <= value <= 1.0
    assert 0.0 <= score.total <= 100.0
    assert len(score.reasons) > 0


def test_one_per_asset_keeps_only_highest_finding_per_asset():
    same_asset_lower = make_exposed_payment_gateway_active_campaign()
    same_asset_lower.vuln_id = "V-TEST-2B"
    same_asset_lower.cvss = 5.0
    same_asset_lower.threat_matches = []
    same_asset_lower.kev_listed = False
    same_asset_lower.kev_ransomware_known = False

    same_asset_higher = make_exposed_payment_gateway_active_campaign()
    other_asset = make_internal_high_cvss_dev_server()

    ranked = rank_risks(
        [same_asset_lower, same_asset_higher, other_asset], top_n=5, one_per_asset=True
    )
    asset_ids = [r.asset_id for r, _ in ranked]
    assert asset_ids.count(same_asset_higher.asset_id) == 1
    assert ranked[0][0] is same_asset_higher  # the higher-scoring finding on that asset wins
    assert other_asset.asset_id in asset_ids  # distinct asset still represented


if __name__ == "__main__":
    test_exposure_and_campaign_beat_raw_cvss()
    test_no_campaign_match_can_still_reach_top_via_exposure_and_business_impact()
    test_score_breakdown_is_transparent_and_bounded()
    test_one_per_asset_keeps_only_highest_finding_per_asset()
    print("All scoring tests passed.")
