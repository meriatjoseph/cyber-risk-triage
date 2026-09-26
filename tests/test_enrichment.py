"""Threat-intel matching: exact CVE matches, the normalised near-miss case
(CVE-2025-0333 in the intel feed vs CVE-SYN-2025-0333 in the vuln list),
and noise rows that must still match nothing."""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.enrichment import build_enriched_risks, find_threat_matches, normalize_cve


def _intel(*cves: str) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "intel_id": f"TI-{i}", "threat_actor": "Actor", "campaign_name": f"Campaign {i}",
                "target_sector": "Fintech", "target_region": "UAE", "matched_cve_or_control": cve,
                "exploit_maturity": "Weaponized", "active_last_seen": "2026-04-01",
                "ransomware_association": "Yes", "confidence": "High", "summary": "",
            }
            for i, cve in enumerate(cves)
        ]
    )


def test_normalize_cve_strips_synthetic_prefix_only():
    assert normalize_cve("CVE-SYN-2025-0333") == "CVE-2025-0333"
    assert normalize_cve(" cve-2025-0333 ") == "CVE-2025-0333"
    assert normalize_cve("CTRL-SYN-003") == "CTRL-SYN-003"


def test_exact_match_is_not_flagged():
    [m] = find_threat_matches("CVE-2024-21762", _intel("CVE-2024-21762"))
    assert m.near_miss is False


def test_normalised_match_is_kept_and_flagged_for_verification():
    [m] = find_threat_matches("CVE-SYN-2025-0333", _intel("CVE-2025-0333"))
    assert m.near_miss is True
    assert m.listed_cve == "CVE-2025-0333"


def test_unrelated_ids_still_match_nothing():
    assert find_threat_matches("CVE-SYN-2025-0333", _intel("CVE-2025-0334", "PHISH-SYN-001")) == []


def test_real_dataset_surfaces_exactly_the_hr_portal_near_miss():
    near = [
        (r.asset_name, r.cve, m.intel_id)
        for r in build_enriched_risks()
        for m in r.threat_matches
        if m.near_miss
    ]
    assert near == [("hr-portal-prod", "CVE-SYN-2025-0333", "TI-3012")]
