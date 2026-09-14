"""
Parses the morning's MDR advisory (data/synthetic_threat_report.md) into a
small structured summary -- this is the sixth ingested input the assignment
spec calls out alongside the five CSVs. Its content isn't re-derived from
threat_intelligence.csv: the report is prose, so we extract just the
risk-level headline, executive overview, and named-campaign list with a
light-touch regex pass (not embeddings -- five short, fixed-format campaign
blocks with clear headings is exact-pattern extraction, not a semantic
retrieval problem) and surface it as context in the report header.
"""
import re
from dataclasses import dataclass

from app.ingestion import read_threat_report


@dataclass
class ThreatReportSummary:
    risk_level: str
    executive_overview: str
    campaign_names: list[str]


_RISK_LEVEL_RE = re.compile(r"\*\*Risk level:\s*([A-Z]+)\.\*\*\s*(.*?)(?=\n---|\Z)", re.DOTALL)
_CAMPAIGN_RE = re.compile(r"^### \d+\.\s*(.+?)\s*—", re.MULTILINE)


def parse_threat_report() -> ThreatReportSummary:
    text = read_threat_report()

    risk_level = "UNKNOWN"
    overview = ""
    m = _RISK_LEVEL_RE.search(text)
    if m:
        risk_level = m.group(1).strip()
        overview = " ".join(m.group(2).split())

    campaigns = [c.strip() for c in _CAMPAIGN_RE.findall(text)]

    return ThreatReportSummary(
        risk_level=risk_level,
        executive_overview=overview,
        campaign_names=campaigns,
    )


if __name__ == "__main__":
    s = parse_threat_report()
    print("Risk level:", s.risk_level)
    print("Campaigns:", s.campaign_names)
    print("Overview:", s.executive_overview[:200], "...")
