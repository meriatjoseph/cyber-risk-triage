"""
Wires the whole system together: ingest -> enrich -> score -> rank ->
retrieve NIST guidance -> generate explanation -> assemble the final
human-readable top-N risk report.
"""
from dataclasses import dataclass

from app import config
from app.enrichment import EnrichedRisk, build_enriched_risks
from app.explain import explain_risk
from app.rag import NistControlRetriever, RetrievedControl, build_query_for_risk
from app.scoring import ScoreBreakdown, rank_risks


@dataclass
class RiskReportEntry:
    rank: int
    risk: EnrichedRisk
    score: ScoreBreakdown
    why_it_ranks_here: str
    nist_controls: list[RetrievedControl]


_retriever_singleton: NistControlRetriever | None = None


def get_retriever() -> NistControlRetriever:
    global _retriever_singleton
    if _retriever_singleton is None:
        _retriever_singleton = NistControlRetriever()
    return _retriever_singleton


def build_top_risk_report(top_n: int = config.TOP_N_RISKS) -> list[RiskReportEntry]:
    risks = build_enriched_risks()
    ranked = rank_risks(risks, top_n=top_n, one_per_asset=True)
    retriever = get_retriever()

    entries = []
    for i, (risk, score) in enumerate(ranked, start=1):
        query = build_query_for_risk(risk)
        controls = retriever.query(query, k=2)
        narrative = explain_risk(i, risk, score)
        entries.append(
            RiskReportEntry(
                rank=i,
                risk=risk,
                score=score,
                why_it_ranks_here=narrative,
                nist_controls=controls,
            )
        )
    return entries


if __name__ == "__main__":
    entries = build_top_risk_report()
    for e in entries:
        r, s = e.risk, e.score
        print(f"\n=== #{e.rank}  [{s.total:.1f}/100]  {r.asset_name}  ({r.cve}) ===")
        print(f"Vulnerability : {r.vulnerability_name}  (CVSS {r.cvss}, {r.severity})")
        print(f"Business svc  : {r.business_service}  (customer_facing={r.customer_facing}, compliance={r.compliance_scope})")
        if r.threat_matches:
            m = r.threat_matches[0]
            print(f"Threat match  : {m.threat_actor} / \"{m.campaign_name}\" (ransomware={m.ransomware_association}, confidence={m.confidence})")
        else:
            print("Threat match  : none (driven by exposure/criticality/controls)")
        print(f"Why here      : {e.why_it_ranks_here}")
        for c in e.nist_controls:
            print(f"NIST control  : {c.control_id} - {c.title} (sim={c.similarity:.3f})")
