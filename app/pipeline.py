"""
Wires the whole system together: ingest -> enrich -> score -> rank ->
retrieve NIST guidance -> generate explanation -> assemble the final
human-readable top-N risk report.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from app import config
from app.enrichment import EnrichedRisk, build_enriched_risks
from app.explain import explain_risk
from app.rag import NistControlRetriever, RetrievedControl
from app.scoring import ScoreBreakdown, rank_grouped


@dataclass
class RiskReportEntry:
    rank: int
    risk: EnrichedRisk
    score: ScoreBreakdown
    why_it_ranks_here: str
    nist_controls: list[RetrievedControl]
    # same CVE/finding on other assets (e.g. the redundant twin of a load
    # balancer), each with its own score -- see scoring.rank_grouped
    also_affected: list[tuple[EnrichedRisk, ScoreBreakdown]] = field(default_factory=list)


_retriever_singleton: NistControlRetriever | None = None


def get_retriever() -> NistControlRetriever:
    global _retriever_singleton
    if _retriever_singleton is None:
        _retriever_singleton = NistControlRetriever()
    return _retriever_singleton


def build_top_risk_report(top_n: int = config.TOP_N_RISKS) -> list[RiskReportEntry]:
    risks = build_enriched_risks()
    ranked = rank_grouped(risks, top_n=top_n)
    retriever = get_retriever()

    # Retrieval is local (ChromaDB, ~10ms) so it stays sequential. The
    # explanation step is a network call to Groq (~1s each) and each risk's
    # call is independent of the others, so those run concurrently -- for
    # top_n=5 this turns ~5x1s of serial network waiting into ~1s total.
    ranks = list(range(1, len(ranked) + 1))
    risks_ranked = [risk for risk, _, _ in ranked]
    scores_ranked = [score for _, score, _ in ranked]
    others_ranked = [others for _, _, others in ranked]
    controls_per_risk = [retriever.query_for_risk(risk, k=2) for risk in risks_ranked]

    with ThreadPoolExecutor(max_workers=max(len(ranked), 1)) as pool:
        narratives = list(
            pool.map(explain_risk, ranks, risks_ranked, scores_ranked, controls_per_risk, others_ranked)
        )

    return [
        RiskReportEntry(
            rank=rank, risk=risk, score=score, why_it_ranks_here=narrative,
            nist_controls=controls, also_affected=others,
        )
        for rank, risk, score, controls, narrative, others in zip(
            ranks, risks_ranked, scores_ranked, controls_per_risk, narratives, others_ranked
        )
    ]


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
        for o, os_ in e.also_affected:
            print(f"Also affected : {o.asset_name} ({o.business_service}) [{os_.total:.1f}]")
        print(f"Why here      : {e.why_it_ranks_here}")
        for c in e.nist_controls:
            print(f"NIST control  : {c.control_id} - {c.title} (sim={c.similarity:.3f})")
