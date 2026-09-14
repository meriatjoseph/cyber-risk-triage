"""Markdown rendering of the top-risk report (used for /report.md and the
standalone file output produced by scripts/run_pipeline.py)."""
from datetime import datetime, timezone

from app.pipeline import RiskReportEntry
from app.threat_report import parse_threat_report


def render_markdown(entries: list[RiskReportEntry]) -> str:
    advisory = parse_threat_report()
    lines = [
        "# TawasolPay — Top 5 Prioritised Cyber Risks",
        "",
        f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        f"— ranked by exposure, active exploitation, campaign match, business criticality, "
        f"and missing controls (NOT CVSS alone)._",
        "",
        f"> **MDR Advisory — Risk level: {advisory.risk_level}.** {advisory.executive_overview}  ",
        f"> Named campaigns: {', '.join(advisory.campaign_names)}.",
        "",
        "---",
        "",
    ]
    for e in entries:
        r, s = e.risk, e.score
        lines.append(f"## #{e.rank} — {r.asset_name} · {r.vulnerability_name}  (Risk score: {s.total:.0f}/100)")
        lines.append("")
        lines.append(f"- **Asset:** {r.asset_name} ({r.asset_type}, {r.environment}, {r.location}) — "
                      f"owner: {r.owner_team}; internet-exposed: {'Yes' if r.internet_exposed else 'No'}; "
                      f"EDR installed: {'Yes' if r.edr_installed else 'No'}")
        lines.append(f"- **Vulnerability:** {r.vulnerability_name} ({r.cve}, CVSS {r.cvss} {r.severity}); "
                      f"exposure: {r.asset_exposure}; auth required to exploit: {'Yes' if r.auth_required else 'No'}; "
                      f"patch available: {'Yes' if r.patch_available else 'No'}")
        if r.kev_listed:
            lines.append(f"- **CISA KEV:** confirmed actively exploited (added {r.kev_date_added})"
                          + (", **known ransomware campaign use**" if r.kev_ransomware_known else ""))
        if r.threat_matches:
            for m in r.threat_matches:
                lines.append(f"- **Threat intel match:** {m.threat_actor} / \"{m.campaign_name}\" "
                              f"({m.exploit_maturity}, {m.confidence} confidence, "
                              f"ransomware-associated: {'Yes' if m.ransomware_association else 'No'}) — {m.summary}")
        else:
            lines.append("- **Threat intel match:** none — this risk is driven by exposure, business criticality, and missing controls, not a named campaign")
        rto_clause = f"; RTO: {r.rto_hours:g}h" if r.rto_hours is not None else ""
        lines.append(f"- **Business service at risk:** {r.business_service} (owner: {r.business_owner}) — {r.business_impact}. "
                      f"Customer-facing: {'Yes' if r.customer_facing else 'No'}; compliance scope: {r.compliance_scope}"
                      f"{rto_clause}")
        lines.append(f"- **Why it ranks here:** {e.why_it_ranks_here}")
        lines.append("- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**")
        for c in e.nist_controls:
            snippet = (c.statement or c.discussion or "")[:400].strip()
            lines.append(f"  - **{c.control_id} — {c.title}** _(similarity {c.similarity:.2f})_: {snippet}...")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)
