"""
FastAPI web app serving the top-5 risk report as a readable HTML page (and
a markdown/JSON variant of the same data). The report is computed once at
startup and cached; POST /refresh recomputes it.
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from app import config
from app.ingestion import load_dataframes
from app.pipeline import build_top_risk_report
from app.render import render_markdown
from app.threat_report import parse_threat_report

app = FastAPI(title="TawasolPay Cyber Risk Assistant")
templates = Jinja2Templates(directory=str(config.ROOT_DIR / "templates"))

_cache: dict = {"entries": None}


def get_entries(force: bool = False):
    if force or _cache["entries"] is None:
        _cache["entries"] = build_top_risk_report()
    return _cache["entries"]


@app.on_event("startup")
def _warm_start():
    get_entries()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    entries = get_entries()
    dfs = load_dataframes()
    summary = {
        "assets": len(dfs["assets"]),
        "vulnerabilities": len(dfs["vulnerabilities"]),
        "threat_intel": len(dfs["threat_intelligence"]),
        "business_services": len(dfs["business_services"]),
        "kev_matches": sum(1 for e in entries if e.risk.kev_listed),
    }
    advisory = parse_threat_report()
    return templates.TemplateResponse(
        request, "report.html", {"entries": entries, "summary": summary, "advisory": advisory}
    )


@app.post("/refresh")
def refresh():
    get_entries(force=True)
    return JSONResponse({"status": "ok", "message": "report recomputed"})


@app.get("/report.md", response_class=PlainTextResponse)
def report_markdown():
    return render_markdown(get_entries())


@app.get("/api/top5")
def api_top5():
    entries = get_entries()
    out = []
    for e in entries:
        out.append(
            {
                "rank": e.rank,
                "score": e.score.total,
                "score_breakdown": {
                    "exposure": e.score.exposure_score,
                    "exploitation": e.score.exploitation_score,
                    "campaign_ransomware": e.score.campaign_score,
                    "business_criticality": e.score.business_score,
                    "missing_controls": e.score.missing_controls_score,
                    "cvss_tiebreaker": e.score.cvss_score,
                },
                "asset": e.risk.asset_name,
                "vulnerability": e.risk.vulnerability_name,
                "cve": e.risk.cve,
                "business_service": e.risk.business_service,
                "why_it_ranks_here": e.why_it_ranks_here,
                "nist_controls": [
                    {"control_id": c.control_id, "title": c.title, "similarity": c.similarity}
                    for c in e.nist_controls
                ],
            }
        )
    return JSONResponse(out)


@app.get("/health")
def health():
    return {"status": "ok"}
