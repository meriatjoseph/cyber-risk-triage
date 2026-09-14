"""
Runs the full pipeline once and writes static output/report.md and
output/report.html files -- useful for reviewing the result without running
the web server, and as a deployment fallback (e.g. GitHub Pages).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import ROOT_DIR
from app.pipeline import build_top_risk_report
from app.render import render_markdown
from app.threat_report import parse_threat_report
from fastapi.templating import Jinja2Templates
from starlette.requests import Request


def main() -> None:
    out_dir = ROOT_DIR / "output"
    out_dir.mkdir(exist_ok=True)

    entries = build_top_risk_report()

    md = render_markdown(entries)
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    print(f"Wrote {out_dir / 'report.md'}")

    from app.ingestion import load_dataframes

    dfs = load_dataframes()
    summary = {
        "assets": len(dfs["assets"]),
        "vulnerabilities": len(dfs["vulnerabilities"]),
        "threat_intel": len(dfs["threat_intelligence"]),
        "business_services": len(dfs["business_services"]),
        "kev_matches": sum(1 for e in entries if e.risk.kev_listed),
    }

    templates = Jinja2Templates(directory=str(ROOT_DIR / "templates"))
    scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
    request = Request(scope)
    advisory = parse_threat_report()
    html = templates.get_template("report.html").render(
        request=request, entries=entries, summary=summary, advisory=advisory
    )
    (out_dir / "report.html").write_text(html, encoding="utf-8")
    print(f"Wrote {out_dir / 'report.html'}")


if __name__ == "__main__":
    main()
