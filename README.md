# TawasolPay - AI-Powered Cyber Risk Assistant

This tool pulls together TawasolPay's asset list, vulnerability list, threat
intel, and business context into one report: the top 5 risks the company
should deal with first, in plain English. Each risk comes with a matching
fix recommendation pulled from the real NIST SP 800-53 control catalog.

The ranking is not just "biggest CVSS score wins." It looks at whether the
system is exposed to the internet, whether the bug is actually being
exploited right now (checked against the real CISA KEV list), whether a
known ransomware group is targeting it, how much the business would be hurt,
and whether basic protections like EDR or patching are missing. A CVSS 10 on
a random internal dev box can end up ranked below a CVSS 8 on a payment
gateway that's internet-facing and actively under attack. That's on purpose,
and there's a test for it (`tests/test_scoring.py`).

## How it's put together

- `app/ingestion.py` loads the 5 CSV files into a small SQLite database.
- `app/kev.py` reads the real CISA KEV catalog once it's been fetched.
- `app/enrichment.py` joins assets, vulnerabilities, business services, and
  threat intel together, and checks each vulnerability against KEV.
- `app/scoring.py` does the actual scoring - plain, readable code, no black box.
- `app/rag.py` embeds the NIST 800-53 controls and searches them with
  ChromaDB to find the best-matching guidance for each risk.
- `app/explain.py` writes the one-sentence "why this is ranked here" line.
- `app/threat_report.py` reads the MDR advisory (the markdown report) and
  pulls out the risk level and campaign names for the summary banner.
- `app/pipeline.py` runs all of the above in order and builds the final list.
- `app/main.py` is the FastAPI app that serves it as a web page.

One small but deliberate choice: the top-5 list only shows one issue per
asset. Without that, two identical Fortinet VPN boxes with the same bug
could fill 4 of the 5 slots, which is technically accurate but not a useful
briefing. The full, non-deduped ranking is still what the tests check
against.

## Running it locally

You'll need Python 3.11+.

```bash
python -m venv .venv
source .venv/Scripts/activate        # on Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# grab the real public data this depends on
python scripts/fetch_kev.py          # -> data/kev_catalog.json
python scripts/fetch_nist.py         # -> data/nist_800_53_chunks.jsonl

# run the tests
python -m pytest tests/ -v

# start the web app
uvicorn app.main:app --reload
```

Then open:
- `http://127.0.0.1:8000/` - the readable report
- `http://127.0.0.1:8000/report.md` - same thing as markdown
- `http://127.0.0.1:8000/api/top5` - same thing as JSON

If you'd rather not run a server, `python scripts/run_pipeline.py` writes
`output/report.md` and `output/report.html` directly.

The cleaned NIST data (`data/nist_800_53_chunks.jsonl`, about 1,000 chunks)
is committed to the repo so you don't have to re-download NIST's full 10MB
file just to start the app. The KEV file and the raw NIST file are not
committed since they're easy to re-fetch and KEV changes weekly anyway.

### Docker

```bash
docker build -t tawasolpay-risk-assistant .
docker run -p 8000:8000 tawasolpay-risk-assistant
```

The Docker build fetches KEV and NIST and builds the search index at build
time, so the container is ready to serve as soon as it starts.

### About the LLM

By default, no LLM is used anywhere in this system. The one place a
generative model *could* help - the "why this is ranked here" sentence - is
written by a plain template that only restates facts the scoring engine
already calculated. That's a deliberate choice so nothing can be invented or
hallucinated.

If you want to try it with an LLM anyway, set a `GROQ_API_KEY` environment
variable (Groq has a free tier) and it will use a small free Llama model to
smooth that same sentence into more natural phrasing, without adding any new
facts. If that call fails for any reason, it quietly falls back to the
template, so the app never depends on an external API being available.

The only model actually required to run this is a small embedding model
(`all-MiniLM-L6-v2`) used to search the NIST controls - that's not an LLM,
it just measures how similar two pieces of text are.

## Q1: What did you embed, and what did you query directly?

Only one thing gets embedded: the ~1,000 cleaned NIST 800-53 control texts.
That's the only part of this system that's genuinely free-form text with no
exact way to look it up - there's no column anywhere that says "use control
SI-2 for this bug." Matching a vulnerability description to the right
control is a "what does this sound like" problem, so a search based on
meaning is the right tool.

Everything else - assets, vulnerabilities, threat intel, business services,
and the KEV catalog - is queried directly as structured data (pandas and
SQLite joins). These are all exact-match, not fuzzy: an asset ID either
matches a vulnerability or it doesn't, and a CVE either shows up in the KEV
list or it doesn't. There's no reason to embed that and turn a certain
answer into a probability. It also matters that 15 of the 40 threat intel
rows are deliberately not supposed to match anything in this data - treating
that as an exact lookup means those rows correctly produce zero matches
instead of accidentally look similar to something.

`remediation_guidance.csv` isn't used in either path. The assignment treats
it as a hint about wording, not something to actually query, so it doesn't
feed the score and it isn't part of what gets embedded either. The actual
remediation text always comes from the live NIST search.

## Q2: Where could this go wrong?

1. **KEV can lag behind reality.** If a CVE isn't in the CISA KEV list, this
   system won't call it "actively exploited," even if it actually is being
   exploited somewhere right now - KEV gets updated periodically and doesn't
   catch everything immediately. To soften this, the score also checks the
   threat intel data as a second, independent signal, so a real campaign
   that hasn't made it into KEV yet can still be caught that way. But if a
   threat shows up in neither KEV nor the threat intel file, the system has
   no way to know about it. Re-running the KEV fetch regularly is the real
   fix here, not a one-time download.

2. **Matching CVEs is done by exact text, which can miss real matches.**
   The threat intel matching is a plain string comparison. If the same bug
   were reported under a slightly different CVE ID, or referenced as a
   range, the join would just come back empty instead of flagging "this
   might be related, please check." Right now the system treats "no match"
   as a normal, expected outcome (because a lot of the sample data is
   supposed to not match), which is correct for this dataset, but in a real
   environment a near-miss like that would be silently dropped rather than
   flagged for a person to look at.

3. **The NIST control it finds might not be the best one.** Search by
   meaning isn't the same as a certified mapping table. For an unusual bug,
   the top match could be a real, related NIST control that still isn't
   what an experienced analyst would have picked. To make this visible
   rather than hidden, the app shows two matches instead of one, shows the
   actual NIST text instead of a summary, and shows the similarity score so
   a weak match looks obviously weak instead of confidently wrong.

## Q3: If I had one more day

The weights used in scoring (in `app/scoring.py`) are numbers I chose by
hand to match the priority order described in the MDR advisory, and to make
sure the CVSS-inversion test actually holds. They're reasonable and every
one of them is explainable, but they weren't tested against any real
"correct" answer, because there isn't one in this dataset - nobody has
labeled which of the 114 findings actually matter most. Given another day,
I'd build a small reference answer (using what the MDR advisory itself
implies the top risks are) and tune the weights against that instead of
against my own judgment, then re-check that the inversion test still
passes. Right now the scoring is transparent and defensible, but
"defensible" isn't the same as "verified against a real answer," and that
gap is the biggest weak point in what's here.

## The data

Provided in `data/`: `assets.csv` (60 rows), `vulnerabilities.csv` (114),
`threat_intelligence.csv` (40), `business_services.csv` (20),
`remediation_guidance.csv` (30, used only as wording guidance), and
`synthetic_threat_report.md`, the MDR advisory that lays out the priority
order the scoring weights follow: exposure first, then active exploitation,
then ransomware association, then business impact, then missing controls.

Fetched automatically at setup time, not committed to the repo: the real
[CISA KEV catalog](https://github.com/cisagov/kev-data) and the real
[NIST SP 800-53 Rev 5 catalog](https://github.com/usnistgov/oscal-content).
