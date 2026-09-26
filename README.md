# TawasolPay - AI-Powered Cyber Risk Assistant

**Live demo:** https://tawasolpay-risk-assistant-w3jd.onrender.com
(free-tier hosting, spins down after ~15 min idle - first request after
that can take 30-60s to wake up)

Takes TawasolPay's asset list, vulnerability list, threat intel, and business
context, and turns it into one thing: the top 5 risks to deal with first,
in plain English, each with a fix recommendation pulled from the real NIST
SP 800-53 control catalog.

CVSS alone doesn't decide the ranking. It also weighs internet exposure,
whether a bug is actually being exploited right now (checked against the
real CISA KEV list), ransomware campaign matches, how much the business
would be hurt, and whether basics like EDR or patching are missing. So a
CVSS 10 on an internal dev box can rank below a CVSS 8 on a payment gateway
that's internet-facing and under active attack right now. `tests/test_scoring.py`
checks this holds.

## How it's put together

- `app/ingestion.py` - loads the 5 CSVs into SQLite.
- `app/kev.py` - reads the real CISA KEV catalog once it's fetched.
- `app/enrichment.py` - joins assets, vulnerabilities, business services,
  threat intel, and checks each vuln against KEV. Intel is matched on exact
  CVE first; a second pass on normalised IDs (`CVE-SYN-2025-0333` ~
  `CVE-2025-0333`) keeps near-misses as "possible match - verify" instead
  of dropping them (see Q2 #2).
- `app/scoring.py` - the actual scoring. Plain arithmetic, no black box.
- `app/rag.py` - embeds the NIST 800-53 controls, searches them with
  ChromaDB for the best match per risk. For a recognised vulnerability class
  (buffer overflow, broken access control, missing patch, ...) it runs a
  second query phrased in that class's own control vocabulary and merges it
  with the literal finding-text query by similarity - a blended query like
  "Fortinet SSL-VPN Heap Buffer Overflow RCE" otherwise embeds closer to
  remote-access controls than to the memory-corruption control that
  actually applies, because "VPN" dominates the sentence. Both queries still
  hit the same live NIST index; this only changes how the question is
  asked, not the answer.
  The embedding model only reads 256 tokens, and 176 of the 1,014 controls
  are longer, so their tails (mostly Discussion text) used to be silently
  cut off. Long controls are now split into passages that each fit (1,243
  in total, each starting with the control's ID and title), and a control
  is scored by its best passage. The index is rebuilt whenever a hash of
  those passages changes, not just when the count does.
- `app/explain.py` - writes the "why this ranks here" sentence.
- `app/threat_report.py` - pulls the risk level and campaign names out of
  the MDR advisory for the summary banner.
- `app/pipeline.py` - runs all of the above and builds the final list.
- `app/main.py` - FastAPI app that serves it as a web page.

The top-5 list shows one issue per asset, and then folds the same finding
on several assets into one entry. TawasolPay runs redundant pairs (two
load balancers, two VPN edges): without the second step, CitrixBleed on
both load balancers and the Fortinet bug on both VPN edges took 4 of the
5 slots - one fix each, two slots each. Now each of those is one entry
with a "same finding also on" list (every twin keeps its own score and
business service, since twins can front different services), and the
top 5 covers 5 distinct problems across 8 assets. The full per-finding
ranking (no dedup) is still available and is what the scoring tests check.

## Running it locally

Needs Python 3.11+.

```bash
python -m venv .venv
source .venv/Scripts/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# pull the real public data
python scripts/fetch_kev.py          # -> data/kev_catalog.json
python scripts/fetch_nist.py         # -> data/nist_800_53_chunks.jsonl

python -m pytest tests/ -v

uvicorn app.main:app --reload
```

Once the embedding model's been downloaded once, `HF_HUB_OFFLINE=1` skips a
network check on every future startup and saves a few seconds. The Docker
build sets this automatically.

Then open:
- `http://127.0.0.1:8000/` - the report
- `http://127.0.0.1:8000/report.md` - same thing, markdown
- `http://127.0.0.1:8000/api/top5` - same thing, JSON

`POST /refresh` recomputes the report. It re-runs the whole pipeline (and
up to 5 Groq calls), so on a public URL it's locked: set `REFRESH_TOKEN`
in `.env` and send it as a header -
`curl -X POST -H "X-Refresh-Token: $REFRESH_TOKEN" http://127.0.0.1:8000/refresh`.
With `REFRESH_TOKEN` unset the route returns 403. `render.yaml` has
Render generate a random token.

No server needed: `python scripts/run_pipeline.py` writes `output/report.md`
and `output/report.html` directly.

`data/nist_800_53_chunks.jsonl` (the cleaned ~1,000-chunk corpus) is
committed so you don't need to re-download NIST's full file just to start
the app. The KEV file and raw NIST file aren't committed - easy to refetch,
and KEV changes weekly anyway.

### Docker

```bash
docker build -t tawasolpay-risk-assistant .
docker run -p 8000:8000 tawasolpay-risk-assistant
```

KEV, NIST, and the search index are all built at image build time, so the
container's ready to serve as soon as it starts.

The image forces `EMBEDDER_BACKEND=tfidf`, so it uses the TF-IDF+SVD
fallback embedder instead of sentence-transformers. Reason: importing torch
+ sentence-transformers costs ~450MB RSS on its own, measured directly, and
that alone blows past the 512MB cap on Render's free tier. TF-IDF matches
are cruder than real semantic embeddings - still relevant, just less
precise - but the app stays up. Outside Docker, local runs use the full
sentence-transformers model by default.

### About the LLM

The "why this ranks here" sentence is the one spot a generative model
actually belongs here, and it's used. Set `GROQ_API_KEY` (copy
`.env.example` to `.env` - Groq's free tier is enough) and a small
open-weight model (`openai/gpt-oss-20b` on Groq) turns the facts the
scoring engine already computed into one natural sentence, and names the
NIST control `app/rag.py` already retrieved. It only gets the score's
reasons and the top control's id/title as fixed facts, and is told
explicitly not to invent a fact, number, CVE, or control id beyond those.
It's doing language generation over grounded input, not generating facts.
See `app/explain.py`.

Everything else stays deterministic: scoring is plain arithmetic over named
weights, NIST matching is embedding similarity search. The LLM only ever
touches the last-mile phrasing of one sentence.

No key, a failed call, a timeout, a rate limit, or an empty response - any
of that and it falls back to a template that restates the same facts
without an LLM (see Q2). The app never depends on Groq being up to produce
a report.

The only model actually required to run this is the small embedding model
(`all-MiniLM-L6-v2`) used to search NIST controls. That's not an LLM, it
just measures how similar two pieces of text are.

## Q1: What did you embed, and what did you query directly?

Just one thing: the ~1,000 cleaned NIST 800-53 control texts. It's the only
genuinely free-form text in this system - there's no column that says "use
SI-2 for this bug." Matching a vulnerability to the right control is a
"what does this sound like" problem, so semantic search is the right tool.

Everything else - assets, vulnerabilities, threat intel, business services,
KEV - is queried directly (pandas/SQLite joins). It's all exact-match: an
asset ID either matches a vuln or it doesn't, a CVE is either in KEV or
it isn't. No reason to embed that and turn a certain answer into a guess.
It also matters that 15 of the 40 threat intel rows are meant to not match
anything - an exact lookup makes those correctly return zero matches
instead of fuzzily latching onto something similar. (The one deliberate
exception is a narrow, rule-based ID normalisation for near-misses - see
Q2 #2 - which is still exact matching, just on a cleaned-up ID, and is
flagged for a human to verify.)

`remediation_guidance.csv` isn't used either way. The assignment treats it
as a wording hint, not a source to query, so it doesn't feed the score and
it isn't embedded. Remediation text always comes from the live NIST search.

## Q2: Where could this go wrong?

1. **KEV can lag reality.** If a CVE isn't in CISA KEV yet, this system
   won't call it "actively exploited" even if it actually is - KEV updates
   periodically, not instantly. The threat intel CSV acts as a second,
   independent signal to catch campaigns before they hit KEV. But if
   something's in neither, the system has no way to know. Real fix:
   re-run the KEV fetch on a schedule, not once.

2. **CVE matching can miss the same bug under a different ID.** This
   actually happened in the provided data: the brief says 25 intel rows
   match the environment, but exact matching found 24. The missing one is
   TI-3012 ("HR Data Theft", AmberFox), which lists `CVE-2025-0333` - while
   the file-upload bug on `hr-portal-prod` is recorded as
   `CVE-SYN-2025-0333`. Pure string equality silently dropped it. What I
   did: a second pass compares normalised IDs (synthetic prefix stripped,
   case/whitespace folded). A hit there is kept as a *possible* match -
   labelled "verify" in the report and the JSON (`possible_match_verify`),
   and scored one confidence step lower than the feed claims - rather than
   either trusted or thrown away. It finds exactly that one row and no
   false positives (`tests/test_enrichment.py` pins this). What it still
   can't catch: a genuinely different ID for the same bug (e.g. a vendor
   advisory number, or a CVE range) - that needs an alias table such as
   the NVD/OSV cross-references.

3. **The NIST control it finds might not be the best one.** Semantic
   search isn't a certified mapping table. For an unusual bug the top hit
   could be real and related but still not what an analyst would've
   picked. To keep that visible instead of hidden, the app shows two
   matches instead of one, the actual NIST text instead of a summary, and
   the similarity score - so a weak match looks obviously weak.

4. **LLM phrasing can drift from the facts it's given.** Even told to use
   only the given facts, a model can paraphrase loosely or drop something.
   The fix here is containment, not trust: the LLM never sees raw data,
   only the short fact list the scoring/retrieval code already computed,
   so worst case is an imprecise sentence - not a fabricated CVE or control.
   It never touches the score or the `/api/top5` fields either; those come
   straight from `scoring.py` and `rag.py`. And any failure just falls back
   to the template, so a flaky API degrades phrasing, not the report.
   One drift that did happen: before the prompt was given the rank, Groq
   wrote "ranks highest" for entries #3-#5. Now the prompt states the rank,
   and a sentence for #2-#5 that still claims top rank is rejected in code
   and replaced by the template (`tests/test_explain.py`).

## Q3: If I had one more day

The scoring weights in `app/scoring.py` are numbers I picked by hand to
match the priority order in the MDR advisory, and to make the CVSS-inversion
test hold. They're explainable, but they weren't checked against any
labeled "correct" answer - there isn't one for this dataset, nobody's
ranked which of the 114 findings actually matter most. With another day I'd
build a small reference ranking from what the advisory itself implies
matters most, tune the weights against that, and re-check the inversion
test still passes. Right now the scoring is defensible, but "defensible"
isn't the same as "verified" - that gap is the biggest weak point here.

## The data

`data/`: `assets.csv` (60 rows), `vulnerabilities.csv` (114),
`threat_intelligence.csv` (40), `business_services.csv` (20),
`remediation_guidance.csv` (30, wording hints only), and
`synthetic_threat_report.md` - the MDR advisory the scoring priority order
follows: exposure, then active exploitation, then ransomware association,
then business impact, then missing controls.

Fetched at setup, not committed: the real
[CISA KEV catalog](https://github.com/cisagov/kev-data) and
[NIST SP 800-53 Rev 5](https://github.com/usnistgov/oscal-content).
