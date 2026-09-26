"""
Explanation layer: turns already-computed structured facts into the one
plain-English "why it ranks here" sentence for each top-5 risk.

Default path is a deterministic template -- it can only restate facts the
scoring engine actually computed, so it cannot hallucinate a campaign match,
a control gap, or a business-impact detail that isn't really there.

Optional enhancement: if a free-tier Groq API key is present in the
GROQ_API_KEY environment variable, we ask a small free open-weight model to
rewrite the same fact list into a smoother sentence AND weave in the
already-retrieved top NIST control (id + title only -- the control was
found by app/rag.py's embedding search, not by the LLM), with an explicit
instruction to use only the given facts and invent nothing. This is the one
place a generative model earns its keep here: language generation over
facts the system already computed, never fact generation. If the call fails
for any reason (no key, no network, rate limit), we silently fall back to
the template -- the report must never depend on an external API being up.
"""
import os
import re

from app import config
from app.enrichment import EnrichedRisk
from app.rag import RetrievedControl
from app.scoring import ScoreBreakdown

# Claims of being #1. If a lower-ranked sentence still says this despite the
# prompt, it's factually wrong, so it's discarded in favour of the template.
_TOP_RANK_CLAIM_RE = re.compile(
    r"\b(ranks?|ranked|ranking)\s+(the\s+)?(highest|first|top)\b|"
    r"\b(highest|top)[- ]ranked\b|\b(ranks?|ranked)\s+#?1\b|\bnumber one\b",
    re.I,
)


def _also_affected_text(also_affected) -> str:
    return ", ".join(f"{o.asset_name} ({o.business_service})" for o, _ in also_affected or [])


def _template_explanation(
    rank: int, risk: EnrichedRisk, score: ScoreBreakdown, also_affected=None
) -> str:
    reasons = score.reasons[:3]
    if not reasons:
        reasons = ["elevated relative to peer findings once exposure, exploitation, and business impact are weighed together"]
    reason_text = "; ".join(reasons)
    text = f"Ranked #{rank} (score {score.total:.0f}/100) because {reason_text}."
    if also_affected:
        text += f" The same finding is also open on {_also_affected_text(also_affected)}."
    return text


def _groq_explanation(
    rank: int,
    risk: EnrichedRisk,
    score: ScoreBreakdown,
    nist_controls: list[RetrievedControl] | None = None,
    also_affected=None,
) -> str | None:
    api_key = os.environ.get(config.GROQ_API_KEY_ENV)
    if not api_key:
        return None
    try:
        import requests

        facts = "\n".join(f"- {r}" for r in score.reasons) or "- no single dominant factor; combination of moderate signals"
        top_control = nist_controls[0] if nist_controls else None
        control_line = (
            f"\nMatching NIST SP 800-53 control (already retrieved, do not change): "
            f"{top_control.control_id} - {top_control.title}\n"
            if top_control
            else ""
        )
        also_line = (
            f"Same finding also open on: {_also_affected_text(also_affected)}\n" if also_affected else ""
        )
        prompt = (
            "You are a security analyst writing ONE plain-English sentence explaining why a "
            "specific risk finding ranks where it does in a prioritised report, and naming the "
            "recommended NIST control. "
            "Use ONLY the facts listed below. Do not invent any fact, number, CVE, campaign "
            "name, or control id that is not in the list. Do not mention the numeric score. "
            # Without the rank the model guessed, and wrote "ranks highest"
            # for #3-#5 too. Give it the rank and forbid superlatives elsewhere.
            f"This finding is ranked #{rank} of {config.TOP_N_RISKS}. "
            + (
                "You may say it ranks highest. "
                if rank == 1
                else f"Do NOT say it ranks highest, first, or top; if you mention its position, say #{rank}. "
            )
            + "Output exactly one sentence.\n\n"
            f"Asset: {risk.asset_name} ({risk.asset_type})\n"
            f"Vulnerability: {risk.vulnerability_name} ({risk.cve})\n"
            f"Business service: {risk.business_service}\n"
            f"{also_line}"
            f"Facts:\n{facts}\n"
            f"{control_line}\n"
            "One-sentence explanation:"
        )
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": config.GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 300,
                # config.GROQ_MODEL is a reasoning model on Groq: it spends part of
                # max_tokens on a hidden reasoning pass before the visible answer,
                # so a small budget here can silently truncate content to "" without
                # ever raising -- keep this low and max_tokens generous.
                "reasoning_effort": "low",
            },
            timeout=20,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        if not content:
            print("[explain] Groq returned empty content, falling back to template")
            return None
        if rank != 1 and _TOP_RANK_CLAIM_RE.search(content):
            print(f"[explain] Groq sentence for #{rank} claims top rank, falling back to template")
            return None
        return content
    except Exception as e:  # noqa: BLE001 - never let LLM issues break the report
        print(f"[explain] Groq call failed, falling back to template: {e}")
        return None


def explain_risk(
    rank: int,
    risk: EnrichedRisk,
    score: ScoreBreakdown,
    nist_controls: list[RetrievedControl] | None = None,
    also_affected=None,
) -> str:
    llm_text = _groq_explanation(rank, risk, score, nist_controls, also_affected)
    return llm_text if llm_text else _template_explanation(rank, risk, score, also_affected)
