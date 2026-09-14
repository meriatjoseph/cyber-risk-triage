"""
Explanation layer: turns already-computed structured facts into the one
plain-English "why it ranks here" sentence for each top-5 risk.

Default path is a deterministic template -- it can only restate facts the
scoring engine actually computed, so it cannot hallucinate a campaign match,
a control gap, or a business-impact detail that isn't really there.

Optional enhancement: if a free-tier Groq API key is present in the
GROQ_API_KEY environment variable, we ask a small free Llama model to
rewrite the same fact list into a smoother sentence, with an explicit
instruction to use only the given facts and invent nothing. If the call
fails for any reason (no key, no network, rate limit), we silently fall back
to the template -- the report must never depend on an external API being up.
"""
import os

from app import config
from app.enrichment import EnrichedRisk
from app.scoring import ScoreBreakdown


def _template_explanation(rank: int, risk: EnrichedRisk, score: ScoreBreakdown) -> str:
    reasons = score.reasons[:3]
    if not reasons:
        reasons = ["elevated relative to peer findings once exposure, exploitation, and business impact are weighed together"]
    reason_text = "; ".join(reasons)
    return (
        f"Ranked #{rank} (score {score.total:.0f}/100) because {reason_text}."
    )


def _groq_explanation(rank: int, risk: EnrichedRisk, score: ScoreBreakdown) -> str | None:
    api_key = os.environ.get(config.GROQ_API_KEY_ENV)
    if not api_key:
        return None
    try:
        import requests

        facts = "\n".join(f"- {r}" for r in score.reasons) or "- no single dominant factor; combination of moderate signals"
        prompt = (
            "You are a security analyst writing ONE plain-English sentence explaining why a "
            "specific risk finding ranks where it does in a prioritised report. "
            "Use ONLY the facts listed below. Do not invent any fact, number, CVE, or campaign "
            "name that is not in the list. Do not mention the numeric score. Output exactly one sentence.\n\n"
            f"Asset: {risk.asset_name} ({risk.asset_type})\n"
            f"Vulnerability: {risk.vulnerability_name} ({risk.cve})\n"
            f"Business service: {risk.business_service}\n"
            f"Facts:\n{facts}\n\n"
            "One-sentence explanation:"
        )
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": config.GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 120,
            },
            timeout=15,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        return content if content else None
    except Exception as e:  # noqa: BLE001 - never let LLM issues break the report
        print(f"[explain] Groq call failed, falling back to template: {e}")
        return None


def explain_risk(rank: int, risk: EnrichedRisk, score: ScoreBreakdown) -> str:
    llm_text = _groq_explanation(rank, risk, score)
    return llm_text if llm_text else _template_explanation(rank, risk, score)
