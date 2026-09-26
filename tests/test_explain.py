"""Explanation layer: the Groq prompt carries the real rank, and a sentence
that still claims top rank for a lower entry is discarded for the template.
requests.post is stubbed, so no network call is made."""
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import explain
from app.rag import _class_hint_query
from app.scoring import score_risk
from tests.test_scoring import make_exposed_payment_gateway_active_campaign


class _Resp:
    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


@pytest.fixture
def groq(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    sent = {}

    def stub(content):
        def post(url, headers=None, json=None, timeout=None):
            sent["prompt"] = json["messages"][0]["content"]
            return _Resp(content)

        monkeypatch.setattr(requests, "post", post)
        return sent

    return stub


def _risk():
    r = make_exposed_payment_gateway_active_campaign()
    return r, score_risk(r)


def test_prompt_states_rank_and_forbids_top_claim_below_first(groq):
    sent = groq("It is exposed and actively exploited, so AC-6 applies.")
    r, s = _risk()
    explain.explain_risk(3, r, s)
    assert "ranked #3 of 5" in sent["prompt"]
    assert "Do NOT say it ranks highest" in sent["prompt"]


def test_rank_one_may_say_highest(groq):
    groq("This finding ranks highest because it is exposed and exploited.")
    r, s = _risk()
    assert explain.explain_risk(1, r, s) == "This finding ranks highest because it is exposed and exploited."


def test_top_rank_claim_below_first_falls_back_to_template(groq):
    groq("This finding ranks highest because it is exposed and exploited.")
    r, s = _risk()
    text = explain.explain_risk(4, r, s)
    assert text.startswith("Ranked #4 (score ")


def test_admin_interface_findings_get_their_own_retrieval_hint():
    r, _ = _risk()
    r.vulnerability_name, r.affected_component = "Kong Gateway Admin API Exposed", "API Admin Interface"
    assert "administrative and management interfaces" in _class_hint_query(r)
    # encryption hint is checked first and still wins for this one
    r.vulnerability_name, r.affected_component = "Unencrypted Management Interface", "Management Plane"
    assert "cryptographic" in _class_hint_query(r)
