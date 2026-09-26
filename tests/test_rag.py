"""Passage splitting (the MiniLM 256-token limit) and index reuse.

Uses a whitespace word count as the token counter and the TF-IDF backend
on a tiny synthetic corpus, so no model download or network is needed."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config, rag


def words(text: str) -> int:
    return len(text.split())


def _chunk(cid: str, title: str, body: str) -> dict:
    return {
        "control_id": cid, "title": title, "family": "Test", "statement": body,
        "discussion": "", "text": f"{cid} {title}\n\nStatement:\n{body}",
    }


LONG = _chunk(
    "SI-99", "Long Control",
    "\n".join(f"Sentence {i} talks about memory protection and flaw remediation." for i in range(40)),
)


def test_short_chunk_is_one_unchanged_passage():
    c = _chunk("AC-1", "Short", "Enforce access.")
    assert rag.split_into_passages(c, words, budget=50) == [c["text"]]


def test_long_chunk_splits_under_budget_with_header_and_no_lost_text():
    passages = rag.split_into_passages(LONG, words, budget=40)
    assert len(passages) > 1
    assert all(words(p) <= 40 for p in passages)
    assert all(p.startswith("SI-99 Long Control\n") for p in passages)
    joined = " ".join(passages)
    assert all(w in joined for w in LONG["text"].split())


def test_single_oversized_sentence_is_split_by_words():
    c = _chunk("SC-99", "Run-on", " ".join(f"w{i}" for i in range(100)))
    passages = rag.split_into_passages(c, words, budget=30)
    assert all(words(p) <= 30 for p in passages)
    assert " ".join(passages).count("w99") == 1


def _corpus():
    return [
        _chunk("AC-2", "Account Management", "Manage system accounts and access."),
        _chunk("SI-2", "Flaw Remediation", "Identify, report and correct system flaws; install patches."),
        _chunk("SI-16", "Memory Protection", "Protect system memory from unauthorized code execution."),
        _chunk("SC-5", "Denial of Service Protection", "Limit the effects of denial of service events."),
    ]


def _retriever(monkeypatch, tmp_path, corpus):
    monkeypatch.setenv("EMBEDDER_BACKEND", "tfidf")
    monkeypatch.setattr(config, "CHROMA_PERSIST_DIR", tmp_path)
    monkeypatch.setattr(rag, "load_nist_chunks", lambda: corpus)
    return rag.NistControlRetriever(persist=True)


def test_query_returns_distinct_controls(monkeypatch, tmp_path):
    ret = _retriever(monkeypatch, tmp_path, _corpus())
    hits = ret.query("unauthorized code execution in memory", k=2)
    assert hits[0].control_id == "SI-16"
    assert len({h.control_id for h in hits}) == 2


def test_persisted_index_reused_only_when_corpus_unchanged(monkeypatch, tmp_path, capsys):
    corpus = _corpus()
    _retriever(monkeypatch, tmp_path, corpus)
    _retriever(monkeypatch, tmp_path, corpus)
    assert "reusing persisted index" in capsys.readouterr().out

    # same number of controls, different text: must rebuild, not reuse
    changed = _corpus()
    changed[0] = _chunk("AC-2", "Account Management", "Totally different wording about accounts.")
    ret = _retriever(monkeypatch, tmp_path, changed)
    out = capsys.readouterr().out
    assert "reusing" not in out and "indexed 4 passages" in out
    assert "Totally different" in ret._collection.get(ids=["AC-2#0"])["documents"][0]
