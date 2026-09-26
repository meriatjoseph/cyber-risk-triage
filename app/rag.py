"""
RAG layer over the real NIST SP 800-53 Rev 5 control catalog.

Only the NIST control prose is embedded. Everything else in this system
(assets, vulns, threat intel, business services, KEV) is exact structured
data queried via joins/filters (see app/ingestion.py, app/enrichment.py) --
retrieval is reserved for the one genuinely unstructured, free-text corpus
where semantic similarity (not exact match) is the right tool. See README Q1.

Two interchangeable embedding backends behind the same embed() interface:
  - primary:  sentence-transformers/all-MiniLM-L6-v2 (free, local, downloads
              once from Hugging Face, then runs fully offline)
  - fallback: TF-IDF + TruncatedSVD (scikit-learn only, no internet/HF
              needed) -- used automatically if the ST model can't be loaded
              (e.g. no internet access to Hugging Face in this environment)

Vector store: ChromaDB, persisted to .chroma/ so the index survives restarts
and doesn't need re-embedding on every deploy. The index holds passages,
not whole controls: MiniLM only reads 256 tokens, so the 176 longer
controls are split into header-prefixed passages (1,243 in total) and each
control is scored by its best passage. A persisted index is reused only if
a SHA-256 of its passages matches the current corpus.
"""
import hashlib
import json
import os
import re
from dataclasses import dataclass

from app import config

_EMBEDDING_DIM_FALLBACK = 256


class Embedder:
    """Common interface: embed(list[str]) -> list[list[float]]"""

    backend_name: str

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError


class SentenceTransformerEmbedder(Embedder):
    backend_name = "sentence-transformers/all-MiniLM-L6-v2"

    def __init__(self):
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        # MiniLM silently truncates anything past max_seq_length (256) tokens.
        # 176 of the 1,014 NIST chunks are longer, so they're split into
        # passages that fit (see split_into_passages). 2 slots are reserved
        # for the [CLS]/[SEP] tokens the tokenizer adds.
        self.token_budget = self.model.max_seq_length - 2

    def token_len(self, text: str) -> int:
        # verbose=False: counting a long text is the point here, so the
        # tokenizer's "longer than max length" warning is just noise.
        return len(self.model.tokenizer(text, add_special_tokens=False, verbose=False)["input_ids"])

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts, show_progress_bar=False, normalize_embeddings=True).tolist()


class TfidfSvdEmbedder(Embedder):
    """Offline fallback used only if sentence-transformers/HF is unreachable."""

    backend_name = "tfidf+truncated-svd (offline fallback)"

    def __init__(self, corpus_texts: list[str]):
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.vectorizer = TfidfVectorizer(max_features=20000, stop_words="english")
        matrix = self.vectorizer.fit_transform(corpus_texts)
        n_components = min(_EMBEDDING_DIM_FALLBACK, matrix.shape[1] - 1, matrix.shape[0] - 1)
        self.svd = TruncatedSVD(n_components=max(n_components, 2), random_state=42)
        self.svd.fit(matrix)

    def embed(self, texts: list[str]) -> list[list[float]]:
        matrix = self.vectorizer.transform(texts)
        return self.svd.transform(matrix).tolist()


def load_nist_chunks() -> list[dict]:
    if not config.NIST_CHUNKS_JSONL.exists():
        raise FileNotFoundError(
            f"{config.NIST_CHUNKS_JSONL} not found. Run scripts/fetch_nist.py first."
        )
    chunks = []
    with config.NIST_CHUNKS_JSONL.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                chunks.append(json.loads(line))
    return chunks


_SENTENCE_BREAK_RE = re.compile(r"(?<=[.;:])\s+")


def split_into_passages(chunk: dict, token_len, budget: int) -> list[str]:
    """Splits one NIST control chunk into passages of at most `budget` tokens.

    Each passage starts with the control's "<ID> <Title>" header so it still
    reads as that control on its own. Text is packed greedily by line, then
    by sentence, so boundaries fall on natural breaks; a single sentence
    longer than the budget is split by words as a last resort. A chunk that
    already fits comes back unchanged as one passage.
    """
    text = chunk["text"]
    if token_len(text) <= budget:
        return [text]

    header = f"{chunk['control_id']} {chunk['title']}"
    body = text[len(header):].strip() if text.startswith(header) else text
    room = budget - token_len(header + "\n") - 1

    pieces: list[str] = []
    for line in (ln.strip() for ln in body.split("\n")):
        if not line:
            continue
        for sentence in _SENTENCE_BREAK_RE.split(line):
            if token_len(sentence) <= room:
                pieces.append(sentence)
                continue
            words, part = sentence.split(), []
            for w in words:
                if part and token_len(" ".join(part + [w])) > room:
                    pieces.append(" ".join(part))
                    part = []
                part.append(w)
            if part:
                pieces.append(" ".join(part))

    passages, current = [], []
    for piece in pieces:
        if current and token_len(" ".join(current + [piece])) > room:
            passages.append(f"{header}\n{' '.join(current)}")
            current = []
        current.append(piece)
    if current:
        passages.append(f"{header}\n{' '.join(current)}")
    return passages


@dataclass
class RetrievedControl:
    control_id: str
    title: str
    family: str
    statement: str
    discussion: str
    text: str
    similarity: float


class NistControlRetriever:
    def __init__(self, persist: bool = True):
        self.chunks = load_nist_chunks()
        self._by_id = {c["control_id"]: c for c in self.chunks}
        self._backend = "unknown"
        self._collection = None
        self._embedder: Embedder | None = None
        self.passage_count = 0
        self._build_index(persist=persist)

    def _build_index(self, persist: bool) -> None:
        texts = [c["text"] for c in self.chunks]

        # torch + sentence-transformers add ~450MB of RSS just from being
        # imported, before any model or index exists -- fine locally, but
        # over the 512MB ceiling on Render's free tier. EMBEDDER_BACKEND=tfidf
        # (set in the Dockerfile) skips importing them entirely rather than
        # loading and discarding them, so the deployed container never pays
        # that cost. Local runs are unaffected and keep the full model.
        if os.environ.get("EMBEDDER_BACKEND") == "tfidf":
            print("[rag] EMBEDDER_BACKEND=tfidf set; using TF-IDF+SVD to stay within memory limits")
            embedder = TfidfSvdEmbedder(texts)
        else:
            try:
                embedder = SentenceTransformerEmbedder()
            except Exception as e:  # noqa: BLE001 - deliberate broad fallback
                print(f"[rag] sentence-transformers unavailable ({e}); falling back to TF-IDF+SVD")
                embedder = TfidfSvdEmbedder(texts)
        self._embedder = embedder
        self._backend = embedder.backend_name

        # One index row per passage, not per control. MiniLM needs long
        # controls split to stay under its 256-token limit; TF-IDF has no
        # length limit, so it keeps one passage per control (unchanged).
        passage_ids, passage_texts, metadatas = [], [], []
        for c in self.chunks:
            if isinstance(embedder, SentenceTransformerEmbedder):
                parts = split_into_passages(c, embedder.token_len, embedder.token_budget)
            else:
                parts = [c["text"]]
            for n, part in enumerate(parts):
                passage_ids.append(f"{c['control_id']}#{n}")
                passage_texts.append(part)
                metadatas.append({"control_id": c["control_id"], "title": c["title"], "family": c["family"]})
        self.passage_count = len(passage_ids)

        # Fingerprint of exactly what gets embedded: a persisted index is only
        # reused if it was built from the same passages. (Comparing row counts
        # alone would silently reuse stale vectors after a same-size change.)
        fingerprint = hashlib.sha256(
            "\x1e".join(f"{i}\x1f{t}" for i, t in zip(passage_ids, passage_texts)).encode("utf-8")
        ).hexdigest()
        collection_meta = {"hnsw:space": "cosine", "corpus_sha256": fingerprint}

        import chromadb

        if persist:
            client = chromadb.PersistentClient(path=str(config.CHROMA_PERSIST_DIR))
        else:
            client = chromadb.EphemeralClient()

        collection_name = f"nist80053_{'st' if isinstance(embedder, SentenceTransformerEmbedder) else 'tfidf'}"
        collection = client.get_or_create_collection(collection_name, metadata=collection_meta)

        if (
            persist
            and (collection.metadata or {}).get("corpus_sha256") == fingerprint
            and collection.count() == len(passage_ids)
        ):
            self._collection = collection
            print(
                f"[rag] reusing persisted index of {len(passage_ids)} passages from "
                f"{len(self.chunks)} NIST 800-53 controls (backend={self._backend})"
            )
            return

        if collection.count() > 0 or (collection.metadata or {}).get("corpus_sha256") != fingerprint:
            client.delete_collection(collection_name)
            collection = client.create_collection(collection_name, metadata=collection_meta)

        embeddings = embedder.embed(passage_texts)
        batch = 256
        for i in range(0, len(passage_ids), batch):
            collection.add(
                ids=passage_ids[i : i + batch],
                embeddings=embeddings[i : i + batch],
                documents=passage_texts[i : i + batch],
                metadatas=metadatas[i : i + batch],
            )
        self._collection = collection
        print(
            f"[rag] indexed {len(passage_ids)} passages from {len(self.chunks)} NIST 800-53 "
            f"controls using backend={self._backend}"
        )

    @property
    def backend_name(self) -> str:
        return self._backend

    def query(self, query_text: str, k: int = 2) -> list[RetrievedControl]:
        """Top-k distinct controls. Several passages of one control can rank
        near each other, so more passages than k are fetched and each
        control is scored by its best-matching passage."""
        query_embedding = self._embedder.embed([query_text])[0]
        n = min(max(k * 8, 20), self.passage_count)
        result = self._collection.query(query_embeddings=[query_embedding], n_results=n)
        best: dict[str, float] = {}
        metas = result["metadatas"][0]
        distances = result.get("distances", [[None] * len(metas)])[0]
        for meta, dist in zip(metas, distances):
            similarity = 1 - dist if dist is not None else float("nan")
            cid = meta["control_id"]
            if cid not in best or similarity > best[cid]:
                best[cid] = similarity
        out = []
        for cid, similarity in sorted(best.items(), key=lambda kv: -kv[1])[:k]:
            chunk = self._by_id[cid]
            out.append(
                RetrievedControl(
                    control_id=chunk["control_id"],
                    title=chunk["title"],
                    family=chunk["family"],
                    statement=chunk["statement"],
                    discussion=chunk["discussion"],
                    text=chunk["text"],
                    similarity=similarity,
                )
            )
        return out

    def query_for_risk(self, risk, k: int = 2) -> list[RetrievedControl]:
        """Retrieves NIST controls for one risk.

        Runs the base finding-level query (build_query_for_risk), and --
        for a recognised vulnerability class (buffer overflow, injection,
        broken access control, missing patch, ...) -- a second query
        phrased in that class's own control vocabulary (see
        _VULN_CLASS_HINTS), then merges both result sets by similarity.

        Why two queries instead of one: a single blended query mixes
        distinct concerns into one mean-pooled vector -- e.g. "Fortinet
        SSL-VPN Heap Buffer Overflow RCE" embeds closer to remote-access/
        networking controls than to the memory-corruption control that
        actually applies, because "VPN" dominates the sentence. Querying
        the vulnerability class on its own, in parallel with the literal
        finding text, and merging by similarity keeps each concern legible
        to the embedding instead of averaging them into a control that
        matches neither well. The real NIST corpus still decides what
        comes back for either query -- this only changes how the question
        is asked, not the answer.
        """
        candidates: dict[str, RetrievedControl] = {}

        def add_all(results: list[RetrievedControl]) -> None:
            for c in results:
                existing = candidates.get(c.control_id)
                if existing is None or c.similarity > existing.similarity:
                    candidates[c.control_id] = c

        add_all(self.query(build_query_for_risk(risk), k=k))
        hint = _class_hint_query(risk)
        if hint:
            add_all(self.query(hint, k=k))

        return sorted(candidates.values(), key=lambda c: -c.similarity)[:k]


# Query expansion for _query_for_risk: vulnerability names that name a
# specific weakness class read, semantically, as much about the *carrier*
# (VPN, API, database) as about the *weakness* (buffer overflow, broken
# access control). Each hint below is a short restatement of that weakness
# class in NIST's own control-statement vocabulary (not naming a specific
# control ID), used as a second, focused retrieval query -- see
# NistControlRetriever.query_for_risk.
_VULN_CLASS_HINTS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"buffer overflow|heap overflow|memory corruption", re.I),
        "protect system memory from unauthorized or malicious code execution, "
        "memory protection against buffer overflow attacks",
    ),
    (
        re.compile(
            r"\brce\b|remote code execution|deserialization|template injection|"
            r"ognl injection|argument injection|sql injection|file upload to rce",
            re.I,
        ),
        "check the validity and syntax of information inputs to prevent injection "
        "and remote code execution attacks",
    ),
    (
        re.compile(
            r"insecure direct object reference|\bidor\b|broken access control|"
            r"excessive .*(permission|privilege)s?|privilege escalation",
            re.I,
        ),
        "enforce approved authorizations for logical access to information and "
        "system resources, employ the principle of least privilege",
    ),
    (
        re.compile(
            r"authentication bypass|hardcoded credential|weak .*password|"
            r"ntlm hash|session fixation",
            re.I,
        ),
        "uniquely identify and authenticate users and devices before allowing "
        "access, manage authenticators and credentials",
    ),
    (
        re.compile(
            r"end of life|end of support|unsupported .*(component|version)|"
            r"outdated .*(version|runtime|firmware)|missing patch|"
            r"critical vendor advisory",
            re.I,
        ),
        "identify, report, and correct system flaws, install security-relevant "
        "software and firmware updates, replace unsupported system components",
    ),
    (
        re.compile(r"no edr|missing edr|edr agent", re.I),
        "implement malicious code protection and endpoint detection mechanisms "
        "at system entry and exit points",
    ),
    (
        re.compile(r"denial of service|\bdos\b", re.I),
        "provide denial-of-service protection for the system",
    ),
    (
        re.compile(
            r"unencrypted|missing encryption|encryption at rest|"
            r"encryption not enforced|backup encryption",
            re.I,
        ),
        "protect the confidentiality of information at rest and in transit "
        "through cryptographic mechanisms",
    ),
    (
        re.compile(r"cross-site scripting|\bxss\b", re.I),
        "check the validity of information inputs to prevent injection of "
        "malicious script content",
    ),
    # Exposed admin/management planes (Kong admin API, K8s dashboard, VPN
    # management plane). Without this, "Kong Gateway Admin API Exposed" had no
    # hint and the TF-IDF backend returned a physical-access control. Kept last
    # so "Unencrypted Management Interface" still takes the encryption hint.
    (
        re.compile(
            r"admin (api|interface|panel|console|portal)|"
            r"management (interface|console|port|api|plane)|"
            r"(dashboard|console) exposed|exposed .*(admin|dashboard|console)",
            re.I,
        ),
        "restrict network access to privileged administrative and management "
        "interfaces, separate system management functionality from user "
        "functionality, route privileged remote access through managed access "
        "control points",
    ),
]


def _class_hint_query(risk) -> str | None:
    haystack = f"{risk.vulnerability_name} {risk.affected_component or ''}"
    for pattern, hint in _VULN_CLASS_HINTS:
        if pattern.search(haystack):
            return hint
    return None


def build_query_for_risk(risk) -> str:
    """Builds a short retrieval query from the risk's finding-type language.

    Deliberately built from vulnerability_name / affected_component /
    missing-control signals only -- NOT from remediation_guidance.csv, which
    the assignment spec treats as a hint about expected vocabulary, not a
    lookup source.

    vulnerability_name/affected_component are repeated: they're the only
    part of this query that differs risk-to-risk in practice, since a top-5
    list mostly shares the same exposure/EDR/auth/ransomware flags (that's
    part of why those risks rank top-5). Under semantic embeddings that
    repetition is a no-op, but the TF-IDF fallback backend (EMBEDDER_BACKEND
    =tfidf, used in the Docker deploy -- see app/rag.py module docstring)
    is a literal-token method: without the repeat, the shared boilerplate
    phrases below dominated cosine similarity and every risk collapsed onto
    the same one or two NIST controls regardless of vulnerability type.
    """
    parts = [
        f"{risk.vulnerability_name}. {risk.vulnerability_name}. "
        f"affected component: {risk.affected_component}. {risk.affected_component}"
    ]
    if not risk.patch_available:
        parts.append("no vendor patch available, unsupported or unpatched component")
    if not risk.edr_installed:
        parts.append("missing endpoint detection and response monitoring")
    if not risk.auth_required:
        parts.append("exploitable without authentication, account and access control weakness")
    if risk.asset_exposure == "Internet":
        parts.append("internet-facing system exposure")
    if risk.any_ransomware_signal:
        parts.append("actively exploited by threat campaign, remediation required")
    return ". ".join(parts)


if __name__ == "__main__":
    retriever = NistControlRetriever()
    test_queries = [
        "Remote code execution in unpatched internet-facing web framework, no EDR",
        "VPN appliance authentication bypass actively exploited",
        "Missing account management and unauthorized privileged access",
        "Unsupported end-of-life operating system with no vendor patches",
    ]
    for q in test_queries:
        print(f"\nQuery: {q}")
        for hit in retriever.query(q, k=2):
            print(f"  {hit.control_id} - {hit.title}  (sim={hit.similarity:.3f})")
