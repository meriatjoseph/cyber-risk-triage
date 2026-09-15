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
and doesn't need re-embedding on every deploy.
"""
import json
import os
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
        self._backend = "unknown"
        self._collection = None
        self._embedder: Embedder | None = None
        self._build_index(persist=persist)

    def _build_index(self, persist: bool) -> None:
        texts = [c["text"] for c in self.chunks]
        ids = [c["control_id"] for c in self.chunks]

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

        import chromadb

        if persist:
            client = chromadb.PersistentClient(path=str(config.CHROMA_PERSIST_DIR))
        else:
            client = chromadb.EphemeralClient()

        collection_name = f"nist80053_{'st' if isinstance(embedder, SentenceTransformerEmbedder) else 'tfidf'}"
        collection = client.get_or_create_collection(collection_name, metadata={"hnsw:space": "cosine"})

        if persist and collection.count() == len(ids):
            self._collection = collection
            print(f"[rag] reusing persisted index of {len(ids)} NIST 800-53 chunks (backend={self._backend})")
            return

        if collection.count() > 0:
            client.delete_collection(collection_name)
            collection = client.create_collection(collection_name, metadata={"hnsw:space": "cosine"})

        embeddings = embedder.embed(texts)
        batch = 256
        for i in range(0, len(ids), batch):
            collection.add(
                ids=ids[i : i + batch],
                embeddings=embeddings[i : i + batch],
                documents=texts[i : i + batch],
                metadatas=[
                    {"title": c["title"], "family": c["family"]} for c in self.chunks[i : i + batch]
                ],
            )
        self._collection = collection
        print(f"[rag] indexed {len(ids)} NIST 800-53 chunks using backend={self._backend}")

    @property
    def backend_name(self) -> str:
        return self._backend

    def query(self, query_text: str, k: int = 2) -> list[RetrievedControl]:
        query_embedding = self._embedder.embed([query_text])[0]
        result = self._collection.query(query_embeddings=[query_embedding], n_results=k)
        out = []
        by_id = {c["control_id"]: c for c in self.chunks}
        ids = result["ids"][0]
        distances = result.get("distances", [[None] * len(ids)])[0]
        for cid, dist in zip(ids, distances):
            chunk = by_id[cid]
            similarity = 1 - dist if dist is not None else float("nan")
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


def build_query_for_risk(risk) -> str:
    """Builds a short retrieval query from the risk's finding-type language.

    Deliberately built from vulnerability_name / affected_component /
    missing-control signals only -- NOT from remediation_guidance.csv, which
    the assignment spec treats as a hint about expected vocabulary, not a
    lookup source.
    """
    parts = [risk.vulnerability_name, f"affected component: {risk.affected_component}"]
    if not risk.patch_available:
        parts.append("no vendor patch available, unsupported or unpatched component")
    if not risk.edr_installed:
        parts.append("missing endpoint detection and response monitoring")
    if not risk.auth_required:
        parts.append("exploitable without authentication, account and access control weakness")
    if risk.asset_exposure == "Internet":
        parts.append("internet-facing system exposure")
    if risk.any_ransomware_signal:
        parts.append("active exploitation, incident response and flaw remediation needed")
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
