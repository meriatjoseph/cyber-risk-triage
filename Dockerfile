FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    HF_HOME=/app/.cache/huggingface \
    PORT=8000

# HF_HUB_OFFLINE is set only after the build step below has already
# downloaded and cached the embedding model into HF_HOME -- it skips a
# ~5s Hugging Face Hub network round-trip on every container start/restart
# that would otherwise happen even though the model is already cached.

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fetch reference data (real CISA KEV + real NIST SP 800-53) and build the
# RAG corpus/index at image build time, so cold starts don't hit the network.
RUN python scripts/fetch_kev.py && \
    python scripts/fetch_nist.py && \
    python -c "from app.rag import NistControlRetriever; NistControlRetriever()"

ENV HF_HUB_OFFLINE=1

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
