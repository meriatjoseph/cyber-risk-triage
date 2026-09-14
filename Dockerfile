FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    HF_HOME=/app/.cache/huggingface \
    PORT=8000

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fetch reference data (real CISA KEV + real NIST SP 800-53) and build the
# RAG corpus/index at image build time, so cold starts don't hit the network.
RUN python scripts/fetch_kev.py && \
    python scripts/fetch_nist.py && \
    python -c "from app.rag import NistControlRetriever; NistControlRetriever()"

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
