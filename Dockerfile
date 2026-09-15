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
# sentence-transformers pulls in torch as a transitive dependency. Installed
# plain, pip grabs the default CUDA-enabled wheel (nvidia-cublas, cudnn,
# triton, ~2GB+) even though this container has no GPU -- that bloats both
# the image and, more importantly, runtime memory, and is what pushed the
# free-tier 512MB Render instance out of memory at startup. Installing the
# CPU-only build first satisfies sentence-transformers' torch requirement
# without pip ever reaching for the GPU wheel.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Render's free tier caps a container at 512MB RAM. Importing torch +
# sentence-transformers alone costs ~450MB RSS before any model is even
# loaded -- measured directly, not estimated -- which OOMs that tier. This
# forces the lighter scikit-learn-only fallback embedder (already built for
# offline use, see app/rag.py) for both the index built below and at
# runtime, so torch/sentence-transformers are never imported in this image.
# Local dev (outside Docker) is unaffected and still gets the full model.
ENV EMBEDDER_BACKEND=tfidf

# Fetch reference data (real CISA KEV + real NIST SP 800-53) and build the
# RAG corpus/index at image build time, so cold starts don't hit the network.
RUN python scripts/fetch_kev.py && \
    python scripts/fetch_nist.py && \
    python -c "from app.rag import NistControlRetriever; NistControlRetriever()"

ENV HF_HUB_OFFLINE=1

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
