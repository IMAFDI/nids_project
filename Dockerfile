# NIDS Backend Dockerfile (multi-stage build, non-root user)
FROM python:3.11-slim AS builder

WORKDIR /build
COPY config/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 nids && \
    useradd --uid 1000 --gid nids --shell /bin/bash --create-home nids

WORKDIR /home/nids

# Copy installed packages from builder
COPY --from=builder /root/.local /home/nids/.local

# Copy application code
COPY --chown=nids:nids config/ ./config/
COPY --chown=nids:nids models/ ./models/
# Create logs directory (don't copy local logs - they should be fresh in container)
RUN mkdir -p ./logs && chown nids:nids ./logs
COPY --chown=nids:nids api/ ./api/

ENV PATH=/home/nids/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

USER nids
EXPOSE 5000 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["api.main:app", "--host", "0.0.0.0", "--port", "8000"]
