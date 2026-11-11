# syntax=docker/dockerfile:1.4
# Multi-stage production backend Dockerfile
# Refer to root Dockerfile.backend for context-at-root builds.
FROM python:3.12-slim-bookworm AS runner
WORKDIR /app

# Copy Node.js and npm directly from the official Node image
COPY --from=node:22-bookworm-slim /usr/local/bin /usr/local/bin
COPY --from=node:22-bookworm-slim /usr/local/lib/node_modules /usr/local/lib/node_modules

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
      git \
      tini && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/app
COPY pytest.ini /app/pytest.ini

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
