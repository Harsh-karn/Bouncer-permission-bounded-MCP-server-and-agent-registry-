# Multi-stage Dockerfile for Bouncer MCP Server
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY registry/ ./registry/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Production Runner Image
FROM python:3.12-slim AS runner

WORKDIR /app

# Run as non-privileged user for least-privilege security
RUN groupadd -g 10001 bouncer && \
    useradd -u 10001 -g bouncer -s /bin/bash -m bouncer

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/bouncer /usr/local/bin/bouncer
COPY --from=builder /app /app

COPY docs/ ./docs/
COPY supabase/ ./supabase/

USER bouncer:bouncer

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Default command: validate registry at startup and launch server
CMD ["bouncer", "validate"]
