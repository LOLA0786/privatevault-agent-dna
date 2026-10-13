# One image for the three demo services. Build context is the repository root:
#   docker compose -f demos/live_checkout/docker-compose.yml up --build
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY agent_dna/ agent_dna/
COPY api/ api/
COPY tools/ tools/
COPY spec/ spec/
COPY network/__init__.py network/__init__.py
COPY network/receiver_kit/*.py network/receiver_kit/
COPY agents/__init__.py agents/__init__.py
COPY agents/core/ agents/core/
COPY demos/__init__.py demos/__init__.py
COPY demos/live_checkout/*.py demos/live_checkout/refund_queue.json demos/live_checkout/
COPY demos/live_checkout/services/ demos/live_checkout/services/
COPY pyproject.toml README.md ./

# Demo containers run as root so the bind-mounted 0600 key files written by
# bootstrap.py on the host are readable. A production gate uses the receiver
# kit's own image and entrypoint, which hands the key to an unprivileged user.
VOLUME /data
