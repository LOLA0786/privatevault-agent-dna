# Build context is the repository root:
#   docker compose -f proof/docker-compose.yml up
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 privatevault \
    && useradd --system --uid 10001 --gid privatevault --home-dir /tmp privatevault

COPY requirements.txt ./
# httpx: the in-process API client (starlette TestClient) the proofs use.
RUN pip install --no-cache-dir -r requirements.txt "httpx>=0.27"

COPY agent_dna/ agent_dna/
COPY api/ api/
COPY tools/ tools/
COPY network/__init__.py network/__init__.py
COPY network/receiver_kit/*.py network/receiver_kit/
COPY agents/ agents/
COPY proof/ proof/

USER 10001:10001

CMD ["python", "-m", "proof.run_all"]
