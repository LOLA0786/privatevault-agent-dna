# Build context is the repository root:
#   docker build -f network/receiver_kit/Dockerfile -t pv-receiver-gate .
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 privatevault \
    && useradd --system --uid 10001 --gid privatevault --home-dir /nonexistent privatevault \
    && install -d -o privatevault -g privatevault /data /keys

COPY --chown=privatevault:privatevault requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=privatevault:privatevault agent_dna/ agent_dna/
COPY --chown=privatevault:privatevault network/__init__.py network/__init__.py
COPY --chown=privatevault:privatevault network/receiver_kit/*.py network/receiver_kit/

USER 10001:10001

EXPOSE 8080

CMD ["uvicorn", "network.receiver_kit.app:app", "--host", "0.0.0.0", "--port", "8080"]
