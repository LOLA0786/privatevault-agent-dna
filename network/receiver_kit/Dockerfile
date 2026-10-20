# Build context is the repository root:
#   docker build -f network/receiver_kit/Dockerfile -t pv-receiver-gate .
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

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
COPY --chmod=0755 network/receiver_kit/entrypoint.sh /entrypoint.sh

# No USER here on purpose: the entrypoint starts as root only to hand the
# mounted key to the gate user (uid 10001), then drops root before exec.
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
# Mutual TLS unless PV_RECEIVER_ALLOW_PLAINTEXT=1 (local demo); see serve.py.
CMD ["python", "-m", "network.receiver_kit.serve"]
