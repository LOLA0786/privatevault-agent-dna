FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PV_DB_PATH=/data/privatevault.db

RUN groupadd --system --gid 10001 privatevault \
    && useradd --system --uid 10001 --gid privatevault --home-dir /nonexistent privatevault \
    && install -d -o privatevault -g privatevault /data

COPY --chown=privatevault:privatevault requirements.txt ./
# PV_DATABASE_URL (several replicas, the Helm chart's default) needs the
# PostgreSQL driver: the `postgres` extra in pyproject.toml.
ARG PV_DB_PACKAGES="psycopg[binary]>=3.2 psycopg-pool>=3.2"
# Signing keys in a KMS (ADR 0023) need the cloud SDK in the image. AWS by
# default; for Google Cloud KMS build with
#   --build-arg PV_KMS_PACKAGES="boto3>=1.40 google-cloud-kms>=3"
# and with PV_KMS_PACKAGES="" for an image without KMS support.
ARG PV_KMS_PACKAGES="boto3>=1.40"
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir $PV_DB_PACKAGES \
    && if [ -n "$PV_KMS_PACKAGES" ]; then pip install --no-cache-dir $PV_KMS_PACKAGES; fi

COPY --chown=privatevault:privatevault agent_dna/ agent_dna/
COPY --chown=privatevault:privatevault api/ api/
COPY --chown=privatevault:privatevault tools/ tools/
COPY --chown=privatevault:privatevault spec/ spec/
COPY --chown=privatevault:privatevault pyproject.toml README.md ./

USER 10001:10001
VOLUME /data

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/ready')"

CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000"]
