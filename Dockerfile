FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PV_DB_PATH=/data/privatevault.db

RUN groupadd --system --gid 10001 privatevault \
    && useradd --system --uid 10001 --gid privatevault --home-dir /nonexistent privatevault \
    && install -d -o privatevault -g privatevault /data

COPY --chown=privatevault:privatevault requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

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
