FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent_dna/ agent_dna/
COPY api/ api/
COPY tools/ tools/
COPY spec/ spec/
COPY pyproject.toml README.md ./

ENV PV_DB_PATH=/data/privatevault.db
VOLUME /data

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000"]
