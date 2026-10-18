#!/usr/bin/env bash
# Install the chart on a kind cluster the way an operator would and check what
# the deployment enforces: secure profile, two replicas on PostgreSQL, real
# keys from tools/init_secure_profile.py, then helm test and
# tools/verify_deployment.py (lineage enforced, decisions signed, durable
# grants, self-approval refused). Needs: kind cluster, helm, kubectl, docker.
set -euo pipefail
NS=privatevault
CHART=deploy/helm/privatevault
IMAGE=privatevault-agent-dna:ci
work=$(mktemp -d)

dump() {
  kubectl -n "$NS" get pods -o wide || true
  kubectl -n "$NS" describe pods || true
  kubectl -n "$NS" logs -l app.kubernetes.io/name=privatevault --all-containers --tail=200 || true
}
trap 'dump' ERR

docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "${KIND_CLUSTER:-pv}"

python tools/init_secure_profile.py --out "$work/pv" --org ci.example >/dev/null
set -a
# shellcheck disable=SC1091
. "$work/pv/secure.env"
set +a

kubectl create namespace "$NS"
kubectl -n "$NS" apply -f "$CHART/ci/postgres.yaml"
kubectl -n "$NS" rollout status deploy/pg --timeout=180s
kubectl -n "$NS" create secret generic pv-secrets \
  --from-file=keys.json="$work/pv/keys.json" \
  --from-file=execution-signer.key="$work/pv/execution-signer.key" \
  --from-file=dispatch-witness.key="$work/pv/dispatch-witness.key" \
  --from-literal=receipt-signing-key="$PV_RECEIPT_SIGNING_KEY" \
  --from-literal=database-url=postgresql://postgres:postgres@pg:5432/postgres
kubectl -n "$NS" create configmap pv-config \
  --from-file=grants.json="$work/pv/grants.json" \
  --from-file=trust-bundle.json="$work/pv/trust-bundle.json"

helm install pv "$CHART" -n "$NS" -f "$CHART/ci/postgres-values.yaml" \
  --set signing.trustedPublicKeys="$PV_TRUSTED_PUBLIC_KEYS" \
  --wait --timeout 5m
ready=$(kubectl -n "$NS" get deploy pv-privatevault -o jsonpath='{.status.readyReplicas}')
test "$ready" = 2 || { echo "expected 2 ready replicas, got $ready"; exit 1; }
helm test pv -n "$NS" --logs

kubectl -n "$NS" port-forward svc/pv-privatevault 8000:8000 >/dev/null &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1 && break; sleep 1; done
python tools/verify_deployment.py --url http://127.0.0.1:8000 \
  --api-key "$PV_OPERATOR_KEY" --agent-id operator
curl -fsS -H "X-API-Key: $PV_OPERATOR_KEY" http://127.0.0.1:8000/v1/runtime \
  | python -c 'import json,sys; d=json.load(sys.stdin); p=d["composition"]["persistence"]["detail"]; print(p); assert "PostgreSQL" in p'
echo "kind install verified"
