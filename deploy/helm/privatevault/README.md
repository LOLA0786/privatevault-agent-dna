# PrivateVault Helm chart

Runs the PrivateVault API (decide, authorize, audit) on Kubernetes: by default
two replicas on PostgreSQL with the secure profile, non-root, read-only root
filesystem, no capabilities, spread across nodes and zones, a disruption
budget and a NetworkPolicy.

The chart creates no secrets and generates no keys. You create them, once,
and the chart references them.

## 1. Material

```sh
python tools/init_secure_profile.py --out ./pv-material --org acme.example \
    --grant treasury-agent=payments.pay_invoice
set -a; . ./pv-material/secure.env; set +a     # for the values printed below

kubectl create namespace privatevault
kubectl -n privatevault create secret generic pv-secrets \
  --from-file=keys.json=pv-material/keys.json \
  --from-file=execution-signer.key=pv-material/execution-signer.key \
  --from-file=dispatch-witness.key=pv-material/dispatch-witness.key \
  --from-literal=receipt-signing-key="$PV_RECEIPT_SIGNING_KEY" \
  --from-literal=database-url='postgresql://USER:PASSWORD@HOST:5432/privatevault'
kubectl -n privatevault create configmap pv-config \
  --from-file=grants.json=pv-material/grants.json \
  --from-file=trust-bundle.json=pv-material/trust-bundle.json \
  --from-file=operations.json=pv-material/operations.json \
  --from-file=presenter-bundle.json=pv-material/presenter-bundle.json
```

Declare in `operations.json` the exact method, destination and route each
capability may use (ADR 0025), then install with
`--set config.operationsKey=operations.json --set config.presenterBundleKey=presenter-bundle.json`.
The operations file starts empty: until it declares an operation, the API
refuses every mint. The presenter bundle is required with the secure profile
(ADR 0028): it pins each agent's TLS client key, so every permit can only be
presented by that agent. The agents' certificates and keys are in
`pv-material/presenters/`; give each agent's sidecar its own pair, and give
receivers `presenters/client-ca.pem` as `PV_RECEIVER_CLIENT_CA`. Store
`presenters/client-ca.key` offline after issuing.

In production put the signing keys in a KMS instead of the Secret
(`signing.*KmsRef`, ADR 0023) and give the ServiceAccount permission to sign
(`serviceAccount.annotations`: IRSA or Workload Identity). Check a KMS key
first with `python tools/kms_smoke.py`.

## 2. Install

```sh
helm install pv deploy/helm/privatevault -n privatevault \
  --set secrets.name=pv-secrets --set config.name=pv-config \
  --set signing.trustedPublicKeys="$PV_TRUSTED_PUBLIC_KEYS" \
  --set image.digest=sha256:...        # pin the exact image you verified
helm test pv -n privatevault
```

## 3. Verify what it enforces

```sh
kubectl -n privatevault port-forward svc/pv-privatevault 8000:8000 &
python tools/verify_deployment.py --url http://127.0.0.1:8000 \
  --api-key "$PV_OPERATOR_KEY" --agent-id operator
```

## Refused at render time

The chart will not render a configuration that would start but not be safe:
more than one replica (or autoscaling) without PostgreSQL; SQLite without a
persistent volume; a missing Secret or ConfigMap; the secure profile without
trusted receipt keys or without enforced lineage; an image digest that is not
`sha256:`. `ci/check-refusals.sh` checks each one in CI.

## Values

| Value | Default | Meaning |
|---|---|---|
| `replicaCount` | `2` | API pods; above 1 needs `postgres.enabled` |
| `image.repository` / `tag` / `digest` | GHCR / appVersion / empty | `digest` wins over `tag` |
| `secureProfile` | `true` | `PV_SECURE_PROFILE=1` |
| `lineage` / `ungrantedDecision` | `enforce` / `block` | |
| `postgres.enabled` | `true` | `PV_DATABASE_URL` from the Secret key `secrets.databaseUrlKey` |
| `postgres.poolSize` / `timeoutSeconds` | `10` / `5` | per pod |
| `persistence.*` | off | SQLite volume, single replica only |
| `secrets.name` + `*Key` | required | API keys, seeds, database URL |
| `config.name` + `*Key` | required | grants, trust bundle, presenter bundle (`presenterBundleKey`, required with the secure profile), policy and operations (`operationsKey`; without it the secure profile refuses every mint) |
| `signing.*KmsRef` | empty | `awskms:` / `gcpkms:` references replacing the seeds |
| `signing.trustedPublicKeys` | required with the secure profile | hex receipt public keys |
| `serviceAccount.annotations` | `{}` | IRSA / Workload Identity for KMS |
| `podDisruptionBudget`, `autoscaling`, `networkPolicy`, `topologySpread` | on, off, on, on | |

The image includes the PostgreSQL driver and the AWS KMS client; build with
`--build-arg PV_KMS_PACKAGES="boto3>=1.40 google-cloud-kms>=3"` for Cloud KMS.

## Tested

CI lints and renders every `ci/*-values.yaml` with Helm, validates the output
against the Kubernetes 1.31 schemas (kubeconform, strict), checks the
refusals, then installs the chart on a kind cluster with PostgreSQL and runs
`helm test` and `tools/verify_deployment.py` (`ci/kind-e2e.sh`). Not tested:
a managed Kubernetes service, ingress/TLS termination (deployment-specific),
and KMS from inside a cluster.
