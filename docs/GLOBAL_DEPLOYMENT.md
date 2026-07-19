> **STATUS: EXPERIMENTAL / NOT SHIPPED.** The functionality described below is roadmap. Its code lives in `experimental/` and is excluded from the installable package and from every compliance claim. See `experimental/README.md`.

# Global Deployment — Multi-Region & Data Residency

## Deployment Model
PrivateVault runtime runs as a container (Docker/K8s) inside
customer VPC in each jurisdiction. No central cloud service.

## Multi-Region PostgreSQL
- Primary per region (`postgres_cluster.py`)
- Cross-region replication: async, encrypted
- Data residency enforced: `enforce_residency()` rejects
  writes outside jurisdiction

## Kubernetes Spec (Planned)
`helm/privatevault/` — Helm chart with:
- `Deployment` (PrivateVault runtime)
- `Service` (local metrics endpoint)
- `ConfigMap` (local policy adapter config)
- `Secret` (Ed25519 signing keys, rotated via `rotate_key()`)

## Data Residency
Per jurisdiction flags: EU (GDPR), US (FedRAMP),
APAC (DPDP). Adapter layer (`adapters_policy/`) ensures
policies comply with local regulations without central rewrite.

## Certification Alignment
- SOC 2 (docs/compliance/soc2/)
- FedRAMP High (planned)
- ISO 27001 (docs/SECURITY.md)
