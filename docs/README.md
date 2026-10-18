# Documentation

Start with the [architecture overview](architecture/README.md). Every
document in `docs/` is listed below with its status;
`test_every_doc_is_indexed` fails if one is added without a row here.

**Status** means:

- **current**: describes the code as it is; code references are checked by
  tests where marked "checked";
- **reference**: stable background, mapping or method; read with the
  current pages;
- **historical**: a point-in-time record (a brief, a pre-change map, a
  proposal); kept for the reasoning, not as a description of today;
- **experimental**: describes code in `experimental/`, which does not ship.

Separation holds only for covered flows where enforcement is enabled and
verified.

## Start here, by role

| You are | Read, in order |
|---|---|
| New engineer | [architecture/README.md](architecture/README.md), [../ARCHITECTURE.md](../ARCHITECTURE.md), [architecture/REPO-MAP.md](architecture/REPO-MAP.md), [architecture/DEPENDENCIES.md](architecture/DEPENDENCIES.md), [adr/README.md](adr/README.md) |
| Integrating an agent | [architecture/FLOWS.md](architecture/FLOWS.md), [HARNESS_INTEGRATION.md](HARNESS_INTEGRATION.md), [integration-patterns/enforcement-middleware.md](integration-patterns/enforcement-middleware.md), [API-SURFACE.md](API-SURFACE.md) |
| Operating a deployment | [architecture/DEPLOYMENT.md](architecture/DEPLOYMENT.md), [architecture/DATA.md](architecture/DATA.md), [operations/BACKUP.md](operations/BACKUP.md), [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) |
| Security reviewer | [architecture/TRUST-AND-KEYS.md](architecture/TRUST-AND-KEYS.md), [SECURITY.md](SECURITY.md), [THREAT-MODEL.md](THREAT-MODEL.md), [WHAT-WE-DO-NOT-CLAIM.md](WHAT-WE-DO-NOT-CLAIM.md), [PRODUCTION-HARDENING.md](PRODUCTION-HARDENING.md) |
| Auditor or risk team | [WHAT-WE-DO-NOT-CLAIM.md](WHAT-WE-DO-NOT-CLAIM.md), [compliance/soc2/control_mapping.md](compliance/soc2/control_mapping.md), [AGENTIC-TRUST-CONTROLS-MAPPING.md](AGENTIC-TRUST-CONTROLS-MAPPING.md), [owasp-llm-2026-coverage.md](owasp-llm-2026-coverage.md) |
| Evaluating or piloting | [EVALUATE.md](EVALUATE.md), [PILOT-SCOPE.md](PILOT-SCOPE.md), [pilot/CAMPFIRE-BLACKBOX.md](pilot/CAMPFIRE-BLACKBOX.md) |

## Architecture

| Document | Status | What it covers |
|---|---|---|
| [architecture/README.md](architecture/README.md) | current, checked | Overview: system context, the parts that run, layers |
| [architecture/REPO-MAP.md](architecture/REPO-MAP.md) | current, checked | Every top-level directory and whether it ships |
| [architecture/FLOWS.md](architecture/FLOWS.md) | current, checked | Sequence diagrams for every flow, and every HTTP route |
| [architecture/DATA.md](architecture/DATA.md) | current, checked | Every ledger table, its writers and readers |
| [architecture/TRUST-AND-KEYS.md](architecture/TRUST-AND-KEYS.md) | current, checked | Every key, what it signs, who verifies it |
| [architecture/DEPLOYMENT.md](architecture/DEPLOYMENT.md) | current, checked | Deployment shapes, Kubernetes, multi-instance, receiver side |
| [architecture/DEPENDENCIES.md](architecture/DEPENDENCIES.md) | current, generated | Who depends on whom, module by module, in layers |
| [architecture/MAP.md](architecture/MAP.md) | current, generated | Directory-level import graph |
| [../ARCHITECTURE.md](../ARCHITECTURE.md) | current, checked | One decision end to end, precedence ladder, trust boundaries |
| [adr/README.md](adr/README.md) | current | Architecture decision records 0001 to 0023 |

## Security and claims

| Document | Status | What it covers |
|---|---|---|
| [WHAT-WE-DO-NOT-CLAIM.md](WHAT-WE-DO-NOT-CLAIM.md) | current | The limits of every claim |
| [SECURITY.md](SECURITY.md) | current | Security model |
| [THREAT-MODEL.md](THREAT-MODEL.md) | reference | Threats indexed by attack, with the test for each |
| [SECURITY-MIGRATION-v0.5.md](SECURITY-MIGRATION-v0.5.md) | reference | Migration notes for DRP 0.2 mintable decisions |
| [PRODUCTION-HARDENING.md](PRODUCTION-HARDENING.md) | reference | Hardening capabilities, each marked shipped, scoped or not started |
| [owasp-llm-2026-coverage.md](owasp-llm-2026-coverage.md) | reference | OWASP LLM Top 10 (2026) coverage |
| [owasp-llm-top10-2025-coverage.md](owasp-llm-top10-2025-coverage.md) | reference | OWASP LLM Top 10 (2025) coverage table |
| [AGENTIC-TRUST-CONTROLS-MAPPING.md](AGENTIC-TRUST-CONTROLS-MAPPING.md) | reference | Agentic trust controls mapped to the code |
| [compliance/soc2/control_mapping.md](compliance/soc2/control_mapping.md) | reference | SOC 2 control mapping |
| [findings/PHASE1-FOLLOW-UPS.md](findings/PHASE1-FOLLOW-UPS.md) | current | Open follow-ups from Phase 1 |

## Integrating and operating

| Document | Status | What it covers |
|---|---|---|
| [API-SURFACE.md](API-SURFACE.md) | reference, incomplete | HTTP API detail; predates `/v1/authorize`, `/v1/revocations` and `/v1/flows`. The complete route list is in [architecture/FLOWS.md](architecture/FLOWS.md) |
| [HARNESS_INTEGRATION.md](HARNESS_INTEGRATION.md) | reference | Wiring an agent harness to PrivateVault |
| [integration-patterns/enforcement-middleware.md](integration-patterns/enforcement-middleware.md) | reference | The enforcement middleware pattern |
| [ENGINEERING-STANDARD.md](ENGINEERING-STANDARD.md) | reference | Standard every connector must meet |
| [POLICY-GATE.md](POLICY-GATE.md) | reference | Putting a control change through code review |
| [DISCOVERY-LOOP.md](DISCOVERY-LOOP.md) | reference | Discovery loop |
| [LOOP-DISCOVERY.md](LOOP-DISCOVERY.md) | reference | Agent security loop discovery at the authority boundary |
| [VALIDATION-MATH.md](VALIDATION-MATH.md) | reference | pv-validation/1 mathematics |
| [operations/BACKUP.md](operations/BACKUP.md) | current | Backup, verify and restore runbook |
| [benchmarks/MULTI-INSTANCE.md](benchmarks/MULTI-INSTANCE.md) | current | Several instances on one PostgreSQL: what holds, measured |
| [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) | reference | Release steps |

## Evaluation and pilots

| Document | Status | What it covers |
|---|---|---|
| [EVALUATE.md](EVALUATE.md) | reference | Evaluating PrivateVault in one day |
| [PILOT-SCOPE.md](PILOT-SCOPE.md) | reference | Pilot scope |
| [pilot/CAMPFIRE-BLACKBOX.md](pilot/CAMPFIRE-BLACKBOX.md) | reference | Black-box partner sandbox |
| [ROADMAP.md](ROADMAP.md) | current | Roadmap and known limitations |

## Historical

| Document | Status | What it covers |
|---|---|---|
| [CURSOR-BRIEF-architecture.md](CURSOR-BRIEF-architecture.md) | historical | The brief that led to the generated map and the ADRs |
| [PHASE1-PRECHANGE-MAP.md](PHASE1-PRECHANGE-MAP.md) | historical | The code as it was before Phase 1 |
| [PROPOSED-CLAIMS-CORRECTION-PV001.md](PROPOSED-CLAIMS-CORRECTION-PV001.md) | historical | A proposed claims correction |
| [TECHNICAL-OVERVIEW-GERARD.md](TECHNICAL-OVERVIEW-GERARD.md) | historical | A technical overview written for one reader |

## Experimental

| Document | Status | What it covers |
|---|---|---|
| [GLOBAL_DEPLOYMENT.md](GLOBAL_DEPLOYMENT.md) | experimental | Roadmap; code in `experimental/` |
| [NETWORK_EFFECTS.md](NETWORK_EFFECTS.md) | experimental | Roadmap; code in `experimental/` |

## Keeping the docs true

- Code references in the checked pages must resolve
  (`tests/test_architecture_doc.py`).
- Generated pages are regenerated, never edited:
  `python tools/archmap.py && python tools/depmap.py`; CI fails if they are
  stale.
- A new document gets a row here, in the right section, with its status.
  The one exception is the deletable lab experiment under `pilot/`, which
  the product must not reference (`tests/test_pilot_isolation.py`).
