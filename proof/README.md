# Proof

Three demonstrations that the binding is what stops an agent with valid
credentials from moving money it was not approved to move. Everything runs
in process with scripted models and per-run keys; the only network is a
stub upstream on loopback.

```sh
docker compose -f proof/docker-compose.yml up --build --abort-on-container-exit
```

or, from a checkout with the dev environment:

```sh
uv run python -m proof.run_all
```

| Proof | What it shows | Details |
|---|---|---|
| P1 `compare/` | The same attack against an LLM guardrail stub, an API gateway with an amount cap, strict idempotency keys, and the PrivateVault receiver gate. Three admit it; the gate refuses it. Every control admits the honest request. | `compare/README.md`, `compare/RESULTS.md` |
| P2 `before_after/` | Finance ops with PrivateVault off (the upstream receives 48,000) and on (refused twice; the upstream receives only the approved 18,000). | `before_after/README.md` |
| P3 `injection/` | An invoice note tells the model to pay another account. Without PrivateVault the attacker is paid; with it the payee is blocked at decide, and a payee injected after approval is refused by the sidecar and the receiver. | `injection/README.md` |

The attack-indexed threat model is `docs/THREAT-MODEL.md`; a one-day
evaluation guide is `docs/EVALUATE.md`.
