# PrivateVault Operator Console

Read-only operational surface for runtime health, enforcement composition,
blocked actions, execution divergence, and audit-chain state. API keys remain
in component memory and are never written to browser storage.

```bash
npm ci
VITE_PV_API_URL=http://localhost:8000 npm run dev
```

For a same-origin deployment, leave `VITE_PV_API_URL` unset and reverse proxy
`/health` and `/v1/*` to the PrivateVault API. The console does not weaken API
scope rules: runtime data requires a full-scope key and audit verification
accepts audit or full scope according to the API contract.

Release gates:

```bash
npm run lint
npm run build
```
