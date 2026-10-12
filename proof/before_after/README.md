# P2: before and after

```sh
uv run python -m proof.before_after.run
```

The finance-ops attack twice. The CFO approves 18,000 INR to V-100; the
agent's process then sends 48,000.

**Before (PrivateVault off).** The same agent code path minus the gate: the
agent holds valid credentials and posts its bytes to the payments upstream
directly. The upstream receives 48,000. No decision record exists anywhere,
because nothing decided. Money moved.

**After (PrivateVault on).** Decide, CFO approval (signed, single-use),
permit, sidecar, receiver gate. The same alteration is refused by the
sidecar before any byte (`EXECUTION_AUTHORIZATION_NON_CONFORMANT`), and by
the receiver gate when the sidecar is bypassed (`RECEIVER_WIRE_MISMATCH`).
The upstream receives only the approved 18,000.

## What is and is not modelled

The "before" is not a straw man: it is what an agent with API credentials
and no binding control does, which is most agents today. The upstream is
the receiver kit's stub; it records what it would have acted on. The
"after" is the agents harness in process (scripted model, demo transport,
per-run keys), exactly as in `agents/personas/finance_ops`.
