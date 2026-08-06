# Agent Security Loop Discovery

## Security objective

PrivateVault loop discovery prevents an agent swarm from manufacturing or
reusing authority through composition. It runs before consequential dispatch
and treats inference as proposal generation only.

The control targets attacks that per-agent policy checks cannot see:

- A delegates to B, B obtains approval from C, and C's authority resolves back
  to A.
- Agents repeatedly invoke the same canonical action through different
  framework callbacks.
- One signed authorization is consumed by several events.
- A malicious trace supplies circular or cross-trace parent evidence.
- An execution creates an unbounded causal chain without repeating one obvious
  tool call.

## Decision boundary

| Finding | Decision | Rationale |
| --- | --- | --- |
| Circular delegation or approval | BLOCK | Authority relations must be acyclic. |
| Authorization reuse | BLOCK | Execution authorization is atomic and single-use. |
| Causal parent cycle or cross-trace parent | BLOCK | Provenance is internally contradictory. |
| Excessive causal depth | BLOCK | Bounded execution is a runtime invariant. |
| Third identical action edge in one lineage | BLOCK | Strong recursive-loop evidence. |
| Second identical action edge | REVIEW | May be an operator-authorized retry. |
| Bidirectional invocation graph | REVIEW | Request/response workflows can be legitimate. |
| Unverified invocation | REVIEW | Telemetry may be incomplete; it cannot prove authority. |
| Unverified delegation, approval, or dispatch | BLOCK | Consequential authority fails closed. |

## Operational flow

1. Translate a framework proposal into immutable `ActionIntent` bytes.
2. Verify PrivateVault authority and obtain a single-use authorization.
3. Emit one strict `pv-agent-security-event/1.0` event.
4. Run loop discovery over the complete causal trace window.
5. Dispatch only an `ALLOW` result. Route `REVIEW` to a named approver and
   refuse `BLOCK`.
6. Bind the report digest into the decision receipt and execution closure.

The current module supplies the deterministic analyzer and CLI. Production
integrations must store the input events and report alongside the signed
decision evidence; the analyzer's hash identifiers are not signatures.

## CLI

```bash
pv loop discover --input events.jsonl --json loop-report.json
```

Exit codes follow the repository contract: `0` for `ALLOW`, `1` for `REVIEW`
or `BLOCK`, and `2` for malformed or unsafe input.

## Boundedness and denial-of-service controls

Default analysis is limited to 10,000 unique events, causal depth 64, and 256
reported findings. Strongly connected components are computed iteratively in
linear graph space. Event identifiers are idempotent only when their complete
bodies match; conflicting reuse is rejected.

## Explicit limitations

- A sequential privilege escalation can be dangerous without forming a loop.
  Authority containment and policy evaluation remain separate controls.
- A graph finding does not prove human collusion or intent.
- A digest does not prove bytes were sent. Only the independent dispatcher
  witness can attest to outbound bytes and peer identity.
- `REVIEW` is not permission to dispatch.
