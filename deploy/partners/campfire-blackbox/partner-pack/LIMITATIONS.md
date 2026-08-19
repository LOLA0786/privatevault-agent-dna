# Limits of this evaluation

This pack is a hosted black-box interface. It is not PrivateVault source, a Docker image, or a claim that Campfire's tools are already mediated.

## What a `200` means

The control plane allowed the proposed sandbox write under the evaluation policy and sealed a DRP 0.2 DecisionRecord. It does not mean the file was written. Writing happens only if Campfire's own execution path then proceeds, and only a governed dispatcher can bind that write to the permit.

## What `202` and `403` mean

`202` is REQUIRE_APPROVAL. Do not execute. `403` on `/v1/decide` is a policy verdict, not a transient network failure. Do not retry it.

## Authorize is not dispatch

`POST /v1/authorize` mints a signed, single-use permit bound to the sealed ALLOW, the action, the dispatch context, the wire-byte digest and length, and the peer identity digest. Mutating the action, the destination, the receipt, or the record fails closed. The mint endpoint does not open a socket and does not write the file.

## Exact-byte demo honesty

Replay refusal and byte-mutation refusal are demonstrated by the in-tree reference exact-byte test (`tools/adversarial_egress_demo.py`). That test uses a recording transport. It is not a partner-executable live dispatch test unless Campfire routes its real tool execution through the PrivateVault dispatcher.

The recording transport proves honest bytes accepted, mutated bytes refused, consumed-permit replay refused, and that the witness verifies. It does not prove bytes reached a network peer, and it does not prove Campfire's live tool path is mediated.

## INDETERMINATE

If an execution is `INDETERMINATE`, do not automatically retry. Treat the permit as burned unless independent evidence shows the first attempt did not execute.

## What this service is not

* Not complete mediation of Campfire until the real tool path is structurally routed through the dispatcher.
* Not multi-instance. No load-balancer story. No published latency or throughput figures.
* Not SOC 2 or ISO certified.
* Not a production filesystem, shell, or secret store. The granted capability is one sandbox write.
* Behavioral drift is not used for these three expected verdicts.
