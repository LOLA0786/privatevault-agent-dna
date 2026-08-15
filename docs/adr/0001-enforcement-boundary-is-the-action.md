# 0001 — The enforcement boundary is the action, not the model

Status:     accepted
Date:       2026-07-08
Commit:     3ab1cbd69dd050fc220af15ad8d3838b256850a2
Pinned by:  tests/test_precedence_contract.py::test_drift_can_never_block

## What forced the decision
Every agent-security product we looked at wanted the model in the
loop: score the prompt, classify intent, let a second model approve
the first. That is tempting because it looks like intelligence, it
demoes well, and it appears to cover cases no rule author thought of.
It also lets the component that proposed the action influence whether
the action runs, and it makes the verdict unreproducible: the same
bytes, a different sample, a different vendor, a different day.

The Hugging Face 2026-07 sandbox escape was not a prompt-classification
miss. It was an action that never entered a reference monitor. Putting
a model on the enforcement path would not have closed that, and it
would have given us a story we could not replay for an auditor.

## The decision
The runtime evaluates the action that was submitted — capability,
arguments, identity, evidence — against deterministic precedence.
Models propose, score, and advise. They never receive credentials,
never mint a permit, never convert a BLOCK into an ALLOW, and never
auto-apply a discovered policy. Drift may escalate to review; it
cannot block and it cannot approve.

## What this costs us
Novel abuse that does not match a written rule, grant, or invariant
is not stopped by "the model would have noticed." Completeness
(every real effect is submitted) is an infrastructure property this
library cannot prove. Operators who wanted an LLM firewall have to
be told they bought a reference monitor for submitted actions.

## What would make us revisit
A learned layer with independently labelled production outcomes,
a published false-positive budget, and a pin that it can only
tighten a named deterministic level — never relax one — and even
then only after `docs/WHAT-WE-DO-NOT-CLAIM.md` is updated in the
same commit. Auto-merge of discovery proposals is not a trigger;
it is a reversal of AGENTS.md.
