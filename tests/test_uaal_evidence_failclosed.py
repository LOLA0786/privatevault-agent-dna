"""L0 evidence handling is three-state, and the mandatory case is
scoped to sensitive capabilities.

Regression: identity_preservation / authority_preservation previously
SKIPPED whenever their evidence was absent, for every action. That is
a fail-open -- an attacker suppressing evidence delivery defeated the
identity check. But making them mandatory for ALL actions breaks
normal operation (every benign call would need planner evidence). The
correct rule blocks on missing identity/authority evidence only when
the action touches a sensitive capability class, where an unstated
intent is itself the anomaly.
"""

from agent_dna.intent_adapter import intent_to_action
from agent_dna.uaal_layer import UAALConstraintChecker


def _act(namespace, verb, obj="x"):
    return intent_to_action(
        actor_id="agent", verb=verb,
        target={"type": namespace, "id": obj}, timestamp=1.0)


C = UAALConstraintChecker()


def test_sensitive_action_missing_identity_evidence_blocks():
    for ns, verb in (("secrets", "read"),
                     ("infra", "exec_remote"),
                     ("network", "egress_external"),
                     ("cloud", "assume_role")):
        r = C.check(_act(ns, verb), evidence={})
        assert r.violated, f"{ns}.{verb} with no evidence must fail closed"
        assert "missing_required_evidence" in r.message


def test_sensitive_action_with_honest_evidence_still_evaluated():
    a = _act("secrets", "read", "cluster-token")
    r = C.check(a, evidence={
        "user_request": {"canonical_target": "cluster-token"},
        "planner": {"canonical_target": "cluster-token"},
        "approvals": {"required": False},
    })
    assert "missing_required_evidence" not in r.message


def test_benign_action_missing_evidence_skips_not_blocks():
    for ns, verb in (("crm", "read_contact"),
                     ("payment", "pay_invoice"),
                     ("storage", "list")):
        r = C.check(_act(ns, verb), evidence={})
        assert not r.violated, (
            f"{ns}.{verb} with no evidence must NOT block -- a missing "
            "identity claim on a benign action is not an anomaly")
        assert "identity_preservation" in r.checks_skipped


def test_the_eval_escape_no_evidence_variant_is_caught():
    """The concrete attack: an agent reaches for a cluster credential
    and supplies no evidence at all, hoping the identity check skips."""
    a = _act("secrets", "read", "cluster-service-token")
    assert C.check(a, evidence={}).violated
