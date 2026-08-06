"""Shadow policy mode: observe candidate policies against live traffic,
enforce nothing, report divergence, stay tamper-evident."""

from agent_dna.apikeys import generate_key
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.connector import ToolCallRequest
from agent_dna.policy.checker import PolicyChecker
from agent_dna.policy.schema import parse_policy_dict
from agent_dna.shadow import ShadowPolicySet


def _runtime(tmp_path):
    key = generate_key("shadow-agent", scope="full")
    import json

    (tmp_path / "keys.json").write_text(
        json.dumps({key["hash"]: {"name": "shadow-agent", "scope": "full"}})
    )
    rt = build_production_runtime(
        RuntimeConfig(
            db_path=str(tmp_path / "pv.db"),
            keys_file=str(tmp_path / "keys.json"),
        )
    )
    return rt, key["key"]


def _candidate(rule_id, capability, outcome="block"):
    return PolicyChecker(
        parse_policy_dict(
            {
                "policies": [
                    {
                        "id": rule_id,
                        "capability": capability,
                        "outcome": outcome,
                        "reason": f"{rule_id} fired",
                    }
                ]
            }
        )
    )


def test_shadow_records_divergence_without_enforcing(tmp_path):
    rt, key = _runtime(tmp_path)
    shadow = ShadowPolicySet().add(
        "proposed-DLP", _candidate("PROP-1", "crm.read_contact")
    )
    mw = rt.middleware(shadow=shadow)

    # crm.read_contact is allowed live; the candidate would block it
    verdict = mw.handle(
        ToolCallRequest(adapter="test", tool="crm.read_contact", api_key=key)
    )
    assert verdict.decision == "allow", "enforcement must be unchanged"

    rep = shadow.report()["shadow_report"]["proposed-DLP"]
    assert rep["observed"] == 1
    assert rep["would_newly_block"] == 1
    assert rep["newly_blocked_by_capability"] == {"crm.read_contact": 1}
    assert rep["sample_newly_blocked"][0]["rule"] == "PROP-1"


def test_shadow_never_touches_enforcement_even_if_candidate_crashes(tmp_path):
    rt, key = _runtime(tmp_path)

    class Exploding:
        def check(self, **kw):
            raise RuntimeError("candidate policy is broken")

    shadow = ShadowPolicySet().add("broken", Exploding())
    mw = rt.middleware(shadow=shadow)

    verdict = mw.handle(
        ToolCallRequest(adapter="test", tool="crm.read_contact", api_key=key)
    )
    assert verdict.decision == "allow"  # enforcement fine
    rep = shadow.report()["shadow_report"]["broken"]
    assert rep["candidate_errors"] == 1


def test_shadow_agreement_is_not_divergence(tmp_path):
    rt, key = _runtime(tmp_path)
    # candidate blocks bulk_export; live policy is absent so live=allow
    # -> that IS divergence. Use a capability both allow to show agreement.
    shadow = ShadowPolicySet().add("agrees", _candidate("A-1", "storage.bulk_export"))
    mw = rt.middleware(shadow=shadow)
    mw.handle(ToolCallRequest(adapter="test", tool="crm.read_contact", api_key=key))
    rep = shadow.report()["shadow_report"]["agrees"]
    # the candidate only fires on bulk_export; a crm.read is 'allow'
    # shadow vs 'allow' live -> unchanged
    assert rep["would_newly_block"] == 0
    assert rep["unchanged"] == 1


def test_shadow_log_is_hash_chained_and_tamper_evident(tmp_path):
    rt, key = _runtime(tmp_path)
    shadow = ShadowPolicySet().add("c", _candidate("R", "crm.read_contact"))
    mw = rt.middleware(shadow=shadow)
    for _ in range(5):
        mw.handle(ToolCallRequest(adapter="test", tool="crm.read_contact", api_key=key))
    assert shadow.verify_chain()
    # tamper: flip one observation's outcome
    shadow._log[2].shadow_outcome = "allow"
    assert not shadow.verify_chain()


def test_multiple_candidates_reported_independently(tmp_path):
    rt, key = _runtime(tmp_path)
    shadow = (
        ShadowPolicySet()
        .add("strict", _candidate("S", "crm.read_contact"))
        .add("lenient", _candidate("L", "storage.bulk_export"))
    )
    mw = rt.middleware(shadow=shadow)
    mw.handle(ToolCallRequest(adapter="test", tool="crm.read_contact", api_key=key))
    report = shadow.report()["shadow_report"]
    assert report["strict"]["would_newly_block"] == 1
    assert report["lenient"]["would_newly_block"] == 0
