"""Deterministic authority graph, adapter, simulation, and report tests."""

from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from nacl.signing import SigningKey

from experimental.authority_reachability_v01 import (
    EvidenceClass,
    GenericJSONGraphAdapter,
    GraphFormatError,
    MappedCompanyGraphAdapter,
    ProtectedSink,
    ReachabilityState,
    analyze_change,
    analyze_reachability,
    merge_graphs,
    sign_analysis_report,
    verify_signed_analysis_report,
)

VECTORS = Path("spec/authority-reachability-v01/vectors")


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _adapter(source: dict[str, Any]) -> MappedCompanyGraphAdapter:
    mapping = _load("adapter-mapping.json")
    adapter = mapping["adapter"]
    sinks = tuple(
        ProtectedSink.from_dict(item, f"protected_sinks[{index}]")
        for index, item in enumerate(mapping["protected_sinks"])
    )
    return MappedCompanyGraphAdapter(
        source,
        source_system=adapter["source_system"],
        adapter_version=adapter["adapter_version"],
        node_mapping=mapping["node_mapping"],
        edge_mapping=mapping["edge_mapping"],
        protected_sinks=sinks,
    )


def _finding(report, sink: str = "sink:payment-execute"):
    return next(item for item in report.findings if item.sink_node_id == sink)


def test_company_graph_adapter_preserves_source_provenance() -> None:
    source = _load("company-graph-after.json")
    graph = _adapter(source).load()

    assumed = next(
        edge
        for edge in graph.edges
        if edge.edge_id == "edge:agent-assumes-refund-automation"
    )

    assert assumed.evidence_state is EvidenceClass.DISCOVERED
    assert assumed.provenance.source_system == "salesforce-agentforce-synthetic"
    assert assumed.provenance.source_snapshot == source["snapshot_hash"]


def test_company_adapter_cannot_assert_verified_evidence() -> None:
    source = _load("company-graph-after.json")
    mapping = _load("adapter-mapping.json")
    mapping["edge_mapping"]["canAssumeIdentity"]["evidence_state"] = "VERIFIED"

    adapter_config = mapping["adapter"]
    sinks = tuple(
        ProtectedSink.from_dict(item, f"protected_sinks[{index}]")
        for index, item in enumerate(mapping["protected_sinks"])
    )

    adapter = MappedCompanyGraphAdapter(
        source,
        source_system=adapter_config["source_system"],
        adapter_version=adapter_config["adapter_version"],
        node_mapping=mapping["node_mapping"],
        edge_mapping=mapping["edge_mapping"],
        protected_sinks=sinks,
    )

    with pytest.raises(GraphFormatError, match="VERIFIED"):
        adapter.load()


def test_generic_json_adapter_cannot_inflate_verified_evidence() -> None:
    canonical = _adapter(_load("company-graph-after.json")).load().to_dict()
    canonical["edges"][0]["evidence_state"] = "VERIFIED"

    with pytest.raises(GraphFormatError, match="VERIFIED"):
        GenericJSONGraphAdapter(canonical).load()


def test_before_change_irreversible_actions_are_unreachable() -> None:
    graph = _adapter(_load("company-graph-before.json")).load()
    report = analyze_reachability(
        graph,
        source_node_id="agent:refund",
        context={"environment": "production"},
    )

    assert _finding(report).state is ReachabilityState.UNREACHABLE
    assert (
        _finding(report, "sink:customer-bulk-export").state
        is ReachabilityState.UNREACHABLE
    )


def test_proposed_identity_binding_exposes_prohibited_payment_path() -> None:
    graph = _adapter(_load("company-graph-after.json")).load()
    finding = _finding(
        analyze_reachability(
            graph,
            source_node_id="agent:refund",
            context={"environment": "production"},
        )
    )

    assert finding.state is ReachabilityState.PROHIBITED_REACHABLE
    assert finding.reason_codes == (
        "DIRECT_GRANT_REQUIRED",
        "MAXIMUM_DELEGATION_DEPTH_EXCEEDED",
        "ISSUER_NOT_ALLOWED",
    )

    assert finding.witness is not None
    assert finding.witness.node_ids == (
        "agent:refund",
        "identity:refund-automation",
        "grant:payment-execute",
        "capability:payment-execute",
        "sink:payment-execute",
    )
    assert finding.witness.hop_count == 4
    assert finding.witness.evidence == {
        "DECLARED": 3,
        "DISCOVERED": 1,
    }
    assert finding.witness.grant_issuers == ("payments-platform@example.com",)


def test_missing_condition_fact_is_conditional_not_unreachable() -> None:
    graph = _adapter(_load("company-graph-after.json")).load()
    finding = _finding(
        analyze_reachability(
            graph,
            source_node_id="agent:refund",
        )
    )

    assert finding.state is ReachabilityState.CONDITIONAL
    assert finding.reason_codes[0] == "UNRESOLVED_PATH_CONDITIONS"
    assert finding.witness is not None
    assert finding.witness.conditional_fields == ("environment",)


def test_false_condition_removes_path() -> None:
    graph = _adapter(_load("company-graph-after.json")).load()
    finding = _finding(
        analyze_reachability(
            graph,
            source_node_id="agent:refund",
            context={"environment": "sandbox"},
        )
    )

    assert finding.state is ReachabilityState.UNREACHABLE


def test_invalid_edge_is_never_traversed() -> None:
    source = _load("company-graph-after.json")
    mapping = _load("adapter-mapping.json")
    mapping["edge_mapping"]["canAssumeIdentity"]["evidence_state"] = "INVALID"

    adapter_config = mapping["adapter"]
    sinks = tuple(
        ProtectedSink.from_dict(item, f"protected_sinks[{index}]")
        for index, item in enumerate(mapping["protected_sinks"])
    )

    graph = MappedCompanyGraphAdapter(
        source,
        source_system=adapter_config["source_system"],
        adapter_version=adapter_config["adapter_version"],
        node_mapping=mapping["node_mapping"],
        edge_mapping=mapping["edge_mapping"],
        protected_sinks=sinks,
    ).load()

    finding = _finding(
        analyze_reachability(
            graph,
            source_node_id="agent:refund",
            context={"environment": "production"},
        )
    )

    assert finding.state is ReachabilityState.UNREACHABLE


def test_direct_allowed_grant_is_reachable() -> None:
    source = _load("company-graph-before.json")

    payment_grant = next(
        node for node in source["nodes"] if node["id"] == "grant:payment-execute"
    )
    payment_grant["attributes"]["delegation_depth"] = 0
    payment_grant["attributes"]["issuer_principal"] = "treasury-owner@example.com"

    source["edges"].append(
        {
            "id": "edge:agent-direct-payment-grant",
            "source": "agent:refund",
            "target": "grant:payment-execute",
            "type": "holdsSignedGrant",
            "conditions": [],
        }
    )

    graph = _adapter(source).load()
    finding = _finding(
        analyze_reachability(
            graph,
            source_node_id="agent:refund",
            context={"environment": "production"},
        )
    )

    assert finding.state is ReachabilityState.REACHABLE
    assert finding.reason_codes == ("VALID_PATH",)


def test_change_analysis_blocks_new_prohibited_reachability() -> None:
    before = _adapter(_load("company-graph-before.json")).load()
    after = _adapter(_load("company-graph-after.json")).load()

    result = analyze_change(
        before,
        after,
        source_node_id="agent:refund",
        context={"environment": "production"},
    )

    assert result.newly_reachable_sinks == ("sink:payment-execute",)
    assert result.newly_prohibited_sinks == ("sink:payment-execute",)
    assert result.should_block
    assert result.to_dict()["decision"] == "BLOCK_PROPOSED_CHANGE"


def test_report_is_deterministic() -> None:
    graph = _adapter(_load("company-graph-after.json")).load()
    arguments = {
        "source_node_id": "agent:refund",
        "context": {"environment": "production"},
    }

    first = analyze_reachability(graph, **arguments).to_dict()
    second = analyze_reachability(graph, **arguments).to_dict()

    assert first == second
    assert first["analysis_id"] == second["analysis_id"]
    assert first["graph_hash"] == second["graph_hash"]


def test_signed_report_detects_content_tampering() -> None:
    graph = _adapter(_load("company-graph-after.json")).load()
    report = analyze_reachability(
        graph,
        source_node_id="agent:refund",
        context={"environment": "production"},
    ).to_dict()

    key = SigningKey(bytes(range(32)))
    envelope = sign_analysis_report(
        report,
        key,
        signer_key_id="pv-analysis-01",
    )
    trusted = {"pv-analysis-01": base64.b64encode(bytes(key.verify_key)).decode()}

    assert verify_signed_analysis_report(
        envelope,
        trusted_keys=trusted,
    )

    tampered = copy.deepcopy(envelope)
    tampered["report"]["findings"][1]["state"] = "REACHABLE"

    assert not verify_signed_analysis_report(
        tampered,
        trusted_keys=trusted,
    )


def test_signed_report_rejects_malformed_signature_fail_closed() -> None:
    graph = _adapter(_load("company-graph-after.json")).load()
    report = analyze_reachability(
        graph,
        source_node_id="agent:refund",
        context={"environment": "production"},
    ).to_dict()

    key = SigningKey(bytes(range(32)))
    envelope = sign_analysis_report(
        report,
        key,
        signer_key_id="pv-analysis-01",
    )
    trusted = {"pv-analysis-01": base64.b64encode(bytes(key.verify_key)).decode()}

    malformed = copy.deepcopy(envelope)
    malformed["signature"] = "ed25519:AA=="

    assert not verify_signed_analysis_report(
        malformed,
        trusted_keys=trusted,
    )


def test_signed_report_rejects_cryptographic_signature_tampering() -> None:
    graph = _adapter(_load("company-graph-after.json")).load()
    report = analyze_reachability(
        graph,
        source_node_id="agent:refund",
        context={"environment": "production"},
    ).to_dict()

    key = SigningKey(bytes(range(32)))
    envelope = sign_analysis_report(
        report,
        key,
        signer_key_id="pv-analysis-01",
    )
    trusted = {"pv-analysis-01": base64.b64encode(bytes(key.verify_key)).decode()}

    signature = bytearray(
        base64.b64decode(
            envelope["signature"].removeprefix("ed25519:"),
            validate=True,
        )
    )
    signature[0] ^= 1

    tampered = copy.deepcopy(envelope)
    tampered["signature"] = "ed25519:" + base64.b64encode(signature).decode()

    assert not verify_signed_analysis_report(
        tampered,
        trusted_keys=trusted,
    )


def test_canonical_graph_and_report_match_published_schemas() -> None:
    specification = Path("spec/authority-reachability-v01")
    graph_schema = json.loads(
        (specification / "authority-graph.schema.json").read_text(encoding="utf-8")
    )
    report_schema = json.loads(
        (specification / "reachability-report.schema.json").read_text(encoding="utf-8")
    )

    graph = _adapter(_load("company-graph-after.json")).load()
    report = analyze_reachability(
        graph,
        source_node_id="agent:refund",
        context={"environment": "production"},
    )

    Draft202012Validator.check_schema(graph_schema)
    Draft202012Validator.check_schema(report_schema)
    Draft202012Validator(graph_schema).validate(graph.to_dict())
    Draft202012Validator(report_schema).validate(report.to_dict())


def test_unmapped_company_type_fails_closed() -> None:
    source = _load("company-graph-before.json")
    source["nodes"][0]["type"] = "UnknownAgentType"

    with pytest.raises(GraphFormatError, match="no mapping"):
        _adapter(source).load()


def test_merge_rejects_conflicting_node_definitions() -> None:
    first = _adapter(_load("company-graph-before.json")).load()

    modified = _load("company-graph-before.json")
    modified["nodes"][0]["label"] = "Conflicting agent label"
    second = _adapter(modified).load()

    with pytest.raises(GraphFormatError, match="conflicting node"):
        merge_graphs(
            [first, second],
            graph_id="merged",
            snapshot_time="2026-07-28T12:30:00Z",
        )


def test_vector_generator_and_cli_are_deterministic() -> None:
    before = {path.name: path.read_bytes() for path in sorted(VECTORS.glob("*.json"))}

    generated = subprocess.run(
        [sys.executable, "tools/generate_authority_reachability_vectors.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert generated.returncode == 0, generated.stdout + generated.stderr

    after = {path.name: path.read_bytes() for path in sorted(VECTORS.glob("*.json"))}
    assert after == before

    cli = subprocess.run(
        [
            sys.executable,
            "tools/pv_authority_reachability.py",
            "simulate",
            str(VECTORS / "company-graph-before.json"),
            str(VECTORS / "company-graph-after.json"),
            str(VECTORS / "adapter-mapping.json"),
            "--source",
            "agent:refund",
            "--context",
            str(VECTORS / "analysis-context.json"),
            "--json",
            "-",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert cli.returncode == 1
    output = json.loads(cli.stdout)
    assert output["decision"] == "BLOCK_PROPOSED_CHANGE"
