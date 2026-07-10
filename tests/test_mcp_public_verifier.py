"""Public MCP verifier tool: proves it catches tampering using the
real, unmodified verifier script as a subprocess -- not a
reimplementation that could drift from it."""

from pathlib import Path

from agent_dna.mcp_public_verifier import pv_verify_records

VECTORS = Path(__file__).resolve().parent.parent / "spec" / "test-vectors"


def test_clean_vector_passes():
    content = (VECTORS / "clean.jsonl").read_text()
    result = pv_verify_records(content)
    assert result["passed"] is True
    assert result["exit_code"] == 0
    assert "VERDICT: PASS" in result["output"]


def test_tampered_vector_fails():
    content = (VECTORS / "tampered_field.jsonl").read_text()
    result = pv_verify_records(content)
    assert result["passed"] is False
    assert "record_hash mismatch" in result["output"]


def test_deleted_record_vector_fails():
    content = (VECTORS / "deleted_record.jsonl").read_text()
    result = pv_verify_records(content)
    assert result["passed"] is False
    assert "chain break" in result["output"]


def test_divergent_vector_fails():
    content = (VECTORS / "divergent.jsonl").read_text()
    result = pv_verify_records(content)
    assert result["passed"] is False
    assert "ENFORCEMENT DIVERGENCE" in result["output"]


def test_malformed_content_does_not_crash():
    result = pv_verify_records("not valid jsonl at all {{{")
    assert result["passed"] is False
