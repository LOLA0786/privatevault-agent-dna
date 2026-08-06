"""Every record in every spec test vector must validate against its
JSON Schema. This pins the schemas to reality: if a code change alters
the wire format, this fails before the format drifts from the spec."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "spec" / "schemas"
VECTORS = ROOT / "spec" / "test-vectors"


def _load_validator(name):
    schema = json.loads((SCHEMAS / name).read_text())
    Draft202012Validator.check_schema(schema)  # the schema itself is valid
    return Draft202012Validator(schema)


DECISION = _load_validator("decision_record.schema.json")
EXECUTION = _load_validator("execution_event.schema.json")

# tampered/deleted vectors are still schema-valid (their corruption is
# cryptographic, not structural) — so all four vectors must conform.
ALL_VECTORS = sorted(VECTORS.glob("*.jsonl"))


@pytest.mark.parametrize("vector", ALL_VECTORS, ids=lambda p: p.name)
def test_every_record_validates(vector):
    for lineno, line in enumerate(vector.read_text().splitlines(), 1):
        rec = json.loads(line)
        validator = EXECUTION if rec.get("kind") == "execution" else DECISION
        errors = list(validator.iter_errors(rec))
        assert not errors, f"{vector.name}:{lineno}: " + "; ".join(
            e.message for e in errors
        )


def test_schema_rejects_unknown_field():
    clean = (VECTORS / "clean.jsonl").read_text().splitlines()[0]
    rec = json.loads(clean)
    rec["smuggled"] = "unhashed data"
    errors = list(DECISION.iter_errors(rec))
    assert errors, "schema accepted an unknown field — conformance hole"


def test_schema_rejects_mutated_outcome():
    """Decisions are immutable: outcome must be 'pending' on the wire.
    An implementation that mutates decisions in place is nonconformant."""
    clean = (VECTORS / "clean.jsonl").read_text().splitlines()
    rec = json.loads(clean[0])
    assert rec["kind"] == "decision"
    rec["outcome"] = "ok"
    errors = list(DECISION.iter_errors(rec))
    assert errors, "schema accepted a mutated decision outcome"
