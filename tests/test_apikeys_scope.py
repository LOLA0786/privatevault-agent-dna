"""API key scoping: audit-scoped keys can verify/export but must
never satisfy a full-access (enforcement) requirement. Full-scope
keys satisfy any requirement, including audit. Backward compatible:
plain-string key file entries mean scope=full, unchanged from before
scoping existed."""

import json

import pytest

from agent_dna.apikeys import ApiKeyRegistry, generate_key


def test_generate_key_defaults_to_full_scope():
    entry = generate_key("op-1")
    assert entry["scope"] == "full"


def test_generate_key_audit_scope():
    entry = generate_key("auditor-1", scope="audit")
    assert entry["scope"] == "audit"


def test_generate_key_rejects_invalid_scope():
    with pytest.raises(ValueError, match="scope must be one of"):
        generate_key("bad", scope="superuser")


def test_backward_compatible_plain_string_entry(tmp_path):
    """A key file written before scoping existed (plain string
    values) must keep working exactly as before -- scope=full,
    verify() still returns the name."""
    entry = generate_key("legacy-key")
    keyfile = tmp_path / "keys.json"
    # OLD FORMAT: plain string, not the new dict shape
    keyfile.write_text(json.dumps({entry["hash"]: entry["name"]}))

    reg = ApiKeyRegistry(str(keyfile))
    assert reg.verify(entry["key"]) == "legacy-key"
    assert reg.verify_scope(entry["key"], required_scope="full") == "legacy-key"
    assert reg.verify_scope(entry["key"], required_scope="audit") == "legacy-key"


def test_full_scope_key_satisfies_audit_requirement(tmp_path):
    """An operator's full key can do everything an auditor's key can
    -- full satisfies any requirement."""
    entry = generate_key("op-1", scope="full")
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(
        json.dumps({entry["hash"]: {"name": entry["name"], "scope": entry["scope"]}})
    )

    reg = ApiKeyRegistry(str(keyfile))
    assert reg.verify_scope(entry["key"], required_scope="full") == "op-1"
    assert reg.verify_scope(entry["key"], required_scope="audit") == "op-1"


def test_audit_scope_key_cannot_satisfy_full_requirement(tmp_path):
    """The core security property: an audit-scoped key must NEVER
    satisfy a full/enforcement requirement -- it must be rejected."""
    entry = generate_key("auditor-1", scope="audit")
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(
        json.dumps({entry["hash"]: {"name": entry["name"], "scope": entry["scope"]}})
    )

    reg = ApiKeyRegistry(str(keyfile))
    assert reg.verify_scope(entry["key"], required_scope="audit") == "auditor-1"
    assert reg.verify_scope(entry["key"], required_scope="full") is None


def test_invalid_key_returns_none_regardless_of_scope(tmp_path):
    entry = generate_key("op-1")
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(json.dumps({entry["hash"]: entry["name"]}))

    reg = ApiKeyRegistry(str(keyfile))
    assert reg.verify_scope("wrong-key-entirely", required_scope="full") is None
    assert reg.verify_scope("wrong-key-entirely", required_scope="audit") is None


def test_verify_unchanged_for_callers_not_using_scope(tmp_path):
    """Existing callers of verify() (not verify_scope()) must see
    identical behavior to before scoping existed."""
    entry = generate_key("op-1")
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(json.dumps({entry["hash"]: entry["name"]}))

    reg = ApiKeyRegistry(str(keyfile))
    assert reg.verify(entry["key"]) == "op-1"
    assert reg.verify(None) is None
    assert reg.verify("garbage") is None


def test_malformed_dict_entry_missing_name_raises(tmp_path):
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(json.dumps({"somehash": {"scope": "audit"}}))

    with pytest.raises(ValueError, match="missing 'name'"):
        ApiKeyRegistry(str(keyfile))


def test_malformed_dict_entry_bad_scope_raises(tmp_path):
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(json.dumps({"somehash": {"name": "x", "scope": "root"}}))

    with pytest.raises(ValueError, match="invalid scope"):
        ApiKeyRegistry(str(keyfile))
