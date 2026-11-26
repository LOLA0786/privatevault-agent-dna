"""A second implementation, sharing no code with PrivateVault, agrees with every vector.

tools/check_execution_vectors.py re-implements RFC 8785, Ed25519 verification
and the four checks from spec/execution-v01/vectors/README.md with Python's
standard library alone. These tests pin what makes that meaningful: it
agrees with every case, it imports nothing outside the standard library, it
notices when the file is wrong, and its Ed25519 matches both RFC 8032's
published Test 1 and libsodium on random keys, messages and tampered
signatures.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import random
import subprocess
import sys
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools" / "check_execution_vectors.py"
VECTORS = ROOT / "spec" / "execution-v01" / "vectors" / "execution-v01.json"
SECTIONS = (
    "authorization_cases",
    "presenter_cases",
    "witness_cases",
    "wire_binding_cases",
)


def _checker():
    spec = importlib.util.spec_from_file_location("check_execution_vectors", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_the_independent_checker_agrees_with_every_case():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    total = sum(len(data[section]) for section in SECTIONS)
    result = _run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"{total} of {total} cases agree; fixtures agree" in result.stdout


def test_the_checker_imports_only_the_standard_library():
    tree = ast.parse(CHECKER.read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported |= {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0
    }
    outside = imported - set(sys.stdlib_module_names) - {"__future__"}
    assert not outside, (
        f"the checker must stay standard-library-only; it imports {sorted(outside)}"
    )


def test_the_checker_notices_a_wrong_outcome_and_a_forged_signature(tmp_path):
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    cases = {case["id"]: case for case in data["authorization_cases"]}
    cases["EA-03"]["expect"].update(decision_conformance="CONFORMANT", reason_code=None)
    signature = cases["EA-20"]["authorization"]["signature"]
    swap = "B" if signature[20] == "A" else "A"
    cases["EA-20"]["authorization"]["signature"] = (
        signature[:20] + swap + signature[21:]
    )
    altered = tmp_path / "altered.json"
    altered.write_text(json.dumps(data), encoding="utf-8")

    result = _run(str(altered))

    assert result.returncode == 1
    assert "DISAGREE EA-03:" in result.stdout
    assert "DISAGREE EA-20:" in result.stdout and "SIGNATURE_INVALID" in result.stdout


def test_its_ed25519_accepts_rfc_8032_test_1_and_nothing_near_it():
    checker = _checker()
    public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065"
        "224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert checker.ed25519_verify(public, b"", signature)
    assert not checker.ed25519_verify(public, b"\x00", signature)
    assert not checker.ed25519_verify(
        public, b"", signature[:63] + bytes([signature[63] ^ 1])
    )


def test_its_ed25519_agrees_with_libsodium():
    checker = _checker()
    rng = random.Random(8032)
    for _ in range(40):
        key = SigningKey(rng.randbytes(32))
        message = rng.randbytes(rng.randrange(0, 200))
        signature = key.sign(message).signature
        public = bytes(key.verify_key)
        for candidate_message, candidate_signature in (
            (message, signature),
            (message + b"x", signature),
            (message, bytes([signature[0] ^ 1]) + signature[1:]),
            (message, signature[:40] + bytes([signature[40] ^ 4]) + signature[41:]),
        ):
            try:
                VerifyKey(public).verify(candidate_message, candidate_signature)
                sodium = True
            except BadSignatureError:
                sodium = False
            assert (
                checker.ed25519_verify(public, candidate_message, candidate_signature)
                is sodium
            )
