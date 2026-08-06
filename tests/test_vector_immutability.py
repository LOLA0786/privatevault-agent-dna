"""The committed DRP spec vectors are the protocol's frozen ground
truth. Nothing in a test run may mutate them -- external implementers
verify against these exact bytes. This test pins their SHA-256s.

Regression context: test_rust_conformance.py previously invoked the
vector generator against spec/test-vectors/ on every run, silently
rewriting the canonical vectors (fresh UUIDs and timestamps each
time) -- and at least one regenerated set was committed before the
bug was found, which is why the canonical generation is pinned as of
the fix commit. If a vector must genuinely change (deliberate
protocol change), regenerate with tools/generate_test_vectors.py,
update the hashes below in the same reviewed commit, and cut a spec
version.
"""

import hashlib
from pathlib import Path

VECTORS = Path(__file__).resolve().parent.parent / "spec" / "test-vectors"

PINNED = {
    "clean.jsonl": "e120ab7f07f815fba4a56f422310d8620e627475a9849cc67a1488a65277de28",
    "deleted_record.jsonl": "30e78af2989eac144e390936cf908d928894e8d43caeee05e04e16fb57f133b8",
    "divergent.jsonl": "54c7a970d49edcf08dd123b733b5808b0c7176a821d2011ee2520ec5498135b1",
    "tampered_field.jsonl": "1ef82be1d8eb0f17bec11bf82426d2c645f9f19d111b8a8a362d5da52989f310",
}


def test_canonical_vectors_unmodified():
    for name, expected in PINNED.items():
        actual = hashlib.sha256((VECTORS / name).read_bytes()).hexdigest()
        assert actual == expected, (
            f"{name} differs from the committed canonical vector "
            f"(got {actual[:12]}…). A test or tool has mutated the spec; "
            "restore with `git checkout -- spec/test-vectors/` and fix "
            "the writer to target a temp dir."
        )


def test_no_stray_files_in_vector_dir():
    names = {p.name for p in VECTORS.glob("*.jsonl")}
    assert names == set(PINNED), f"unexpected vector files: {names ^ set(PINNED)}"
