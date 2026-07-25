"""tools/verify_records.py is vendored into drp-spec as the protocol's
canonical verifier. The copies must be byte-identical; this pins the
hash. Context: the two copies silently diverged (runtime advanced to
9 strict check families while the spec repo carried the 6-check
version) — found during the vector re-pin, resolved by promoting the
strict verifier to drp-spec. If the verifier legitimately changes,
update BOTH repos in lockstep and re-pin here in the same commit."""

import hashlib
from pathlib import Path

PINNED = "632972c0cb015457e9309f3c31ed65c13cb288c752409d9025f85d2d9882903b"


def test_verifier_matches_drp_spec_copy():
    actual = hashlib.sha256(Path("tools/verify_records.py").read_bytes()).hexdigest()
    assert actual == PINNED, (
        "verify_records.py changed — sync the copy in drp-spec and "
        "re-pin in the same commit"
    )
