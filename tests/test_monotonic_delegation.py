"""Authority can only narrow.

Seven rules in _verify_evidence make delegation monotonic: a child grant
can never carry authority its parent lacked. Containment of scope,
constraints and obligations is covered in test_authority_v01.py under
names describing containment. The structural rules below -- the ones
keeping a chain a chain rather than a set of grants that merely look
related -- were enforced but unnamed.

This is what bounds agents that spawn agents. A parent cannot hand a
child wider scope, a longer life, or an issuer it does not control, and
no configuration relaxes it: the receipt fails to verify.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_dna.authority_v01 import grant_digest  # noqa: E402
from tests.test_authority_v01 import (  # noqa: E402
    _replace_child,
    _report,
    artifacts,  # noqa: F401 -- pytest fixture, reused
)


def test_child_must_link_to_its_actual_parent(artifacts):  # noqa: F811
    """Re-pointing parent_grant_digest at a well-formed but wrong digest
    breaks the chain, even though both grants are individually valid and
    correctly signed. Linkage is by content, not by declaration."""
    # Point at the digest of the child itself: a well-formed digest of a
    # real grant, just not the one that issued this authority.
    receipt = _replace_child(
        artifacts,
        lambda child: child.update(
            parent_grant_digest=grant_digest(
                artifacts["receipt"]["grant_chain"][1]
            )
        ),
    )
    report = _report(artifacts, receipt)
    assert not report.ok
    assert report.reason_code == "CHAIN_DISCONTINUOUS"


def test_child_issuer_must_be_the_parent_subject(artifacts):  # noqa: F811
    """Delegation flows through the holder. A grant issued by a principal
    that was never the parent's subject is not delegation -- it is a
    second root wearing a child's shape."""
    receipt = _replace_child(
        artifacts,
        lambda child: child.update(issuer_principal="stranger@example"),
    )
    report = _report(artifacts, receipt)
    assert not report.ok
    assert report.reason_code == "KEY_CONTINUITY_BROKEN"


def test_child_may_not_outlive_its_parent(artifacts):  # noqa: F811
    """A child window extending past its parent's would let revoked
    authority keep acting through its delegate."""
    receipt = _replace_child(
        artifacts,
        lambda child: child.update(expires_at="2099-01-01T00:00:00Z"),
    )
    report = _report(artifacts, receipt)
    assert not report.ok
    assert report.reason_code == "GRANT_EXCEEDS_PARENT_AUTHORITY"
