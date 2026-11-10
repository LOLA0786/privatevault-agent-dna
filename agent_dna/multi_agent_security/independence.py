"""
Voter independence.

Three agents that approve are three opinions only if they could have
disagreed. If they run the same model with the same instructions under the
same operator, one prompt injection or one blind spot moves all three, and a
"3 of 3" quorum is one opinion counted three times.

Signatures cannot see this: three keys sign three valid votes. What can be
checked is what the OPERATOR declared about each voter when pinning the
roster -- its model, its provider, its operator -- and a rule over those:

    "require_distinct": {"provider": 2, "operator": 2}

means the approving voters must between them span at least two providers
and at least two operators. A voter with no declared value for an attribute
contributes nothing toward it, so an undeclared roster cannot satisfy a rule
by omission.

Limit: these are the operator's declarations. Nothing here measures whether
two differently-labelled voters are in fact independent, or whether a voter
runs the model its roster entry says.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

ATTRIBUTES = ("model", "provider", "operator")


def independence_shortfall(
    approvers: Iterable[str],
    attributes: Mapping[str, Mapping[str, str]],
    require: Mapping[str, int],
) -> list[str]:
    """Rules in ``require`` the approving voters fail, as readable reasons.

    ``attributes`` maps voter id to its declared attribute values. An empty
    list means every rule is met.
    """
    approving = list(approvers)
    shortfalls: list[str] = []
    for attribute, needed in sorted(require.items()):
        values = {
            attributes.get(voter, {}).get(attribute)
            for voter in approving
            if attributes.get(voter, {}).get(attribute)
        }
        if len(values) < needed:
            shortfalls.append(
                f"{attribute}: approving voters span {len(values)} distinct "
                f"value(s), {needed} required"
            )
    return shortfalls
