"""
Multi-Agent Security Layer -- trust between agents.

Owner: Chandan Galani.

A single-agent gate asks whether one agent's action is allowed. This layer
covers what goes wrong at the handoff between agents:

    delegation    Authority handed from one agent to another can only
                  shrink. A receiver verifies the whole signed chain
                  offline, so an agent cannot launder an action through a
                  more privileged one.            (``delegation``)

    independence  A quorum of voters that share a model, a provider or an
                  operator is one opinion counted several times. The
                  operator can require approving voters to differ.
                                                  (``independence``)

    replay        A cleared quorum is single-use across every replica that
                  shares the ledger, not only inside one process.
                                                  (``nonce_ledger``)

    deniability   Each party holds the other's signed checkpoints, so
                  neither can drop history afterwards without the other
                  being able to show it.          (``counterparty``)

What is enforced on the live decision path and what is a library only is
stated in docs/MULTI-AGENT-SECURITY.md. Nothing here uses a model.
"""

from .counterparty import (
    CheckpointRejected,
    CounterpartyLedger,
    verify_acknowledgement,
)
from .delegation import (
    DelegationDecision,
    DelegationError,
    TrustAnchors,
    authorize,
    issue_link,
    link_hash,
    verify_chain,
    within_scope,
)
from .gate import (
    DelegationConfigError,
    DelegationGate,
    DelegationPolicy,
    delegated_action_id,
    sign_presentation,
)
from .independence import ATTRIBUTES, independence_shortfall, normalize_label
from .nonce_ledger import (
    LedgerUnavailable,
    MemoryNonceLedger,
    NonceLedger,
    PostgresNonceLedger,
    SqliteNonceLedger,
)
from .possession import DelegationChallenges, sign_possession

__all__ = [
    "within_scope",
    "sign_presentation",
    "normalize_label",
    "delegated_action_id",
    "PostgresNonceLedger",
    "LedgerUnavailable",
    "DelegationPolicy",
    "DelegationGate",
    "DelegationConfigError",
    "ATTRIBUTES",
    "CheckpointRejected",
    "CounterpartyLedger",
    "DelegationChallenges",
    "DelegationDecision",
    "DelegationError",
    "MemoryNonceLedger",
    "NonceLedger",
    "SqliteNonceLedger",
    "TrustAnchors",
    "authorize",
    "independence_shortfall",
    "issue_link",
    "link_hash",
    "sign_possession",
    "verify_acknowledgement",
    "verify_chain",
]
