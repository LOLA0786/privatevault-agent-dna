"""
Vendored from PrivateVault.ai's pv_runtime_v2 consensus module.
Origin: pv_runtime_v2/src/pv_runtime_v2/consensus/weighted_quorum.py
and leader_state.py. That source had zero tests prior to vendoring;
this module and its test suite were written fresh against the
vendored code, following the same pattern used for UAAL's EAV engine
in Step 13.

Note on naming: the source repo also has a "ConsensusEngine" class,
which is a single-value threshold bucketer (trust_score -> 1.0/0.8/0.0),
not a multi-agent agreement mechanism. It is NOT vendored here to
avoid implying threshold classification is consensus. WeightedQuorum
below is the actual voting logic.
"""

from .weighted_quorum import LeaderState, Vote, WeightedQuorum

__all__ = ["LeaderState", "Vote", "WeightedQuorum"]
