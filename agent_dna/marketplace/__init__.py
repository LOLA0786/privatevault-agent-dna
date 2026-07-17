"""
Behavioral Profile Marketplace — Network Effects Layer.

Organizations contribute anonymized invariant patterns.
No agent identity or raw execution data leaves premises.
Only statistical patterns (drift distributions, invariant hits,
capability namespace frequencies) are aggregated.

This creates the network effect: more agents = stronger
cross-organization defense patterns.
"""

from .analytics import AggregateAnalytics
from .shared_invariants import SharedInvariantLibrary
from .profile_export import AnonymizedProfileExporter

__all__ = ["AggregateAnalytics", "SharedInvariantLibrary", "AnonymizedProfileExporter"]
