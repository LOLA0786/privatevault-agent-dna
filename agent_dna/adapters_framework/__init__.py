"""
Evidence adapter framework — the pattern any future data-source
connector should follow, built in direct response to a real incident:
the AMLSim benchmark's first run silently flagged 100% of transactions
because the adapter's authorization model (empty GrantRegistry) wasn't
noticed until the run completed and the numbers looked wrong.

Three guarantees this framework enforces structurally, not by
developer discipline alone:

  1. Ground-truth isolation: a SourceRow's ground-truth fields are
     type-separated from its evidence output. An adapter physically
     cannot leak a label into evidence without an explicit, named
     override.
  2. Schema validation: every evidence dict is checked against the
     real shapes documented in spec/contracts/evidence-integration.md
     before it's usable.
  3. Dry-run by default: an adapter's first invocation reports what
     WOULD happen -- verdict distribution, evidence-shape summary,
     skipped-check counts -- without being trusted as ground truth
     until explicitly run live.
"""

from .base import EvidenceAdapter, DryRunReport, SourceRow

__all__ = ["EvidenceAdapter", "DryRunReport", "SourceRow"]
