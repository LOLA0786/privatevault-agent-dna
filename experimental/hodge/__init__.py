"""Hodge decomposition on agent interaction complexes.

RESEARCH ARTIFACT. Not wired into any decision, enforcement or scoring path.
See README.md for status and the conditions under which that would change.
"""

from .hodge import (
    ComplexBuilder,
    HodgeComponents,
    InteractionComplex,
    boundary_matrices,
    decompose,
    verify_chain_complex,
)

__all__ = [
    "ComplexBuilder",
    "HodgeComponents",
    "InteractionComplex",
    "boundary_matrices",
    "decompose",
    "verify_chain_complex",
]
