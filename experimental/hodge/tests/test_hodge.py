"""Mathematical invariants of the Hodge decomposition.

These are not accuracy tests. They pin the properties that must hold for the
decomposition to be a decomposition at all. If any fail, every number produced
by the experiments is meaningless regardless of how good it looks.

Run: python -m pytest experimental/hodge/tests -q
"""

from __future__ import annotations

import json
import pathlib

import numpy as np
import pytest

from hodge import (
    ComplexBuilder,
    boundary_matrices,
    decompose,
    verify_chain_complex,
)

VECTORS = pathlib.Path(__file__).parent.parent / "vectors" / "canonical.json"


def cosigned_triangle() -> ComplexBuilder:
    b = ComplexBuilder()
    b.add_flow("a", "b", 10.0)
    b.add_flow("b", "c", 9.0)
    b.add_flow("c", "a", 8.0)
    b.add_cosignature("a", "b", "c")
    return b


def uncosigned_triangle() -> ComplexBuilder:
    b = ComplexBuilder()
    b.add_flow("a", "b", 10.0)
    b.add_flow("b", "c", 9.0)
    b.add_flow("c", "a", 8.0)
    return b


def pure_hierarchy() -> ComplexBuilder:
    b = ComplexBuilder()
    b.add_flow("root", "mid", 10.0)
    b.add_flow("mid", "leaf_a", 5.0)
    b.add_flow("mid", "leaf_b", 4.0)
    return b


# ----------------------------------------------------------- chain complex


def test_boundary_of_boundary_is_zero():
    """d-squared = 0. The defining identity of a chain complex.

    If this fails the orientation convention in boundary_matrices is wrong
    and the three components are not orthogonal subspaces.
    """
    complex_, _ = cosigned_triangle().build()
    b1, b2 = boundary_matrices(complex_)

    assert np.allclose(b1 @ b2, 0.0, atol=1e-12)
    assert verify_chain_complex(complex_) == pytest.approx(0.0, abs=1e-12)


def test_boundary_identity_holds_on_multiple_faces():
    b = ComplexBuilder()
    b.add_cosignature("a", "b", "c")
    b.add_cosignature("b", "c", "d")
    b.add_cosignature("a", "c", "d")
    complex_, _ = b.build()

    assert verify_chain_complex(complex_) == pytest.approx(0.0, abs=1e-12)


# ------------------------------------------------------------ decomposition


@pytest.mark.parametrize(
    "builder_factory",
    [cosigned_triangle, uncosigned_triangle, pure_hierarchy],
)
def test_components_reconstruct_the_original_flow(builder_factory):
    complex_, flow = builder_factory().build()
    parts = decompose(complex_, flow)

    recomposed = parts.gradient + parts.curl + parts.harmonic
    assert np.allclose(recomposed, flow, atol=1e-10)


@pytest.mark.parametrize(
    "builder_factory",
    [cosigned_triangle, uncosigned_triangle, pure_hierarchy],
)
def test_components_are_mutually_orthogonal(builder_factory):
    complex_, flow = builder_factory().build()
    parts = decompose(complex_, flow)

    for inner_product in parts.orthogonality():
        assert inner_product < 1e-9


@pytest.mark.parametrize(
    "builder_factory",
    [cosigned_triangle, uncosigned_triangle, pure_hierarchy],
)
def test_energy_fractions_sum_to_one(builder_factory):
    complex_, flow = builder_factory().build()
    parts = decompose(complex_, flow)

    total = parts.gradient_energy + parts.curl_energy + parts.harmonic_energy
    assert total == pytest.approx(1.0, abs=1e-9)


# --------------------------------------------------------- domain semantics


def test_pure_hierarchy_has_no_circulation():
    """A tree has no cycles, so all flow is gradient."""
    complex_, flow = pure_hierarchy().build()
    parts = decompose(complex_, flow)

    assert parts.gradient_energy == pytest.approx(1.0, abs=1e-9)
    assert parts.curl_energy == 0.0
    assert parts.harmonic_energy == 0.0


def test_cosigned_cycle_is_curl_not_harmonic():
    """Circulation inside a jointly approved face is sanctioned."""
    complex_, flow = cosigned_triangle().build()
    parts = decompose(complex_, flow)

    assert parts.curl_energy > 0.5
    assert parts.harmonic_energy == 0.0


def test_uncosigned_cycle_is_harmonic():
    """The same circulation without joint approval is harmonic.

    This is the entire security claim: identical flow, different evidence,
    different component. A cycle detector cannot separate these two cases.
    """
    complex_, flow = uncosigned_triangle().build()
    parts = decompose(complex_, flow)

    assert parts.harmonic_energy > 0.5
    assert parts.curl_energy == 0.0


def test_cosignature_changes_classification_of_identical_flow():
    """Pin the discrimination directly: same flow, only evidence differs."""
    _, flow_a = cosigned_triangle().build()
    _, flow_b = uncosigned_triangle().build()
    assert np.allclose(flow_a, flow_b)

    cosigned = decompose(*cosigned_triangle().build())
    uncosigned = decompose(*uncosigned_triangle().build())

    assert cosigned.harmonic_energy == 0.0
    assert uncosigned.harmonic_energy > 0.5


def test_interaction_triangle_is_not_a_face():
    """Three agents talking is not three agents co-signing.

    If mere interaction filled faces, every dense subgraph would look
    sanctioned and the method would report harmonic ~0 everywhere.
    """
    complex_, _ = uncosigned_triangle().build()
    assert complex_.n_faces == 0

    cosigned, _ = cosigned_triangle().build()
    assert cosigned.n_faces == 1


# --------------------------------------------------------------- numerics


def test_absent_components_are_exactly_zero():
    """Sub-precision dust must snap to 0.0, not 1e-17.

    Without this, ranking metrics compare floating point noise and results
    differ across BLAS builds. Regression test for exactly that bug.
    """
    complex_, flow = pure_hierarchy().build()
    parts = decompose(complex_, flow)

    assert parts.curl_energy == 0.0
    assert parts.harmonic_energy == 0.0
    assert isinstance(parts.curl_energy, float)


def test_decomposition_is_bit_identical_across_runs():
    """Determinism is a precondition for use anywhere near evidence."""
    first = decompose(*cosigned_triangle().build())
    second = decompose(*cosigned_triangle().build())

    assert first.harmonic_energy == second.harmonic_energy
    assert first.curl_energy == second.curl_energy
    assert first.gradient_energy == second.gradient_energy
    assert np.array_equal(first.gradient, second.gradient)


def test_zero_flow_does_not_divide_by_zero():
    b = ComplexBuilder()
    b.add_cosignature("a", "b", "c")
    complex_, flow = b.build()
    parts = decompose(complex_, flow)

    assert parts.gradient_energy == 0.0
    assert parts.harmonic_energy == 0.0


def test_opposing_flows_cancel_on_the_same_edge():
    """Net flow is what the decomposition sees."""
    b = ComplexBuilder()
    b.add_flow("a", "b", 10.0)
    b.add_flow("b", "a", 10.0)
    _, flow = b.build()

    assert flow[0] == pytest.approx(0.0)


def test_self_loops_are_ignored():
    b = ComplexBuilder()
    b.add_flow("a", "a", 10.0)
    complex_, _ = b.build()

    assert complex_.n_edges == 0


# ------------------------------------------------------- canonical vectors


def test_canonical_vectors_are_reproduced_exactly():
    """Stored vectors must not regenerate on run.

    Vectors that rewrite themselves prove nothing. These are committed and
    compared, never overwritten.
    """
    stored = json.loads(VECTORS.read_text())

    factories = {
        "cosigned_triangle": cosigned_triangle,
        "uncosigned_triangle": uncosigned_triangle,
        "pure_hierarchy": pure_hierarchy,
    }

    for name, expected in stored["cases"].items():
        parts = decompose(*factories[name]().build())
        assert parts.gradient_energy == pytest.approx(
            expected["gradient"], abs=1e-9
        ), name
        assert parts.curl_energy == pytest.approx(
            expected["curl"], abs=1e-9
        ), name
        assert parts.harmonic_energy == pytest.approx(
            expected["harmonic"], abs=1e-9
        ), name
