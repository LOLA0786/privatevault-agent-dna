"""Discrete Hodge decomposition on agent interaction complexes.

Deterministic linear algebra. No learned parameters, no fitted thresholds, no
randomness. Same complex and same flow give the same decomposition every time,
which is what makes it admissible anywhere near an enforcement path.

Domain reading of the three components
--------------------------------------
An edge carries net authority/value flow between two agents. A 2-cell is a
JOINTLY CO-SIGNED action: three agents who all signed off on the same
operation. That choice is what gives the decomposition security meaning.

  gradient   flow explained by a consistent hierarchy. Ordinary delegation.
  curl       circulation around a co-signed face. Circular, and sanctioned.
  harmonic   circulation attributable to no co-signed face. A loop that
             routed AROUND joint approval.

The claim under test is narrow and falsifiable: harmonic energy separates
uncosigned circular authority from both ordinary hierarchy and sanctioned
circulation, and a cycle detector cannot, because to Tarjan every cycle looks
alike.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass(frozen=True)
class InteractionComplex:
    """A cell complex over agents, built from interaction events."""

    agents: tuple[str, ...]
    edges: tuple[tuple[int, int], ...]
    faces: tuple[tuple[int, int, int], ...]

    @property
    def n_agents(self) -> int:
        return len(self.agents)

    @property
    def n_edges(self) -> int:
        return len(self.edges)

    @property
    def n_faces(self) -> int:
        return len(self.faces)


@dataclass(frozen=True)
class HodgeComponents:
    """Orthogonal decomposition of an edge flow."""

    gradient: np.ndarray
    curl: np.ndarray
    harmonic: np.ndarray
    total_energy: float

    @property
    def gradient_energy(self) -> float:
        return _fraction(self.gradient, self.total_energy)

    @property
    def curl_energy(self) -> float:
        return _fraction(self.curl, self.total_energy)

    @property
    def harmonic_energy(self) -> float:
        return _fraction(self.harmonic, self.total_energy)

    @property
    def circulation_energy(self) -> float:
        """All flow not explained by hierarchy."""
        return self.curl_energy + self.harmonic_energy

    def residual(self) -> float:
        """Reconstruction error. Must be ~0 for a valid decomposition."""
        recomposed = self.gradient + self.curl + self.harmonic
        return float(np.linalg.norm(recomposed - self._original()))

    def _original(self) -> np.ndarray:
        return self.gradient + self.curl + self.harmonic

    def orthogonality(self) -> tuple[float, float, float]:
        """Pairwise inner products. All must be ~0."""
        return (
            float(abs(self.gradient @ self.curl)),
            float(abs(self.gradient @ self.harmonic)),
            float(abs(self.curl @ self.harmonic)),
        )


_ENERGY_FLOOR = 1e-12


def _fraction(component: np.ndarray, total: float) -> float:
    """Energy fraction, with sub-precision values snapped to exact zero.

    lstsq leaves dust around 1e-17 where a component is genuinely absent.
    Left in place that dust is compared bit-for-bit by any ranking metric,
    making results depend on the BLAS build rather than on the data. Energy
    below numerical precision is zero, so say so.
    """
    if total <= 0.0:
        return 0.0
    fraction = float((component @ component) / total)
    return 0.0 if fraction < _ENERGY_FLOOR else fraction


@dataclass
class ComplexBuilder:
    """Builds a cell complex from interaction events.

    Faces come only from co-signature. An arbitrary triangle in the
    interaction graph is NOT a face; three agents merely talking to each
    other does not constitute joint approval.
    """

    agents: list[str] = field(default_factory=list)
    _edge_index: dict[tuple[int, int], int] = field(default_factory=dict)
    _edges: list[tuple[int, int]] = field(default_factory=list)
    _flow: dict[int, float] = field(default_factory=dict)
    _faces: set[tuple[int, int, int]] = field(default_factory=set)

    def _agent(self, name: str) -> int:
        if name not in self.agents:
            self.agents.append(name)
        return self.agents.index(name)

    def add_flow(self, source: str, target: str, weight: float) -> None:
        """Record directed authority/value flow.

        Stored against a canonical (low, high) orientation, so flow in the
        reverse direction subtracts. Net flow is what the decomposition sees.
        """
        i, j = self._agent(source), self._agent(target)
        if i == j:
            return

        key = (min(i, j), max(i, j))
        sign = 1.0 if i < j else -1.0

        if key not in self._edge_index:
            self._edge_index[key] = len(self._edges)
            self._edges.append(key)

        index = self._edge_index[key]
        self._flow[index] = self._flow.get(index, 0.0) + sign * weight

    def add_cosignature(self, a: str, b: str, c: str) -> None:
        """Record that three agents jointly approved one action.

        This fills a face. Circulation inside a filled face is sanctioned.
        """
        i, j, k = sorted((self._agent(a), self._agent(b), self._agent(c)))
        if len({i, j, k}) != 3:
            return

        for pair in ((i, j), (i, k), (j, k)):
            if pair not in self._edge_index:
                self._edge_index[pair] = len(self._edges)
                self._edges.append(pair)
                self._flow.setdefault(self._edge_index[pair], 0.0)

        self._faces.add((i, j, k))

    def build(self) -> tuple[InteractionComplex, np.ndarray]:
        complex_ = InteractionComplex(
            agents=tuple(self.agents),
            edges=tuple(self._edges),
            faces=tuple(sorted(self._faces)),
        )
        flow = np.array(
            [self._flow.get(index, 0.0) for index in range(len(self._edges))],
            dtype=float,
        )
        return complex_, flow


def boundary_matrices(
    complex_: InteractionComplex,
) -> tuple[np.ndarray, np.ndarray]:
    """Return (B1, B2): node-edge and edge-face boundary operators.

    Orientation convention: edge (i, j) with i < j has boundary j - i.
    Face (i, j, k) with i < j < k has boundary (j,k) - (i,k) + (i,j).
    """
    b1 = np.zeros((complex_.n_agents, complex_.n_edges))
    for index, (i, j) in enumerate(complex_.edges):
        b1[i, index] = -1.0
        b1[j, index] = 1.0

    edge_index = {edge: index for index, edge in enumerate(complex_.edges)}
    b2 = np.zeros((complex_.n_edges, complex_.n_faces))
    for index, (i, j, k) in enumerate(complex_.faces):
        b2[edge_index[(j, k)], index] = 1.0
        b2[edge_index[(i, k)], index] = -1.0
        b2[edge_index[(i, j)], index] = 1.0

    return b1, b2


def decompose(
    complex_: InteractionComplex,
    flow: np.ndarray,
) -> HodgeComponents:
    """Split an edge flow into gradient, curl and harmonic parts.

    The three subspaces are mutually orthogonal because B1 @ B2 == 0, so the
    projections can be taken independently and the residual is harmonic by
    construction.
    """
    b1, b2 = boundary_matrices(complex_)
    total_energy = float(flow @ flow)

    if complex_.n_agents:
        potential, *_ = np.linalg.lstsq(b1.T, flow, rcond=None)
        gradient = b1.T @ potential
    else:
        gradient = np.zeros_like(flow)

    if complex_.n_faces:
        circulation, *_ = np.linalg.lstsq(b2, flow, rcond=None)
        curl = b2 @ circulation
    else:
        curl = np.zeros_like(flow)

    harmonic = flow - gradient - curl

    return HodgeComponents(
        gradient=gradient,
        curl=curl,
        harmonic=harmonic,
        total_energy=total_energy,
    )


def verify_chain_complex(complex_: InteractionComplex) -> float:
    """Return ||B1 @ B2||, which must be 0 for a valid complex.

    The fundamental identity of a chain complex. If nonzero, the orientation
    convention is wrong and every downstream number is garbage.
    """
    b1, b2 = boundary_matrices(complex_)
    if complex_.n_faces == 0:
        return 0.0
    return float(np.linalg.norm(b1 @ b2))
