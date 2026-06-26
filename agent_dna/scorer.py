"""
Drift scorer.

Combines capability novelty, behavioral ordering, argument drift and
execution-rate anomalies into a single explainable advisory score.

IMPORTANT

Behavior scoring intentionally does NOT know about enterprise approvals.

Unknown capability
        ↓
Behavior = CRITICAL

Later

Authorization Policy
        ↓
may downgrade because the capability was explicitly approved.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .advisory import (
    AdvisorySignal,
    Posture,
    Severity,
)
from .dynamics import (
    BehaviorDynamics,
    _START,
)
from .manifold import CapabilityManifold
from .rate import RateAnomalyDetector
from .trace import AgentAction

_RARE_FREQ = 0.005

_Z_LOW = 2.0
_Z_HIGH = 6.0

_ELEVATED = 0.30
_CRITICAL = 0.70


class DriftScorer:

    def __init__(
        self,
        manifold: CapabilityManifold,
        dynamics: BehaviorDynamics,
    ) -> None:

        if not manifold.fitted:
            raise ValueError(
                "CapabilityManifold must be fitted."
            )

        if not dynamics.fitted:
            raise ValueError(
                "BehaviorDynamics must be fitted."
            )

        self.manifold = manifold
        self.dynamics = dynamics
        self.rate_detector = RateAnomalyDetector(
            manifold,
        )

    def score(
        self,
        action: AgentAction,
        prev_capability: Optional[str] = None,
        prev_timestamp: Optional[float] = None,
    ) -> AdvisorySignal:

        reasons: List[str] = []
        components: Dict[str, float] = {}

        components["novelty"] = self._novelty(
            action,
            reasons,
        )

        components["sequence"] = self._sequence(
            action,
            prev_capability,
            reasons,
        )

        components["arguments"] = self._arguments(
            action,
            reasons,
        )

        #
        # timing
        #

        if prev_timestamp is None:

            components["rate"] = 0.0

        else:

            interval = max(
                0.0,
                action.timestamp - prev_timestamp,
            )

            rate = self.rate_detector.score(
                interval,
            )

            components["rate"] = rate.score

            if rate.score >= 0.50:
                reasons.append(
                    rate.reason,
                )

        #
        # unseen capability dominates
        #

        if components["novelty"] >= 1.0:

            drift = 0.90

        else:

            drift = (
                0.40 * components["novelty"]
                + 0.25 * components["arguments"]
                + 0.20 * components["sequence"]
                + 0.15 * components["rate"]
            )

        drift = max(
            0.0,
            min(
                1.0,
                drift,
            ),
        )

        if drift >= _CRITICAL:

            severity = Severity.CRITICAL
            posture = Posture.RECOMMEND_BLOCK

        elif drift >= _ELEVATED:

            severity = Severity.ELEVATED
            posture = Posture.REQUIRE_APPROVAL

        else:

            severity = Severity.INFO
            posture = Posture.LOG

        if severity == Severity.INFO and not reasons:

            reasons.append(
                "Action consistent with trusted behavioral profile."
            )

        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=drift,
            severity=severity,
            components=components,
            reasons=reasons,
            recommended_posture=posture,
        )

    # ------------------------------------------------------------
    # Component Scores
    # ------------------------------------------------------------

    def _novelty(
        self,
        action: AgentAction,
        reasons: List[str],
    ) -> float:

        if not self.manifold.known_capability(
            action.capability,
        ):

            reasons.append(
                f"Capability '{action.capability}' has never appeared in the trusted profile."
            )

            return 1.0

        if (
            self.manifold.capability_frequency(
                action.capability,
            )
            < _RARE_FREQ
        ):

            reasons.append(
                f"Capability '{action.capability}' is rarely used."
            )

            return 0.40

        return 0.0

    def _sequence(
        self,
        action: AgentAction,
        prev: Optional[str],
        reasons: List[str],
    ) -> float:

        previous = prev if prev is not None else _START

        surprise = self.dynamics.surprise(
            previous,
            action.capability,
        )

        ceiling = self.dynamics.ceil_surprise

        score = max(
            0.0,
            min(
                1.0,
                (surprise - ceiling)
                /
                max(
                    ceiling,
                    1.0,
                ),
            ),
        )

        if score >= 0.85:

            if previous == _START:

                reasons.append(
                    f"Transition from session start to '{action.capability}' is improbable."
                )

            else:

                reasons.append(
                    f"Transition from '{previous}' to '{action.capability}' is improbable."
                )

        return score

    def _arguments(
        self,
        action: AgentAction,
        reasons: List[str],
    ) -> float:

        worst = 0.0

        features = self.manifold.feature_extractor(
            action,
        )

        for feature, value in features.items():

            #
            # Numeric
            #

            if isinstance(
                value,
                float,
            ):

                z = self.manifold.numeric_zscore(
                    action.capability,
                    feature,
                    value,
                )

                if z is None:
                    continue

                if z == float("inf"):

                    score = 1.0

                else:

                    score = max(
                        0.0,
                        min(
                            1.0,
                            (z - _Z_LOW)
                            /
                            (_Z_HIGH - _Z_LOW),
                        ),
                    )

                if score >= 0.50:

                    bounds = self.manifold.numeric_bounds(
                        action.capability,
                        feature,
                    )

                    if bounds:

                        reasons.append(
                            f"Argument '{feature}'={value:g} is outside trusted range "
                            f"({bounds[0]:g}..{bounds[1]:g})."
                        )

                    else:

                        reasons.append(
                            f"Argument '{feature}'={value:g} is outside trusted range."
                        )

                worst = max(
                    worst,
                    score,
                )

            #
            # Categorical
            #

            else:

                if self.manifold.categorical_is_novel(
                    action.capability,
                    feature,
                    str(value),
                ):

                    reasons.append(
                        f"Argument '{feature}'='{value}' was never seen for "
                        f"'{action.capability}'."
                    )

                    worst = max(
                        worst,
                        1.0,
                    )

        return worst
