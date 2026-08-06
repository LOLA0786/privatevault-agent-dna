"""Optional runtime guard driven by a pv-validation/1 report.

Contract with the enforcement core (the non-negotiable part):

- The guard NEVER touches deterministic levels L0-L4. It has no API
  through which it could.
- Its only runtime effect is at the existing ``drift`` level, and it
  is TIGHTEN-ONLY: ``effective_drift_threshold`` returns
  min(configured, adjusted). A validation report can raise scrutiny;
  it can never lower it. A missing, expired, tampered, or malformed
  report leaves the configured threshold exactly as it was (plus a
  warning) -- absence of validation is the status quo, not a bypass.
- Calibration findings (high ECE, poor Brier) are REPORT-ONLY:
  surfaced via ``warnings()``, never converted into a threshold
  change. Calibration quality affects how probability outputs may be
  *described*, not how enforcement behaves.

Wiring: composition code may consult the guard when constructing the
DecisionEngine (which already takes ``drift_threshold``); the engine
itself is untouched. Enable by setting ``PV_VALIDATION_REPORT`` to
the report path.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field

ENV_VAR = "PV_VALIDATION_REPORT"
AUC_FLOOR = 0.60  # below this, ranking quality is too weak to trust
TIGHTEN_FACTOR = 0.80  # threshold *= factor when degraded (tighten-only)
ECE_WARN = 0.10


@dataclass
class ValidationGuard:
    report_path: str | None = None
    _body: dict | None = field(default=None, repr=False)
    _warnings: list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        path = self.report_path or os.environ.get(ENV_VAR)
        if not path:
            self._warnings.append(
                "no validation report configured (PV_VALIDATION_REPORT unset); "
                "drift threshold unchanged"
            )
            return
        try:
            envelope = json.loads(open(path, encoding="utf-8").read())
            body = envelope["body"]
            claimed = envelope["report_hash"]
            actual = hashlib.sha256(
                json.dumps(
                    body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode()
            ).hexdigest()
            if actual != claimed:
                self._warnings.append(
                    f"validation report REJECTED: hash mismatch ({path}); "
                    "drift threshold unchanged"
                )
                return
            if body.get("format") != "pv-validation/1":
                self._warnings.append(
                    "validation report REJECTED: unknown format; "
                    "drift threshold unchanged"
                )
                return
            if body.get("expires_at", 0) < time.time():
                self._warnings.append(
                    "validation report EXPIRED; drift threshold unchanged"
                )
                return
            self._body = body
            self._collect_calibration_warnings(body)
        except Exception as e:  # malformed file, unreadable, missing keys
            self._warnings.append(
                f"validation report unusable ({type(e).__name__}: {e}); "
                "drift threshold unchanged"
            )

    # ---------------------------------------------------------- runtime effect

    def effective_drift_threshold(self, configured: float) -> float:
        """Tighten-only adjustment of the drift threshold.

        If the sealed report shows global ranking quality below
        AUC_FLOOR, scrutiny is raised (threshold lowered) at the drift
        level only. The return value is never above ``configured``.
        """
        if self._body is None:
            return configured
        g = self._body.get("global")
        if not g or g.get("auc") is None:
            return configured
        if g["auc"] < AUC_FLOOR:
            return min(configured, configured * TIGHTEN_FACTOR)
        return configured

    # ---------------------------------------------------------- report-only

    def warnings(self) -> list[str]:
        return list(self._warnings)

    @property
    def loaded(self) -> bool:
        return self._body is not None

    def _collect_calibration_warnings(self, body: dict) -> None:
        cal = body.get("calibration")
        stype = body.get("score", {}).get("type")
        if stype == "ranking" and cal is not None:
            # defense in depth; verifier also rejects this
            self._warnings.append(
                "report anomaly: calibration metrics present on a ranking "
                "score -- treat calibration numbers as void"
            )
            return
        if cal:
            if cal.get("ece", 0) > ECE_WARN:
                self._warnings.append(
                    f"calibration warning (report-only): ECE={cal['ece']:.3f} "
                    f"> {ECE_WARN}; probability outputs should not be "
                    "presented as calibrated until recalibrated"
                )
        drift = body.get("drift")
        if drift and drift.get("verdict") == "concept_drift":
            self._warnings.append(
                "validation drift verdict: concept_drift -- advisory scorer "
                "no longer matches its validation window; "
                "investigate/retrain (report-only notice)"
            )
