"""Diagnostics proving that the evaluator uses the pinned real runtime."""

from __future__ import annotations

import json
import platform
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import agent_dna
from agent_dna import AgentAction, DecisionEngine, DriftScorer
from agent_dna.consensus.checker import ConsensusChecker
from agent_dna.decision_record import DecisionRecord
from agent_dna.evidence import EvidenceEngine
from agent_dna.grants import GrantRegistry
from agent_dna.policy.checker import PolicyChecker
from agent_dna.reference_policies import SequenceInvariantEngine
from agent_dna.signer import SIGNER_BACKEND, ReceiptSigner

from . import __version__

EXPECTED_RUNTIME_VERSION = "0.3.0"


def _runtime_version() -> str | None:
    try:
        return version("privatevault-agent-dna")
    except PackageNotFoundError:
        return None


def doctor_report() -> dict[str, Any]:
    """Return runtime dependency and component provenance."""

    runtime_version = _runtime_version()

    components = {
        item.__name__: item.__module__
        for item in (
            AgentAction,
            ConsensusChecker,
            DecisionEngine,
            DecisionRecord,
            DriftScorer,
            EvidenceEngine,
            GrantRegistry,
            PolicyChecker,
            ReceiptSigner,
            SequenceInvariantEngine,
        )
    }

    return {
        "spec": "pv-coding-eval-doctor/0.1",
        "package": "privatevault-coding-eval",
        "version": __version__,
        "python": platform.python_version(),
        "runtime_package": "privatevault-agent-dna",
        "expected_runtime_version": EXPECTED_RUNTIME_VERSION,
        "runtime_version": runtime_version,
        "runtime_location": str(Path(agent_dna.__file__).resolve().parent),
        "signer_backend": SIGNER_BACKEND,
        "runtime_components": components,
        "ready": runtime_version == EXPECTED_RUNTIME_VERSION,
    }


def render_doctor_text(
    report: dict[str, Any],
) -> str:
    """Render concise diagnostics for a reviewer."""

    components = report["runtime_components"]

    return "\n".join(
        (
            "PRIVATEVAULT CODING AGENT EVALUATOR",
            "=" * 56,
            f"Evaluator        {report['version']}",
            f"Runtime          {report['runtime_package']}",
            f"Runtime version  {report['runtime_version']}",
            f"Required version {report['expected_runtime_version']}",
            f"Runtime location {report['runtime_location']}",
            f"Signer backend   {report['signer_backend']}",
            f"Components       {len(components)} actual runtime classes",
            f"DOCTOR           {'PASS' if report['ready'] else 'FAIL'}",
        )
    )


def doctor_json() -> str:
    """Return formatted diagnostic JSON."""

    return json.dumps(
        doctor_report(),
        indent=2,
        sort_keys=True,
    )
