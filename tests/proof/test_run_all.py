"""P4: one command runs P1 to P3 and prints the results.

Claims -> tests:
  - run_all runs the three proofs in process, prints each block, and exits
    0 only if all three hold
    -> test_run_all_prints_every_proof_and_holds
  - The compose file resolves and names the one service and command
    -> test_compose_file_is_valid
  - Opt-in: the container runs the same command and prints the summary
    -> test_compose_runs_the_proofs (PV_PROOF_DOCKER_TESTS=1)
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from proof import run_all

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "proof" / "docker-compose.yml"


def test_run_all_prints_every_proof_and_holds(capsys, tmp_path):
    assert run_all.main(["--run-dir", str(tmp_path / "all")]) == 0
    out = capsys.readouterr().out
    for marker in (
        "P1 ",
        "P2 ",
        "P3 ",
        "RECEIVER_WIRE_MISMATCH",
        "48,000",
        "ACCT-ATTACKER",
        "ALL PROOFS HOLD",
    ):
        assert marker in out, marker


def _docker_available() -> bool:
    return (
        subprocess.run(
            ["docker", "compose", "version"], capture_output=True, check=False
        ).returncode
        == 0
    )


@pytest.mark.skipif(not _docker_available(), reason="docker compose not available")
def test_compose_file_is_valid():
    import yaml

    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "config"],
        cwd=COMPOSE.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    resolved = yaml.safe_load(result.stdout)
    assert list(resolved["services"]) == ["proof"]
    assert "proof.run_all" in " ".join(resolved["services"]["proof"]["command"])


@pytest.mark.skipif(
    os.environ.get("PV_PROOF_DOCKER_TESTS") != "1",
    reason="set PV_PROOF_DOCKER_TESTS=1 to build the image and run the proofs in a container",
)
def test_compose_runs_the_proofs():
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "proof",
        ],
        cwd=COMPOSE.parent,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
    assert "ALL PROOFS HOLD" in result.stdout
