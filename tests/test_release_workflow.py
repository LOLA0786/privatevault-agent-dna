"""A signed release must come from master, signed by a key master lists.

The release workflow checked a tag's SSH signature against
.github/allowed_signers read from the tagged commit itself, and never
checked that the commit was on master. Anyone who could push could add
their own key on a branch, tag that branch and get a release built,
attested, signed and published (audit finding, infra). These tests run the
workflow's own signature step against real SSH-signed tags.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
STEP = "Tag is signed by a release manager"

needs_ssh_keygen = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="needs ssh-keygen for SSH-signed tags"
)


def _job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["build"]


def _signature_script(text: str | None = None) -> str:
    job = yaml.safe_load(text)["jobs"]["build"] if text else _job()
    return next(step for step in job["steps"] if step.get("name") == STEP)["run"]


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def _key(tmp: Path, who: str) -> Path:
    key = tmp / who
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"{who}@example.test",
            "-f",
            str(key),
        ],
        check=True,
    )
    return key


def _as(repo: Path, who: str, key: Path) -> None:
    for name, value in (
        ("user.name", who),
        ("user.email", f"{who}@example.test"),
        ("gpg.format", "ssh"),
        ("user.signingkey", f"{key}.pub"),
    ):
        _git(repo, "config", name, value)


def _signers(*entries: tuple[str, Path]) -> str:
    return "".join(
        f"{who}@example.test {Path(f'{key}.pub').read_text().strip()}\n"
        for who, key in entries
    )


@pytest.fixture
def world(tmp_path: Path) -> dict:
    """master lists alice; mallory can push but is not listed."""
    alice, mallory = _key(tmp_path, "alice"), _key(tmp_path, "mallory")
    origin = tmp_path / "origin"
    (origin / ".github").mkdir(parents=True)
    _git(origin, "init", "-q", "-b", "master")
    _as(origin, "alice", alice)
    (origin / ".github" / "allowed_signers").write_text(_signers(("alice", alice)))
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "release managers")
    _git(origin, "tag", "-s", "-m", "release", "v1.0.0")
    _git(origin, "checkout", "-qb", "evil")
    _as(origin, "mallory", mallory)
    (origin / ".github" / "allowed_signers").write_text(
        _signers(("alice", alice), ("mallory", mallory))
    )
    _git(origin, "commit", "-qam", "add a release manager")
    _git(origin, "tag", "-s", "-m", "release", "v6.6.6")
    _git(origin, "checkout", "-q", "master")
    _git(
        origin, "tag", "-s", "-m", "release", "v1.0.1"
    )  # mallory's key, a master commit
    _as(origin, "alice", alice)
    _git(origin, "config", "user.email", "bob@example.test")
    _git(origin, "tag", "-s", "-m", "release", "v1.0.2")  # alice's key, tagger bob
    return {"origin": origin, "tmp": tmp_path}


def _release(world: dict, tag: str, script: str) -> subprocess.CompletedProcess[str]:
    runner = world["tmp"] / f"runner-{tag}"
    _git(world["tmp"], "clone", "-q", f"file://{world['origin']}", runner.name)
    _git(runner, "checkout", "-q", tag)
    env = {
        **os.environ,
        "TAG": tag,
        "RUNNER_TEMP": str(world["tmp"]),
        "GITHUB_STEP_SUMMARY": str(world["tmp"] / "summary"),
    }
    return subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=runner,
        env=env,
        capture_output=True,
        text=True,
    )


@needs_ssh_keygen
def test_a_release_managers_tag_on_master_is_accepted(world):
    assert _release(world, "v1.0.0", _signature_script()).returncode == 0


@needs_ssh_keygen
def test_a_tag_on_a_branch_that_lists_its_own_signer_is_refused(world):
    result = _release(world, "v6.6.6", _signature_script())
    assert result.returncode != 0
    assert "not on master" in result.stdout + result.stderr


@needs_ssh_keygen
def test_a_tag_signed_by_a_key_master_does_not_list_is_refused(world):
    result = _release(world, "v1.0.1", _signature_script())
    assert result.returncode != 0
    assert "not signed by a key" in result.stdout + result.stderr


@needs_ssh_keygen
def test_a_listed_key_cannot_sign_as_someone_else(world):
    result = _release(world, "v1.0.2", _signature_script())
    assert result.returncode != 0
    assert "but the tagger is" in result.stdout + result.stderr


def test_dry_runs_only_run_from_master():
    assert (
        _job()["if"]
        == "github.event_name == 'push' || github.ref == 'refs/heads/master'"
    )


def test_the_checkout_has_the_history_to_check_the_tag_is_on_master():
    checkout = next(
        step
        for step in _job()["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"]["fetch-depth"] == 0


def test_no_step_interpolates_a_value_into_its_script():
    assert not [
        step.get("name") for step in _job()["steps"] if "${{" in step.get("run", "")
    ]


def test_signatures_are_verified_against_the_exact_ref_not_a_pattern():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert (
        "--certificate-identity-regexp" not in text
    )  # neither in the steps nor in the documented command
    assert (
        "--certificate-identity 'https://github.com/LOLA0786/privatevault-agent-dna/.github/workflows/release.yml@refs/tags/<tag>'"
        in text
    )
