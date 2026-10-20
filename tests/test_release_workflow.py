"""The release workflow can be rehearsed without publishing, and a real
release cannot ship under the wrong version.

Before this, release.yml had never run (no tag had been cut with it) and
its first real run would also have been its first test.

Claims -> tests:
  - A manual run rehearses every step but publishing the release
    -> test_dry_run_skips_only_the_release
  - A tag must equal the package version -> test_tag_must_match_the_version
  - A tag with a pre-release part is published as a pre-release
    -> test_rc_tags_are_prereleases
  - The image is signed and its provenance pushed to the registry by digest
    -> test_image_is_attested_and_signed_by_digest
  - The run verifies both, as a consumer would, before publishing
    -> test_image_is_verified_before_publishing
  - A release tag is SSH-signed by a key listed for the tagger's email in
    .github/allowed_signers, checked before anything is built
    -> test_tag_signature_is_checked_first, test_release_managers_are_listed
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SIGNERS = ROOT / ".github" / "allowed_signers"
RELEASE_MANAGER = "chandan.galani@privatevault.ai"
DOC = yaml.safe_load(WORKFLOW.read_text())
TRIGGERS = DOC[True]  # YAML 1.1 reads the key "on" as True
STEPS = DOC["jobs"]["build"]["steps"]


def _step(name: str) -> dict:
    (step,) = [s for s in STEPS if s.get("name") == name]
    return step


def test_dry_run_skips_only_the_release():
    assert set(TRIGGERS) == {"push", "workflow_dispatch"}
    assert TRIGGERS["push"]["tags"] == ["v*"]
    gated = [s.get("name") for s in STEPS if "if" in s]
    assert gated == [
        "Tag is signed by a release manager",
        "Tag matches the package version",
        "Publish the GitHub release",
    ]
    assert all(s["if"] == "github.event_name == 'push'" for s in STEPS if "if" in s)
    assert "dryrun-" in _step("Build and push image")["run"]
    assert _step("Keep dist/ for verification")["with"]["path"] == "dist/"


def test_tag_must_match_the_version():
    run = _step("Tag matches the package version")["run"]
    assert "Version(tag[1:]) != Version(pkg)" in run
    names = [s.get("name") for s in STEPS]
    assert names.index("Tag matches the package version") < names.index(
        "Tests must pass on the tagged commit"
    )


def test_rc_tags_are_prereleases():
    run = _step("Publish the GitHub release")["run"]
    assert '*-*) PRE="--prerelease"' in run
    assert "--verify-tag" in run


def test_image_is_attested_and_signed_by_digest():
    attest = _step("Image build provenance (pushed to the registry)")["with"]
    assert attest["subject-digest"] == "${{ steps.image.outputs.sha }}"
    assert attest["push-to-registry"] is True
    sign = _step("Sign the image (keyless)")["run"]
    assert sign == 'cosign sign --yes "${{ steps.image.outputs.ref }}"'
    perms = DOC["jobs"]["build"]["permissions"]
    assert perms["id-token"] == "write" and perms["attestations"] == "write"


def test_image_is_verified_before_publishing():
    names = [s.get("name") for s in STEPS]
    verify = names.index("Verify the image signature and provenance")
    assert names.index("Sign the image (keyless)") < verify
    assert verify < names.index("Publish the GitHub release")
    run = _step("Verify the image signature and provenance")["run"]
    assert 'cosign verify "$REF"' in run
    assert (
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in run
    )
    assert 'gh attestation verify "oci://$REF"' in run
    assert "--signer-workflow" in run


def test_tag_signature_is_checked_first():
    names = [s.get("name") for s in STEPS]
    assert names.index("Tag is signed by a release manager") < names.index(
        "Tag matches the package version"
    )
    run = _step("Tag is signed by a release manager")["run"]
    assert "-c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag" in run
    assert 'git cat-file -t "$TAG")" = tag' in run  # lightweight tags refused
    assert 'test "$signer" = "$tagger"' in run  # the key is the tagger's


def test_release_managers_are_listed():
    entries = [
        line.split()
        for line in SIGNERS.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert entries, "no release manager can sign a tag"
    for principal, *rest in entries:
        assert re.fullmatch(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", principal), principal
        key = [w for w in rest if not w.startswith("namespaces=")]
        assert key[0] in {
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "sk-ssh-ed25519@openssh.com",
        }
        assert re.fullmatch(r"AAAA[\w+/=]+", key[1]), "public key body"
    assert RELEASE_MANAGER in {e[0] for e in entries}
