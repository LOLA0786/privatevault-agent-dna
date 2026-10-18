"""The Docker image installs what the deployments it serves need.

The Helm chart runs the image on PostgreSQL by default, and its signing
keys may live in AWS KMS. Both need packages that are optional extras in
pyproject.toml. The first kind install found every pod failing at start-up
because the image lacked the PostgreSQL driver.

Claims -> tests:
  - every package of the `postgres` and `kms-aws` extras is installed by
    default -> test_image_installs_the_extras_deployments_need
  - a Dockerfile without one is caught -> test_negative_control_missing_driver
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEEDED_EXTRAS = ("postgres", "kms-aws")
ARG = re.compile(r'^ARG\s+\w+="([^"]*)"', re.M)


def _name(requirement: str) -> str:
    return re.split(r"[\[<>=!~ ;]", requirement.strip(), maxsplit=1)[0].lower()


def needed() -> set[str]:
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]["optional-dependencies"]
    return {_name(r) for extra in NEEDED_EXTRAS for r in extras[extra]}


def installed_by_default(dockerfile: str, requirements: str) -> set[str]:
    names = {
        _name(line)
        for line in requirements.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for value in ARG.findall(dockerfile):
        names.update(_name(r) for r in value.split())
    return names


def test_image_installs_the_extras_deployments_need():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert {"psycopg", "psycopg-pool", "boto3"} <= needed()
    assert needed() - installed_by_default(dockerfile, requirements) == set()


def test_negative_control_missing_driver():
    dockerfile = 'ARG PV_KMS_PACKAGES="boto3>=1.40"\n'
    assert needed() - installed_by_default(dockerfile, "fastapi>=0.115\n") == {
        "psycopg",
        "psycopg-pool",
    }
