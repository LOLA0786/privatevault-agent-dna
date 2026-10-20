"""Every container image the product builds from or CI runs is pinned by
digest.

A tag such as ``python:3.12-slim`` is re-pointed by its publisher on every
patch release, so two builds of the same commit could start from different
bytes, and a compromised tag would flow straight into the release image. A
``@sha256:`` digest names one immutable manifest (here the multi-arch index,
so amd64 and arm64 builds both stay pinned). Dependabot's ``docker``
ecosystem proposes digest updates.

Images not yet pinned are listed in ``NOT_YET_PINNED`` with the reason; any
other unpinned reference fails.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
FROM = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE | re.MULTILINE)
IMAGE = re.compile(r"^\s*image:\s*['\"]?([^\s'\"{]+)['\"]?\s*$", re.MULTILINE)

# reference -> why it is not pinned yet
NOT_YET_PINNED = {
    "prom/prometheus:v2.55.1": "local platform compose only, not shipped",
    "alpine:3.20": "deletable pilot experiment, not shipped",
    "postgres:16.1": "deletable pilot experiment, not shipped",
}
SKIP_DIRS = {".git", ".venv", "node_modules", "target", "dist"}


def _files(patterns: tuple[str, ...]) -> list[Path]:
    out = []
    for pattern in patterns:
        for path in ROOT.rglob(pattern):
            if not SKIP_DIRS & set(path.relative_to(ROOT).parts):
                out.append(path)
    return sorted(set(out))


def _references() -> list[tuple[Path, str]]:
    refs = []
    for path in _files(("Dockerfile", "Dockerfile.*")):
        text = path.read_text()
        stages = {s.lower() for s in re.findall(r"\bAS\s+(\S+)", text, re.IGNORECASE)}
        for m in FROM.finditer(text):
            ref = m.group(1)
            if ref.lower() in stages or ref == "scratch":
                continue  # FROM <an earlier build stage>
            refs.append((path, ref))
    for path in _files(("*.yml", "*.yaml")):
        if ".github" in path.parts:
            continue
        for m in IMAGE.finditer(path.read_text()):
            refs.append((path, m.group(1)))
    return refs


def test_images_are_found():
    names = {ref.split("@")[0] for _p, ref in _references()}
    assert {"python:3.12-slim", "postgres:16"} <= names


def test_every_image_is_digest_pinned():
    unpinned = [
        f"{path.relative_to(ROOT)}: {ref}"
        for path, ref in _references()
        if not DIGEST.search(ref) and ref not in NOT_YET_PINNED
    ]
    assert not unpinned, "pin these by digest:\n" + "\n".join(unpinned)


def test_product_images_share_one_python_base():
    pythons = {ref for _p, ref in _references() if ref.startswith("python:")}
    assert len(pythons) == 1, pythons  # one base, updated together
