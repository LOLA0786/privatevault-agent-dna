"""Generated pages ship with the repository, so they never carry a
credential-shaped string, fake or not: a public scanner cannot tell a test
fixture from a leak, and neither can a reader. The meeting dashboard once
listed a test id that spelled out a fake Stripe live key, and GitHub push
protection refused the push."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PAGES = [
    "architecture.html",
    "scenarios.html",
    "meeting-dashboard.html",
    "test-index.html",
]
CREDENTIAL = re.compile(
    r"(?:sk|rk)_live_[A-Za-z0-9]{20,}"
    r"|sk-proj-[A-Za-z0-9_-]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)


def credential_shaped(text: str) -> list[str]:
    return sorted({m.group(0)[:12] + "..." for m in CREDENTIAL.finditer(text)})


@pytest.mark.parametrize("page", PAGES)
def test_generated_page_carries_no_credential(page):
    assert credential_shaped((ROOT / page).read_text(encoding="utf-8")) == []


def test_negative_control_fake_key_is_caught():
    fake = "sk_live_" + "a" * 24
    assert credential_shaped(f"test_x[{fake}]") == ["sk_live_aaaa..."]
