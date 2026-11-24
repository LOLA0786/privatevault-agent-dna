"""The AAT -02 analogues of PrivateVault's delegation vectors
(vectors/aat02/aat-analogues.json) stay in step with the suite they were
built from. With TENUO_DIR set to a tenuo-ai/tenuo checkout, every token is
rebuilt and run through the AAT reference verifier again."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SUITE = ROOT / "vectors" / "aat02" / "pv-delegation-2.json"
ANALOGUES = ROOT / "vectors" / "aat02" / "aat-analogues.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _expressible(suite: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        v["id"]: v["aat_02"]
        for v in suite["vectors"]
        if v["aat_02"]["verdict"] != "n/a"
    }


def test_analogues_match_the_suite():
    suite, analogues = _load(SUITE), _load(ANALOGUES)
    assert analogues["spec"] == "draft-niyikiza-oauth-attenuating-agent-tokens-02"
    want = _expressible(suite)
    assert [v["id"] for v in analogues["vectors"]] == list(want)
    for v in analogues["vectors"]:
        expected = {
            "verdict": want[v["id"]]["verdict"],
            "step": want[v["id"]].get("step"),
        }
        assert v["expected"] == expected, v["id"]
        assert v["presentation"]["aat_chain"] and v["presentation"]["aat_pop"], v["id"]


@pytest.mark.skipif(
    not os.environ.get("TENUO_DIR"), reason="set TENUO_DIR to a tenuo-ai/tenuo checkout"
)
def test_reference_verifier_agrees_and_tokens_are_current():
    spec = importlib.util.spec_from_file_location(
        "check_aat02", ROOT / "tools" / "check_aat02_analogues.py"
    )
    assert spec is not None and spec.loader is not None
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    builder = check.Builder(
        check.load_reference(Path(os.environ["TENUO_DIR"])), _load(SUITE)
    )
    committed = {v["id"]: v for v in _load(ANALOGUES)["vectors"]}
    for v in _load(SUITE)["vectors"]:
        if v["aat_02"]["verdict"] == "n/a":
            continue
        chain, pop = builder.presentation(v)
        assert committed[v["id"]]["presentation"] == {
            "aat_chain": chain,
            "aat_pop": pop,
        }, v["id"]
        assert builder.verdict(chain, pop, v) == (
            v["aat_02"]["verdict"],
            v["aat_02"].get("step"),
        ), v["id"]
