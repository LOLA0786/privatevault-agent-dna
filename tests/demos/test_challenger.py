"""The continuous challenger, short: every challenge runs against real
services. Nothing may move money, burn an honest refund or go unseen."""

import json
import os

import pytest

from demos.live_checkout import challenger

ARGS = [
    "--actions",
    "8",
    "--seed",
    "4242",
    "--race-every",
    "4",
    "--bypass-every",
    "4",
    "--reconcile-every",
    "4",
    "--drill-every",
    "8",
]


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    run = tmp_path_factory.mktemp("challenger")
    before = os.environ.get(challenger.QUEUE_ENV)
    challenger.main([*ARGS, "--run-dir", str(run)])
    assert os.environ.get(challenger.QUEUE_ENV) == before  # no leak into later worlds
    return json.loads((run / "challenger-summary.json").read_text())


def test_no_money_moves_and_the_oracle_can_see(report):
    failing = [f for f in report["failures"] if f["verdict"] != "LEAK"]
    assert not failing, failing
    assert report["tally"]["upstream_direct"].get("BOUNDARY")  # planted bypass seen
    assert report["tally"]["velocity_race"].get("CAUGHT")


@pytest.mark.xfail(
    strict=True,
    reason="grant spend committed by the engine is not "
    "released when /v1/decide later refuses (ADR 0045 fact check)",
)
def test_refused_decides_do_not_spend_the_grant(report):
    assert not report["tally"]["budget_oracle"].get("LEAK"), report["tally"][
        "budget_oracle"
    ]
