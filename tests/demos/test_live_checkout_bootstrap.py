"""The live refund demo's bootstrap.

Claims -> tests:
  - The gate tolerates 5 s of clock difference (ADR 0044)
    -> test_gate_clock_tolerance_is_set
  - A run directory made by an older demo (an older or missing
    bootstrap_version) is regenerated, not reused: an old services.env lacks
    settings today's services require (a gate without a transaction key does
    not start). A current one is reused as is.
    -> test_stale_run_directory_is_regenerated
"""

from __future__ import annotations

import json

from demos.live_checkout import config as cfg
from demos.live_checkout.bootstrap import BOOTSTRAP_VERSION, bootstrap


def test_gate_clock_tolerance_is_set(tmp_path):
    bootstrap(tmp_path / "run", force=True)
    env = cfg.parse_env_file(tmp_path / "run" / "services.env")
    assert env["PV_RECEIVER_CLOCK_SKEW_SECONDS"] == "5"


def test_stale_run_directory_is_regenerated(tmp_path, capsys):
    run = tmp_path / "run"
    first = bootstrap(run, force=True)
    assert first["bootstrap_version"] == BOOTSTRAP_VERSION
    again = bootstrap(run)
    assert again == first  # current: reused, keys unchanged

    marker = run / "READY"
    old = dict(first)
    old.pop("bootstrap_version")
    marker.write_text(json.dumps(old))
    env_file = run / "services.env"
    env_file.write_text(
        "\n".join(
            line
            for line in env_file.read_text().splitlines()
            if not line.startswith("PV_RECEIVER_TRANSACTION_KEYS")
        )
        + "\n"
    )

    regenerated = bootstrap(run)
    assert regenerated["bootstrap_version"] == BOOTSTRAP_VERSION
    assert "made by an older demo" in capsys.readouterr().err
    assert "PV_RECEIVER_TRANSACTION_KEYS" in cfg.parse_env_file(env_file)
