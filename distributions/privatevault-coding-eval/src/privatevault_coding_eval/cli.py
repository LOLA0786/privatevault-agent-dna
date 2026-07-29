"""Command-line surface for the actual-runtime coding-agent evaluator."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .builtins import suites
from .doctor import (
    doctor_json,
    doctor_report,
    render_doctor_text,
)
from .harness import run_suite
from .scan import (
    iter_claude_code_events,
    write_events_jsonl,
)
from .scenario import load_scenario
from .verification import (
    VerificationError,
    verify_report,
)

PUBLIC_KEY_SPEC = "pv-coding-eval-public-key/0.1"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pv-coding-eval",
        description=(
            "PrivateVault evaluation harness for coding agents"
        ),
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    doctor = commands.add_parser(
        "doctor",
        help="prove runtime coupling",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
    )

    listing = commands.add_parser(
        "list",
        help="list built-in scenarios",
    )
    listing.add_argument(
        "--json",
        action="store_true",
    )

    run = commands.add_parser(
        "run",
        help="run actual-runtime scenarios",
    )
    source = run.add_mutually_exclusive_group(
        required=True,
    )
    source.add_argument(
        "--suite",
        choices=(
            "baseline",
            "adversarial",
        ),
    )
    source.add_argument(
        "--scenario",
        type=Path,
    )
    run.add_argument(
        "--output",
        type=Path,
        default=Path("results.json"),
    )
    run.add_argument(
        "--public-key-output",
        type=Path,
    )

    scan = commands.add_parser(
        "scan",
        help="scan an observed Claude Code session",
    )
    scan.add_argument(
        "--claude-jsonl",
        type=Path,
        required=True,
    )
    scan.add_argument(
        "--output",
        type=Path,
        default=Path("observed-events.jsonl"),
    )

    verify = commands.add_parser(
        "verify",
        help=(
            "runtime-coupled verification "
            "with an out-of-band trust key"
        ),
    )
    verify.add_argument(
        "report",
        type=Path,
    )
    verify.add_argument(
        "--trusted-public-key",
        type=Path,
        required=True,
    )

    return parser


def _write_json(
    path: Path,
    value: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _read_object(
    path: Path,
) -> Mapping[str, Any]:
    value = json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )

    if not isinstance(value, Mapping):
        raise ValueError(
            f"{path}: expected JSON object"
        )

    return value


def _key_path(
    arguments: argparse.Namespace,
) -> Path:
    public_key_output = arguments.public_key_output

    if public_key_output is not None:
        if not isinstance(public_key_output, Path):
            raise ValueError(
                "invalid public-key output path"
            )

        return public_key_output

    output = arguments.output

    if not isinstance(output, Path):
        raise ValueError(
            "invalid report output path"
        )

    return output.with_suffix(
        ".public-key.json"
    )


def _run(
    arguments: argparse.Namespace,
) -> int:
    if arguments.suite is not None:
        suite_name = arguments.suite
        scenarios = suites()[suite_name]
    else:
        suite_name = (
            f"custom:{arguments.scenario.name}"
        )
        scenarios = (
            load_scenario(
                arguments.scenario,
            ),
        )

    report, public_key = run_suite(
        suite_name,
        scenarios,
    )

    key_path = _key_path(arguments)

    _write_json(
        arguments.output,
        report,
    )
    _write_json(
        key_path,
        {
            "spec": PUBLIC_KEY_SPEC,
            "algorithm": "Ed25519",
            "public_key": public_key,
        },
    )

    print("PRIVATEVAULT CODING AGENT EVALUATION")
    print("=" * 56)
    print(f"Suite             {suite_name}")
    print(
        f"Scenarios run     "
        f"{report['scenarios_run']}"
    )
    print(
        f"Scenarios passed  "
        f"{report['scenarios_passed']}"
    )
    print(
        f"Scenarios failed  "
        f"{report['scenarios_failed']}"
    )
    print(f"Signed report     {arguments.output}")
    print(f"Trust key         {key_path}")
    print(
        f"VERDICT           "
        f"{'PASS' if report['passed'] else 'FAIL'}"
    )

    return 0 if report["passed"] else 1


def _scan(
    arguments: argparse.Namespace,
) -> int:
    count = write_events_jsonl(
        arguments.output,
        iter_claude_code_events(
            arguments.claude_jsonl,
        ),
    )

    print("PRIVATEVAULT CODING SESSION SCAN")
    print("=" * 56)
    print("Source             CLAUDE_CODE_JSONL")
    print(f"Events observed    {count}")
    print(f"Output             {arguments.output}")
    print("Evidence state     OBSERVED")
    print("VERDICT            COMPLETE")

    return 0


def _trusted_key(
    path: Path,
) -> str:
    document = _read_object(path)
    expected = {
        "spec",
        "algorithm",
        "public_key",
    }

    if set(document) != expected:
        raise ValueError(
            f"{path}: invalid trust-key fields"
        )

    if (
        document["spec"] != PUBLIC_KEY_SPEC
        or document["algorithm"] != "Ed25519"
        or not isinstance(
            document["public_key"],
            str,
        )
    ):
        raise ValueError(
            f"{path}: invalid trust key"
        )

    return document["public_key"]


def _verify(
    arguments: argparse.Namespace,
) -> int:
    report = _read_object(
        arguments.report,
    )

    result = verify_report(
        report,
        trusted_public_key=_trusted_key(
            arguments.trusted_public_key,
        ),
    )

    print(
        "PRIVATEVAULT CODING EVALUATION VERIFICATION"
    )
    print("=" * 56)
    print("Verifier           runtime-coupled")
    print(f"Suite              {result['suite']}")
    print(
        f"Records verified   "
        f"{result['scenarios_verified']}"
    )
    print(
        "Trust mode         "
        "OUT_OF_BAND_PUBLIC_KEY"
    )
    print("VERDICT            PASS")

    return 0


def _list(
    json_output: bool,
) -> int:
    listing = {
        name: [
            {
                "name": scenario.name,
                "description": scenario.description,
            }
            for scenario in scenarios
        ]
        for name, scenarios in suites().items()
    }

    if json_output:
        print(
            json.dumps(
                listing,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for suite_name, scenarios in listing.items():
            print(suite_name.upper())

            for scenario in scenarios:
                print(
                    f"  {scenario['name']}: "
                    f"{scenario['description']}"
                )

    return 0


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """Run the evaluator command line."""

    try:
        arguments = _parser().parse_args(argv)

        if arguments.command == "doctor":
            report = doctor_report()

            print(
                doctor_json()
                if arguments.json
                else render_doctor_text(report)
            )

            return 0 if report["ready"] else 1

        if arguments.command == "list":
            return _list(arguments.json)

        if arguments.command == "run":
            return _run(arguments)

        if arguments.command == "scan":
            return _scan(arguments)

        if arguments.command == "verify":
            return _verify(arguments)

        raise AssertionError(
            f"unhandled command: {arguments.command}"
        )

    except (
        OSError,
        ValueError,
        VerificationError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
