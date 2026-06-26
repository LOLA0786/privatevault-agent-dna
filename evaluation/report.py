"""
Pretty reporting for Agent DNA benchmark results.
"""

from __future__ import annotations

from pathlib import Path

from evaluation.benchmark import evaluate


def main() -> None:
    result = evaluate()

    out = Path("evaluation/results")
    out.mkdir(parents=True, exist_ok=True)

    report = result.report()

    print(report)

    (out / "benchmark_report.txt").write_text(report)

    print("\nSaved:")
    print(out / "benchmark_report.txt")


if __name__ == "__main__":
    main()
