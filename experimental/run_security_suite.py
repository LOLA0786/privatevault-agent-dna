import json
from pathlib import Path

from agent_dna.security_validation.orchestrator import AttackOrchestrator


def main():
    orchestrator = AttackOrchestrator()

    summary = orchestrator.run_all(
        target_agent="demo-agent"
    )

    reports_dir = Path("agent_dna/security_validation/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_file = reports_dir / "latest_security_report.json"

    with output_file.open("w") as f:
        json.dump(summary, f, indent=2)

    print("=" * 60)
    print("Security Validation Complete")
    print("=" * 60)
    print(f"Adversaries executed : {summary['adversaries_executed']}")
    print(f"Average score        : {summary['average_score']:.2f}")
    print(f"Report written to    : {output_file}")


if __name__ == "__main__":
    main()
