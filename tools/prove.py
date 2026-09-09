#!/usr/bin/env python3
"""prove.py -- one command that re-runs every claim gate and seals the result.

    python tools/prove.py [-o proof-of-run.json]

What it runs, in order:
  1. the full pytest suite (every test nodeid is captured, not just counts)
  2. the adversarial corpus (tools/run_adversarial.py)
  3. the stdlib audit verifier against a fresh LIVE export generated
     through the real engine
  4. the stdlib validation verifier against the canonical vector
  5. the stdlib Discovery Loop verifier against its canonical vector
  6. hashes of the precedence contract and canonical vectors

Output: a sealed envelope {body, report_hash} in the same canonical-
JSON + SHA-256 pattern as decision records and pv-validation/1. The
body embeds the git commit, a dirty-tree flag, interpreter and
platform, wall-clock timings, and the complete list of passed tests.

What this does and does not prove. The seal makes the report
tamper-evident after the fact; it does not make the run trustworthy
to a third party -- a self-issued attestation never can. The honest
protocol for an outside reviewer is: clone the pinned commit, run
this command, diff the body (minus timestamps) against ours. The
value of this file is that it turns "the suite passes" from a
sentence into a reproducible artifact with a stable shape.

Exit code 0 iff every gate passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "spec" / "contracts" / "precedence-order.json"
VECTOR = ROOT / "spec" / "validation" / "vectors" / "valid_report.json"
DISCOVERY_VECTOR = (
    ROOT / "spec" / "discovery-loop-v1" / "vectors" / "no-change-report.json"
)


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def seal(body: dict) -> dict:
    return {
        "body": body,
        "report_hash": hashlib.sha256(canonical(body).encode()).hexdigest(),
    }


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_state() -> dict:
    def run(*args):
        try:
            return subprocess.run(
                ["git", *args], cwd=ROOT, text=True, capture_output=True
            ).stdout.strip()
        except FileNotFoundError:
            return ""

    return {
        "commit": run("rev-parse", "HEAD") or None,
        "dirty": bool(run("status", "--porcelain")),
    }


def run_pytest() -> dict:
    """Full suite. -rA report lines give one PASSED/FAILED line per
    nodeid, which we parse rather than trusting a summary count."""
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rA", "--color=no"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    out = proc.stdout
    passed = re.findall(r"^PASSED\s+(\S+)", out, re.M)
    failed = re.findall(r"^FAILED\s+(\S+)", out, re.M)
    skipped = re.findall(r"^SKIPPED\s+\[(\d+)\]", out, re.M)
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    return {
        "passed": len(passed),
        "failed": len(failed),
        "skipped": sum(int(n) for n in skipped),
        "summary_line": tail,
        "duration_s": round(time.time() - t0, 2),
        "failed_tests": failed,  # empty on a green run
        "passed_tests": sorted(passed),  # the full claim ledger
        "ok": proc.returncode == 0 and not failed and len(passed) > 0,
    }


def run_adversarial() -> dict:
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "run_adversarial.py")],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    m = re.search(
        r"RESULT:\s+(\d+)\s+passed,\s+(\d+)\s+failed,\s+(\d+)\s+total", proc.stdout
    )
    passed, failed, total = (int(x) for x in m.groups()) if m else (0, -1, 0)
    return {
        "passed": passed,
        "failed": failed,
        "total": total,
        "duration_s": round(time.time() - t0, 2),
        "ok": proc.returncode == 0 and failed == 0 and passed == total > 0,
    }


def run_validation_verifier() -> dict:
    if not VECTOR.exists():
        return {"ok": False, "error": "canonical vector missing"}
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "verify_validation.py"), str(VECTOR)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    return {
        "ok": proc.returncode == 0,
        "verdict_line": proc.stdout.strip().splitlines()[-1]
        if proc.stdout.strip()
        else "",
    }


def run_discovery_verifier() -> dict:
    if not DISCOVERY_VECTOR.exists():
        return {"ok": False, "error": "canonical discovery vector missing"}
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "verify_discovery.py"),
            str(DISCOVERY_VECTOR),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    return {
        "ok": proc.returncode == 0,
        "verdict_line": proc.stdout.strip().splitlines()[-1]
        if proc.stdout.strip()
        else "",
    }


def run_audit_verifier() -> dict:
    """Generate a small live export through the real engine, then
    verify it with the stdlib auditor -- proving the two agree on the
    wire format right now, not just in vectors."""
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="pv_prove_"))
    export = tmp / "export.jsonl"
    gen = (
        f"import sys; sys.path.insert(0, {str(ROOT)!r})\n"
        "from agent_dna.composition import RuntimeConfig, "
        "build_production_runtime\n"
        f"rt = build_production_runtime(RuntimeConfig(db_path={str(tmp / 'prove.db')!r}))\n"
        "from agent_dna.trace import AgentAction\n"
        "mon = rt.monitor()\n"
        "for i in range(5):\n"
        "    mon.process(AgentAction(agent_id='prove-agent',"
        " capability='crm.read_contact', timestamp=float(i)))\n"
        f"rt.store.export_jsonl({str(export)!r})\n"
    )
    g = subprocess.run(
        [sys.executable, "-c", gen], cwd=ROOT, text=True, capture_output=True
    )
    if g.returncode != 0 or not export.exists():
        return {
            "ok": False,
            "note": "mandatory live audit export generation failed",
            "generator_error": (g.stderr or "").strip()[-300:],
        }
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "verify_records.py"), str(export)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    return {
        "ok": proc.returncode == 0,
        "records": sum(1 for _ in export.open()),
        "verdict_line": proc.stdout.strip().splitlines()[-1]
        if proc.stdout.strip()
        else "",
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Re-run every claim gate and seal a pv-proof-of-run/1 envelope."
    )
    ap.add_argument("-o", "--out", default="proof-of-run.json")
    args = ap.parse_args()

    started = time.time()
    print("== 1/5 pytest (full suite) ==", flush=True)
    pytest_res = run_pytest()
    print(f"   {pytest_res['summary_line']}")
    print("== 2/5 adversarial corpus ==", flush=True)
    adv = run_adversarial()
    print(f"   {adv['passed']}/{adv['total']} passed")
    print("== 3/5 audit verifier on live export ==", flush=True)
    audit = run_audit_verifier()
    print(f"   {audit.get('verdict_line') or audit.get('note')}")
    print("== 4/5 validation verifier on canonical vector ==", flush=True)
    val = run_validation_verifier()
    print(f"   {val.get('verdict_line', val)}")
    print("== 5/5 discovery verifier on canonical vector ==", flush=True)
    discovery = run_discovery_verifier()
    print(f"   {discovery.get('verdict_line', discovery)}")

    gates_ok = all(
        [
            pytest_res["ok"],
            adv["ok"],
            val["ok"],
            discovery["ok"],
            audit["ok"] is True,  # Mandatory evidence must explicitly pass.
        ]
    )

    body = {
        "format": "pv-proof-of-run/1",
        "started_at": started,
        "finished_at": time.time(),
        "git": git_state(),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "pinned_artifacts": {
            "precedence_contract_sha256": sha256_file(CONTRACT),
            "validation_vector_sha256": sha256_file(VECTOR),
            "discovery_vector_sha256": sha256_file(DISCOVERY_VECTOR),
        },
        "gates": {
            "pytest": pytest_res,
            "adversarial": adv,
            "audit_verifier": audit,
            "validation_verifier": val,
            "discovery_verifier": discovery,
        },
        "all_gates_passed": gates_ok,
        "reproduction": "clone the commit above, run: python tools/prove.py",
    }
    envelope = seal(body)
    Path(args.out).write_text(json.dumps(envelope, indent=2, sort_keys=True))

    n = pytest_res["passed"]
    print(
        f"\nVERDICT: {'PASS' if gates_ok else 'FAIL'} "
        f"({n} tests, {adv['passed']}/{adv['total']} adversarial, "
        f"verifiers ok={val['ok'] and discovery['ok']})"
    )
    print(f"sealed: {args.out}  report_hash={envelope['report_hash'][:16]}…")
    if body["git"]["dirty"]:
        print(
            "note: working tree is dirty; the commit hash does not fully pin what ran"
        )
    return 0 if gates_ok else 1


if __name__ == "__main__":
    sys.exit(main())
