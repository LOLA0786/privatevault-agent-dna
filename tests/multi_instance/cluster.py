"""Run several real PrivateVault API processes against one PostgreSQL.

This is the deployment shape a load balancer produces: separate server
processes (separate memory, separate connection pools) sharing one
database. The client below sends requests round-robin across them, which
is what a round-robin balancer does, so every scenario exercises state
crossing process boundaries.

Used by tests/multi_instance/test_two_processes.py, and runnable on its
own for a latency report:

    python -m tests.multi_instance.cluster --database-url postgresql://... \
        --instances 2 --requests 2000 --concurrency 32
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import CANONICALIZATION, TRUST_SPEC, encode_public_key
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.signer_python import generate_keypair
from tests.decide_binding import decide_json, dispatch_context_for, execution_action_for

REPO = Path(__file__).resolve().parents[2]
ORG = "org-multi"
PAY = "payments.transfer"
INITIATE, APPROVE = "payments.initiate_wire", "payments.approve_wire"
AGENTS = ("payer-1", "maker-1", "checker-1")
PAYERS = tuple(f"payer-{i}" for i in range(2, 34))  # load spread across agents
DESTINATION = "bank-sandbox.example"
OPERATION = "POST /v1/transfers"
PEER = b"tls-spki:bank-sandbox.example:v1"
Z = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64


def canon(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class Instance:
    port: int
    log: Path
    proc: subprocess.Popen[bytes] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@dataclass
class Cluster:
    """N API processes on one database. Use as a context manager."""

    database_url: str
    instances: int = 2
    budget: int = 100
    workdir: Path = field(
        default_factory=lambda: Path(tempfile.mkdtemp(prefix="pvmi-"))
    )
    keys: dict[str, str] = field(default_factory=dict)
    nodes: list[Instance] = field(default_factory=list)
    _rr: int = 0
    _rr_lock: threading.Lock = field(default_factory=threading.Lock)
    # One keep-alive client: a fresh httpx client per request costs more CPU
    # than the server spends deciding, and would measure the load generator.
    http: httpx.Client = field(
        default_factory=lambda: httpx.Client(
            timeout=30.0,
            limits=httpx.Limits(max_connections=256, max_keepalive_connections=256),
        )
    )

    # ---- configuration ----------------------------------------------------

    def _write_config(self) -> dict[str, str]:
        w = self.workdir
        entries = {}
        for name in AGENTS + PAYERS:
            k = generate_key(name, "full")
            self.keys[name] = k["key"]
            entries[k["hash"]] = {"name": name, "scope": "full"}
        auditor = generate_key("auditor-1", "audit")
        self.keys["auditor-1"] = auditor["key"]
        entries[auditor["hash"]] = {"name": "auditor-1", "scope": "audit"}
        (w / "keys.json").write_text(json.dumps(entries))
        grants = [
            {
                "agent_id": p,
                "capability": PAY,
                "budget": self.budget,
                "grant_id": f"grant-{p}",
                "granted_by": "ops",
            }
            for p in ("payer-1",) + PAYERS
        ] + [
            {"agent_id": a, "capability": c, "granted_by": "ops"}
            for a in ("maker-1", "checker-1")
            for c in (INITIATE, APPROVE)
        ]
        (w / "grants.json").write_text(json.dumps(grants))
        sk = SigningKey.generate()
        (w / "exec.key").write_bytes(bytes(sk))
        bundle = {
            "spec": TRUST_SPEC,
            "canonicalization": CANONICALIZATION,
            "organisation_id": ORG,
            "bundle_version": 1,
            "pinned_at": "2026-10-01T00:00:00Z",
            "keys": [
                {
                    "key_id": "k1",
                    "principal": f"execution-runtime@{ORG}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(sk),
                    "usages": ["execution_authorization_signer"],
                }
            ],
        }
        (w / "trust.json").write_text(json.dumps(bundle))
        receipt = generate_keypair()
        env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
        env.update(
            {
                "PV_DATABASE_URL": self.database_url,
                "PV_DB_PATH": str(w / "must-not-exist.db"),
                "PV_API_KEYS_FILE": str(w / "keys.json"),
                "PV_GRANTS_FILE": str(w / "grants.json"),
                "PV_BASELINE_CAPABILITIES": f"{PAY},{INITIATE},{APPROVE}",
                "PV_EXECUTION_SIGNER_KEY": str(w / "exec.key"),
                "PV_TRUST_BUNDLE": str(w / "trust.json"),
                "PV_RECEIPT_SIGNING_KEY": receipt["signing_key"],
                "PV_TRUSTED_PUBLIC_KEYS": receipt["public_key"],
                "PV_LINEAGE": "enforce",
                "PYTHONPATH": str(REPO),
            }
        )
        return env

    # ---- lifecycle --------------------------------------------------------

    def __enter__(self) -> Cluster:
        self._env = self._write_config()
        self.nodes = [
            Instance(_free_port(), self.workdir / f"api-{i}.log")
            for i in range(self.instances)
        ]
        for i in range(self.instances):
            self.start(i)
        return self

    def __exit__(self, *exc: object) -> None:
        for i in range(len(self.nodes)):
            self.kill(i, sig=signal.SIGTERM)
        self.http.close()

    def start(self, i: int, timeout: float = 30.0) -> None:
        node = self.nodes[i]
        node.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "api.server:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(node.port),
                "--log-level",
                "warning",
            ],
            cwd=REPO,
            env=self._env,
            stdout=node.log.open("ab"),
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + timeout
        last: str = "no response yet"
        while time.monotonic() < deadline:
            if node.proc.poll() is not None:
                raise RuntimeError(
                    f"instance {i} exited:\n{node.log.read_text()[-3000:]}"
                )
            try:
                status = httpx.get(f"{node.url}/ready", timeout=1).status_code
            except httpx.HTTPError as exc:  # not listening yet
                last = type(exc).__name__
            else:
                if status == 200:
                    return
                last = f"/ready {status}"
            time.sleep(0.2)
        raise RuntimeError(
            f"instance {i} not ready ({last}):\n{node.log.read_text()[-3000:]}"
        )

    def kill(self, i: int, sig: int = signal.SIGKILL) -> None:
        proc = self.nodes[i].proc
        if proc is not None and proc.poll() is None:
            proc.send_signal(sig)
            proc.wait(timeout=15)
        self.nodes[i].proc = None

    def alive(self) -> list[int]:
        return [i for i, n in enumerate(self.nodes) if n.proc is not None]

    # ---- client -----------------------------------------------------------

    def next_node(self) -> Instance:
        """Round-robin over live instances, as a balancer would."""
        with self._rr_lock:
            live = self.alive()
            node = self.nodes[live[self._rr % len(live)]]
            self._rr += 1
            return node

    def post(
        self,
        path: str,
        agent: str,
        body: dict[str, Any],
        node: Instance | None = None,
        timeout: float = 30.0,
    ) -> httpx.Response:
        target = node or self.next_node()
        return self.http.post(
            f"{target.url}{path}",
            headers={"X-API-Key": self.keys[agent]},
            json=body,
            timeout=timeout,
        )

    def get(
        self, path: str, agent: str = "auditor-1", node: Instance | None = None
    ) -> Any:
        target = node or self.next_node()
        r = self.http.get(
            f"{target.url}{path}", headers={"X-API-Key": self.keys[agent]}
        )
        r.raise_for_status()
        return r.json()

    # ---- request bodies ---------------------------------------------------

    @staticmethod
    def payment(
        amount: int, ref: str | None = None, agent: str = "payer-1"
    ) -> tuple[dict[str, Any], bytes]:
        args = {"amount": amount, "reference": ref or uuid.uuid4().hex}
        wire = canon(args)
        body = decide_json(
            agent,
            PAY,
            arguments=args,
            resource=DESTINATION,
            org=ORG,
            dispatch_context=dispatch_context_for(
                operation=OPERATION, destination=DESTINATION
            ),
            expected_wire_bytes_digest=sha256_bytes_digest(wire),
            expected_wire_bytes_length=len(wire),
        )
        return body, wire

    @staticmethod
    def authorize_body(
        record: dict[str, Any], args: dict[str, Any], wire: bytes
    ) -> dict[str, Any]:
        ctx = dispatch_context_for(operation=OPERATION, destination=DESTINATION)
        return {
            "request_id": f"req-{record['decision_id']}",
            "agent_id": "payer-1",
            "organisation_id": ORG,
            "decision_id": record["decision_id"],
            "action": execution_action_for(
                "payer-1", PAY, args, resource=DESTINATION, org=ORG
            ),
            "dispatch": {
                "transport": ctx["transport"],
                "destination": ctx["destination"],
                "operation": ctx["operation"],
                "wire_content_type": ctx["wire_content_type"],
                "wire_content_encoding": "identity",
                "tool_id": "payments.transfer.v1",
                "tool_schema_digest": Z,
                "tool_artifact_digest": ONE,
                "credential_audience": ctx["destination"],
                "idempotency_key_digest": Z,
                "retry_policy_digest": ONE,
                "serialization": ctx["serialization"],
            },
            "expected_wire_bytes_digest": sha256_bytes_digest(wire),
            "expected_wire_bytes_length": len(wire),
            "expected_peer_identity_digest": sha256_bytes_digest(PEER),
            "decision_receipt_digest": "sha256:" + record["record_hash"],
            "authority_receipt_digest": ONE,
            "state_snapshot_digest": Z,
            "policy_bundle_digest": ONE,
            "obligations_digest": Z,
        }

    @staticmethod
    def wire_decide(
        agent: str, capability: str, lineage: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body = decide_json(agent, capability, arguments={"amount": 1000}, org=ORG)
        if lineage:
            body["lineage"] = lineage
        return body


# ---- load report -------------------------------------------------------------


def verdict_of(r: httpx.Response) -> str:
    """The decide verdict (also carried as 200/202/403), else http_<status>."""
    try:
        body = r.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and body.get("decision") in (
        "allow",
        "block",
        "require_approval",
    ):
        return str(body["decision"])
    return f"http_{r.status_code}"


def _percentile(sorted_ms: list[float], p: float) -> float:
    if not sorted_ms:
        return float("nan")
    k = min(len(sorted_ms) - 1, max(0, round(p / 100 * (len(sorted_ms) - 1))))
    return sorted_ms[k]


def load(
    cluster: Cluster,
    requests: int,
    concurrency: int,
    amount: int = 1,
    agents: tuple[str, ...] = ("payer-1",),
) -> dict[str, Any]:
    """Round-robin decides; returns verdict counts and latency percentiles.

    One agent is serial by design (one hash chain, one grant budget);
    spreading ``agents`` measures how the cluster scales across agents.
    """
    latencies: list[float] = []
    verdicts: dict[str, int] = {}
    errors: list[str] = []
    lock = threading.Lock()

    def one(n: int) -> None:
        agent = agents[n % len(agents)]
        body, _wire = cluster.payment(amount, agent=agent)
        started = time.perf_counter()
        try:
            r = cluster.post("/v1/decide", agent, body)
            elapsed = (time.perf_counter() - started) * 1000
            key = verdict_of(r)
        except httpx.HTTPError as exc:
            elapsed, key = (time.perf_counter() - started) * 1000, "connection_error"
            with lock:
                errors.append(type(exc).__name__)
        with lock:
            latencies.append(elapsed)
            verdicts[key] = verdicts.get(key, 0) + 1

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(one, range(requests)))
    wall = time.perf_counter() - started
    ms = sorted(latencies)
    return {
        "instances": len(cluster.alive()),
        "requests": requests,
        "concurrency": concurrency,
        "verdicts": verdicts,
        "throughput_rps": round(requests / wall, 1),
        "p50_ms": round(_percentile(ms, 50), 1),
        "p95_ms": round(_percentile(ms, 95), 1),
        "p99_ms": round(_percentile(ms, 99), 1),
        "max_ms": round(ms[-1], 1) if ms else None,
        "mean_ms": round(statistics.fmean(ms), 1) if ms else None,
        "errors": sorted(set(errors)),
    }


def _iter_args(argv: list[str] | None) -> Iterator[argparse.Namespace]:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--database-url", required=True)
    p.add_argument("--instances", type=int, default=2)
    p.add_argument("--requests", type=int, default=2000)
    p.add_argument("--concurrency", type=int, default=32)
    yield p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = next(_iter_args(argv))
    with Cluster(args.database_url, instances=args.instances, budget=10**8) as cluster:
        load(cluster, 50, 8)  # warm-up: pools, imports, first-request paths
        print(json.dumps(load(cluster, args.requests, args.concurrency), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
