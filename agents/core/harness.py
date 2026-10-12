"""In-process assembly of everything a persona needs, for demos and tests.

One ``Harness.start`` gives you: the PrivateVault API under a test client
with per-run keys and the persona's compiled policy and grants; the
receiver gate as a reverse proxy in front of the receiver kit's stub
upstream; the exact-byte sidecar with the demo transport; the approver kit
pinned as the API's approver bundle; and a gate, registry and receipt log
wired together. No sockets except the stub upstream on loopback, no real
keys, nothing persisted outside ``run_dir``.
"""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import CANONICALIZATION, TRUST_SPEC, encode_public_key
from agent_dna.connector.adapters.exact_byte_http import (
    ExactByteHttpDispatcher,
    WitnessSigner,
)
from agent_dna.receiver.asgi import ReceiverGateProxy
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.sqlite_store import SQLiteDecisionStore
from agents.core.approval import Approver, ApproverKit, ScriptedApprover
from agents.core.gate import PrivateVaultGate
from agents.core.model import Model
from agents.core.persona import Persona, load_persona
from agents.core.receipts import ReceiptLog
from agents.core.runner import AgentRunner, RunReport
from agents.core.tools import RiskClass, Tool, ToolRegistry
from agents.core.transport import AsgiSidecarTransport
from network.receiver_kit import export_receipts, upstream

ENV_KEYS = (
    "PV_DB_PATH",
    "PV_API_KEYS_FILE",
    "PV_EXECUTION_SIGNER_KEY",
    "PV_TRUST_BUNDLE",
    "PV_GRANTS_FILE",
    "PV_POLICY_FILE",
    "PV_APPROVER_TRUST_BUNDLE",
    "PV_BASELINE_CAPABILITIES",
    "PV_ALLOW_NO_AUTH",
)


def _execution_bundle(
    organisation_id: str, signer: SigningKey, witness: SigningKey
) -> dict:
    # The API signs with keys[0]; the sidecar needs the witness usages.
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": organisation_id,
        "bundle_version": 1,
        "pinned_at": "2026-01-01T00:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": f"execution-runtime@{organisation_id}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(signer),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-01",
                "principal": f"egress-witness@{organisation_id}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }


def _persona_tools(persona: Persona) -> list[Tool]:
    module = importlib.import_module(f"agents.personas.{persona.name}.tools")
    available = {tool.name: tool for tool in module.TOOLS}
    missing = [name for name in persona.tools if name not in available]
    if missing:
        raise ValueError(f"persona {persona.name} lists unknown tools {missing}")
    return [available[name] for name in persona.tools]


@dataclass
class Runtime:
    persona: Persona
    run_dir: Path
    client: Any
    api_key: str
    gate: PrivateVaultGate
    registry: ToolRegistry
    receiver: Any
    receiver_gate: ReceiverGate
    receiver_ledger_path: Path
    receiver_key_id: str
    upstream: upstream.UpstreamServer
    receipts: ReceiptLog
    approver_kit: ApproverKit
    approver: Approver
    execution_bundle: dict[str, Any]

    @property
    def receiver_public_key(self) -> str:
        return self.receiver_gate.receipt_public_key

    def run_agent(
        self, model: Model, goal: str = "process the next invoice"
    ) -> RunReport:
        return AgentRunner(
            model=model,
            registry=self.registry,
            gate=self.gate,
            approver=self.approver,
            receipts=self.receipts,
        ).run(goal)

    def export_receiver_receipts(self, out: Path) -> int:
        return export_receipts.export(self.receiver_ledger_path, Path(out))


class Harness:
    @staticmethod
    @contextmanager
    def start(
        persona_path: str | Path,
        run_dir: str | Path,
        *,
        approver: Approver | None = None,
        tools: list[Tool] | None = None,
    ) -> Iterator[Runtime]:
        persona = load_persona(persona_path)
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        compiled = persona.compile(run_dir)
        # ``tools`` overrides the persona's module (the proof demos use
        # variants of a persona's tools); names must still match the YAML.
        tools = _persona_tools(persona) if tools is None else list(tools)
        unknown = sorted(set(persona.tools) - {t.name for t in tools})
        if unknown:
            raise ValueError(f"persona {persona.name} lists unknown tools {unknown}")
        money = [t for t in tools if t.risk is RiskClass.MONEY]
        receivers = {t.receiver for t in money if t.receiver is not None}
        if len(receivers) > 1:
            raise ValueError("this harness wires exactly one receiver gate")
        receiver_spec = next(iter(receivers), None)

        # ---- per-run key material; nothing leaves run_dir ----
        operator = generate_key(persona.agent_id, "full")
        (run_dir / "keys.json").write_text(
            json.dumps({operator["hash"]: {"name": operator["name"], "scope": "full"}})
        )
        signer = SigningKey.generate()
        (run_dir / "exec.key").write_bytes(bytes(signer))
        witness = SigningKey.generate()
        bundle = _execution_bundle(persona.organisation_id, signer, witness)
        (run_dir / "trust.json").write_text(json.dumps(bundle))
        first = persona.approvers[0]
        kit = ApproverKit(
            persona.organisation_id,
            principal=first["principal"],
            key_id=first["key_id"],
        )
        (run_dir / "approvers.json").write_text(json.dumps(kit.bundle))

        saved = {k: os.environ.get(k) for k in ENV_KEYS}
        os.environ.update(
            {
                "PV_DB_PATH": str(run_dir / "pv.db"),
                "PV_API_KEYS_FILE": str(run_dir / "keys.json"),
                "PV_EXECUTION_SIGNER_KEY": str(run_dir / "exec.key"),
                "PV_TRUST_BUNDLE": str(run_dir / "trust.json"),
                "PV_GRANTS_FILE": str(compiled.grants_file),
                "PV_POLICY_FILE": str(compiled.policy_file),
                "PV_APPROVER_TRUST_BUNDLE": str(run_dir / "approvers.json"),
                # The drift baseline is operator configuration: the persona's
                # declared capabilities are its normal behaviour. Anything
                # else the model proposes is drift and escalates.
                "PV_BASELINE_CAPABILITIES": ",".join(
                    sorted({tool.capability for tool in tools})
                ),
            }
        )
        os.environ.pop("PV_ALLOW_NO_AUTH", None)

        from fastapi.testclient import TestClient

        import api.server as server

        server._pv_signer_cache.clear()
        importlib.reload(server)
        server._pv_signer_cache.clear()
        client = TestClient(server.app)
        client.__enter__()
        stub = None
        receiver_client = None
        try:
            # ---- receiver: gate as reverse proxy in front of the stub ----
            receipt_key = SigningKey.generate()
            ledger_path = run_dir / "receiver.db"
            receiver_gate = None
            dispatcher = None
            peer = b""
            if receiver_spec is not None:
                stub = upstream.start()
                receiver_gate = ReceiverGate(
                    receiver_id=receiver_spec.receiver_id,
                    destinations=frozenset({receiver_spec.destination}),
                    trust_bundle=bundle,
                    ledger=ReceiverLedger(ledger_path),
                    receipt_signing_key=receipt_key,
                    receipt_key_id="partner-receiver-01",
                )
                proxy = ReceiverGateProxy(
                    receiver_gate,
                    f"http://127.0.0.1:{stub.port}",
                    allow_http_upstream=True,
                )
                receiver_client = TestClient(proxy)
                receiver_client.__enter__()
                peer = f"tls-spki:{receiver_spec.receiver_id}".encode()
                dispatcher = ExactByteHttpDispatcher(
                    consume_ledger=SQLiteDecisionStore(str(run_dir / "agent-side.db")),
                    witness=WitnessSigner(
                        signing_key=witness,
                        signer_key_id="witness-01",
                        witness_component_id=f"agents-sidecar-{persona.name}",
                        closure_signer_key_id="witness-01",
                        closure_signing_key=witness,
                    ),
                    trust_bundle=bundle,
                    transport=AsgiSidecarTransport(
                        receiver_client, peer_label=peer.decode()
                    ),
                    attach_permit_header=True,
                )
            gate = PrivateVaultGate(
                client,
                operator["key"],
                agent_id=persona.agent_id,
                organisation_id=persona.organisation_id,
                peer_identity=peer,
                dispatcher=dispatcher,
            )
            yield Runtime(
                persona=persona,
                run_dir=run_dir,
                client=client,
                api_key=operator["key"],
                gate=gate,
                registry=ToolRegistry(tools),
                receiver=receiver_client,
                receiver_gate=receiver_gate,  # type: ignore[arg-type]
                receiver_ledger_path=ledger_path,
                receiver_key_id="partner-receiver-01",
                upstream=stub,  # type: ignore[arg-type]
                receipts=ReceiptLog(run_dir / "receipts.jsonl"),
                approver_kit=kit,
                approver=approver or ScriptedApprover(kit),
                execution_bundle=bundle,
            )
        finally:
            if receiver_client is not None:
                receiver_client.__exit__(None, None, None)
            if stub is not None:
                stub.shutdown()
            client.__exit__(None, None, None)
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
