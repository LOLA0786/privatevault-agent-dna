"""Environment-driven configuration for the receiver gate.

Every value is read from the environment and validated before the gate is
built. Anything missing or malformed raises ``ConfigError`` and the process
does not start. There are no defaults for identities or keys.

The trust bundle the gate pins is built deterministically from
``PV_ISSUER_ORGANISATION`` and ``PV_ISSUER_KEYS`` so that an issuer holding
the same two values computes the same bundle digest (a permit names the digest
of the bundle it was minted under). A pinned bundle file replaces this in
Phase 2 of the network kit.
"""

from __future__ import annotations

import base64
import binascii
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from agent_dna.authority_v01 import CANONICALIZATION, TRUST_SPEC, sha256_digest
from agent_dna.receiver.asgi import ReceiverGateProxy
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger

DEFAULT_BUNDLE_VERSION = 1
DEFAULT_PINNED_AT = "2026-01-01T00:00:00Z"
SIGNER_USAGE = "execution_authorization_signer"

REQUIRED_VARS = (
    "PV_RECEIVER_ID",
    "PV_RECEIVER_DESTINATIONS",
    "PV_ISSUER_ORGANISATION",
    "PV_ISSUER_KEYS",
    "PV_RECEIPT_KEY_FILE",
    "PV_RECEIPT_KEY_ID",
    "PV_UPSTREAM",
    "PV_LEDGER_PATH",
)


class ConfigError(ValueError):
    """A required setting is missing or malformed. The gate does not start."""


def _require(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _split_list(value: str, name: str) -> tuple[str, ...]:
    items = tuple(part.strip() for part in value.split(";") if part.strip())
    if not items:
        raise ConfigError(f"{name} must list at least one value")
    if len(set(items)) != len(items):
        raise ConfigError(f"{name} contains a duplicate")
    return items


def decode_public_key(text: str, name: str) -> str:
    """Return the base64 text if it is exactly one Ed25519 public key."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(f"{name}: public key is not valid base64") from exc
    if len(raw) != 32:
        raise ConfigError(f"{name}: public key must be 32 bytes")
    return base64.b64encode(raw).decode("ascii")


def parse_issuer_keys(
    value: str, name: str = "PV_ISSUER_KEYS"
) -> tuple[tuple[str, str], ...]:
    """``key_id=BASE64;key_id=BASE64`` to a tuple of (key_id, base64) pairs."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in _split_list(value, name):
        key_id, sep, public = item.partition("=")
        key_id = key_id.strip()
        if not sep or not key_id or not public.strip():
            raise ConfigError(f"{name}: expected key_id=BASE64, got {item!r}")
        if key_id in seen:
            raise ConfigError(f"{name}: duplicate key_id {key_id!r}")
        seen.add(key_id)
        pairs.append((key_id, decode_public_key(public.strip(), name)))
    return tuple(pairs)


def trust_bundle(
    organisation_id: str,
    issuer_keys: tuple[tuple[str, str], ...],
    *,
    bundle_version: int = DEFAULT_BUNDLE_VERSION,
    pinned_at: str = DEFAULT_PINNED_AT,
) -> dict[str, Any]:
    """Deterministic trust bundle: same inputs, same bytes, same digest.

    Keys are ordered by ``key_id`` so the order in ``PV_ISSUER_KEYS`` does not
    change the digest.
    """
    if not organisation_id:
        raise ConfigError("organisation_id is required")
    if not issuer_keys:
        raise ConfigError("at least one issuer key is required")
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": organisation_id,
        "bundle_version": bundle_version,
        "pinned_at": pinned_at,
        "keys": [
            {
                "key_id": key_id,
                "principal": f"execution-runtime@{organisation_id}",
                "algorithm": "ed25519",
                "public_key": public,
                "usages": [SIGNER_USAGE],
            }
            for key_id, public in sorted(issuer_keys)
        ],
    }


def load_signing_key(path: Path, name: str = "PV_RECEIPT_KEY_FILE") -> SigningKey:
    """Read a base64 Ed25519 seed from a file that only its owner can read."""
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ConfigError(f"{name}: cannot read {path}: {exc.strerror}") from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(
            f"{name}: {path} is readable by group or others; "
            "chmod 600 it (keygen.py writes it that way)"
        )
    text = path.read_text(encoding="ascii").strip()
    try:
        seed = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(f"{name}: key file is not valid base64") from exc
    if len(seed) != 32:
        raise ConfigError(f"{name}: key file must hold a 32-byte seed")
    return SigningKey(seed)


@dataclass(frozen=True)
class GateSettings:
    receiver_id: str
    destinations: tuple[str, ...]
    organisation_id: str
    issuer_keys: tuple[tuple[str, str], ...]
    receipt_key_file: Path
    receipt_key_id: str
    upstream: str
    ledger_path: Path
    allow_http_upstream: bool = False
    unprotected_operations: tuple[str, ...] = ()
    bundle_version: int = DEFAULT_BUNDLE_VERSION
    pinned_at: str = DEFAULT_PINNED_AT
    max_body_bytes: int = 1_048_576

    @property
    def trust_bundle(self) -> dict[str, Any]:
        return trust_bundle(
            self.organisation_id,
            self.issuer_keys,
            bundle_version=self.bundle_version,
            pinned_at=self.pinned_at,
        )

    @property
    def trust_bundle_digest(self) -> str:
        return sha256_digest(self.trust_bundle)


def _flag(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "0").strip().lower()
    if value in {"0", "", "false", "no"}:
        return False
    if value in {"1", "true", "yes"}:
        return True
    raise ConfigError(f"{name} must be 0 or 1")


def _int(env: Mapping[str, str], name: str, default: int, minimum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


def settings_from_env(env: Mapping[str, str] | None = None) -> GateSettings:
    source = os.environ if env is None else env
    for name in REQUIRED_VARS:
        _require(source, name)
    return GateSettings(
        receiver_id=_require(source, "PV_RECEIVER_ID"),
        destinations=_split_list(
            _require(source, "PV_RECEIVER_DESTINATIONS"), "PV_RECEIVER_DESTINATIONS"
        ),
        organisation_id=_require(source, "PV_ISSUER_ORGANISATION"),
        issuer_keys=parse_issuer_keys(_require(source, "PV_ISSUER_KEYS")),
        receipt_key_file=Path(_require(source, "PV_RECEIPT_KEY_FILE")),
        receipt_key_id=_require(source, "PV_RECEIPT_KEY_ID"),
        upstream=_require(source, "PV_UPSTREAM"),
        ledger_path=Path(_require(source, "PV_LEDGER_PATH")),
        allow_http_upstream=_flag(source, "PV_ALLOW_HTTP_UPSTREAM"),
        unprotected_operations=tuple(
            part.strip()
            for part in source.get("PV_UNPROTECTED_OPERATIONS", "").split(";")
            if part.strip()
        ),
        bundle_version=_int(
            source, "PV_TRUST_BUNDLE_VERSION", DEFAULT_BUNDLE_VERSION, 1
        ),
        pinned_at=source.get("PV_TRUST_BUNDLE_PINNED_AT", "").strip()
        or DEFAULT_PINNED_AT,
        max_body_bytes=_int(source, "PV_MAX_BODY_BYTES", 1_048_576, 0),
    )


def build_gate(settings: GateSettings) -> ReceiverGate:
    """Build the gate. ``ReceiverGate`` itself refuses a receipt key that is
    also an issuer key, an unprotected write route, or a bundle without a
    signer key; those errors propagate unchanged."""
    signing_key = load_signing_key(settings.receipt_key_file)
    ledger = ReceiverLedger(settings.ledger_path)
    return ReceiverGate(
        receiver_id=settings.receiver_id,
        destinations=frozenset(settings.destinations),
        trust_bundle=settings.trust_bundle,
        ledger=ledger,
        receipt_signing_key=signing_key,
        receipt_key_id=settings.receipt_key_id,
        unprotected_operations=frozenset(settings.unprotected_operations),
        max_body_bytes=settings.max_body_bytes,
    )


def build_app(settings: GateSettings) -> ReceiverGateProxy:
    return ReceiverGateProxy(
        build_gate(settings),
        settings.upstream,
        allow_http_upstream=settings.allow_http_upstream,
    )


def describe(settings: GateSettings, gate: ReceiverGate) -> str:
    """Startup summary. Contains public material only."""
    lines = [
        "receiver gate",
        f"  receiver_id          {settings.receiver_id}",
        f"  destinations         {'; '.join(settings.destinations)}",
        f"  issuer organisation  {settings.organisation_id}",
        f"  issuer key ids       {', '.join(k for k, _ in settings.issuer_keys)}",
        f"  trust bundle digest  {settings.trust_bundle_digest}",
        f"  receipt key id       {settings.receipt_key_id}",
        f"  receipt public key   {gate.receipt_public_key}",
        f"  ledger               {settings.ledger_path}",
        f"  upstream             {settings.upstream}",
        f"  unprotected          {'; '.join(settings.unprotected_operations) or '(none)'}",
    ]
    return "\n".join(lines)
