"""Environment-driven configuration for the receiver gate.

Every value is read from the environment and validated before the gate is
built. Anything missing or malformed raises ``ConfigError`` and the process
does not start. There are no defaults for identities or keys.

The trust bundle the gate pins comes from one of two places. By default it
is built deterministically from ``PV_ISSUER_ORGANISATION`` and
``PV_ISSUER_KEYS`` so that an issuer holding the same two values computes the
same bundle digest (a permit names the digest of the bundle it was minted
under). With ``PV_TRUST_BUNDLE_FILE`` set, the gate pins that file's bytes
instead: this is how a deployment shares one bundle (signer and witness keys)
between the PrivateVault API, the sidecar and the gate. When both are given,
the file wins and the issuer values must agree with it, or the gate does not
start.

Hardened by default (external review, 19 October 2026): the gate serves only
mutual TLS, requires every permit to name its presenter, and refuses permits
unless a fresh signed revocation list is installed. Each relaxation is an
explicit flag for a local demo: ``PV_RECEIVER_ALLOW_PLAINTEXT=1``,
``PV_RECEIVER_REQUIRE_PRESENTER=0``, ``PV_RECEIVER_ALLOW_NO_REVOCATION=1``.
The ledger is SQLite: run one receiver host.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    AuthorityFormatError,
    sha256_digest,
    validate_trust_bundle,
)
from agent_dna.key_custody import Ed25519Signer, SignerError, is_kms_ref, kms_signer
from agent_dna.receiver.asgi import ReceiverGateProxy
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.revocation_list import RevocationListCache

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
# Only needed when PV_TRUST_BUNDLE_FILE is not set (the bundle is derived).
DERIVED_BUNDLE_VARS = ("PV_ISSUER_ORGANISATION", "PV_ISSUER_KEYS")


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


def load_trust_bundle_file(
    path: Path,
    *,
    organisation_id: str = "",
    issuer_keys: tuple[tuple[str, str], ...] = (),
    name: str = "PV_TRUST_BUNDLE_FILE",
) -> dict[str, Any]:
    """Load a pinned trust bundle and refuse anything that is not one.

    The bundle must validate as ``pv-trust-bundle`` and carry at least one
    ``execution_authorization_signer`` key. If the issuer organisation or
    issuer keys are also configured, they must agree with the file: a bundle
    that names another organisation, or that lacks a configured issuer key
    with signer usage, is a configuration error, not a silent override.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"{name}: cannot read {path}: {exc.strerror}") from exc
    try:
        bundle = json.loads(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}: {path} is not valid JSON") from exc
    try:
        keys = validate_trust_bundle(bundle)
    except AuthorityFormatError as exc:
        raise ConfigError(f"{name}: {exc}") from exc
    if not any(SIGNER_USAGE in key["usages"] for key in keys.values()):
        raise ConfigError(f"{name}: bundle has no {SIGNER_USAGE} key")
    if organisation_id and bundle["organisation_id"] != organisation_id:
        raise ConfigError(
            f"{name}: bundle organisation {bundle['organisation_id']!r} differs "
            f"from PV_ISSUER_ORGANISATION {organisation_id!r}"
        )
    for key_id, public in issuer_keys:
        key = keys.get(key_id)
        if key is None or key["public_key"] != public:
            raise ConfigError(
                f"{name}: PV_ISSUER_KEYS names {key_id!r} but the bundle does "
                "not carry that key"
            )
        if SIGNER_USAGE not in key["usages"]:
            raise ConfigError(f"{name}: {key_id!r} lacks {SIGNER_USAGE} in the bundle")
    return bundle


def _key_ref(value: str) -> Path | str:
    return value if is_kms_ref(value) else Path(value)


def load_receipt_signer(
    ref: Path | str, name: str = "PV_RECEIPT_KEY_FILE"
) -> SigningKey | Ed25519Signer:
    """The receiver's receipt key: a local seed file, or a KMS key that the
    receiver operator controls (agent_dna.key_custody)."""
    if isinstance(ref, str) and is_kms_ref(ref):
        try:
            return kms_signer(ref)
        except SignerError as exc:
            raise ConfigError(f"{name}: {exc}") from exc
    return load_signing_key(Path(ref), name)


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
    try:
        text = path.read_text(encoding="ascii").strip()
    except PermissionError as exc:
        raise ConfigError(
            f"{name}: the gate user (uid {os.getuid()}) cannot read {path}. "
            "Inside the kit image the entrypoint copies the key for the gate "
            "user; outside it, make the file readable by the gate user only "
            "(mode 0400 or 0600)."
        ) from exc
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
    receipt_key_file: Path | str  # a seed file, or an awskms:/gcpkms: reference
    receipt_key_id: str
    upstream: str
    ledger_path: Path
    allow_http_upstream: bool = False
    unprotected_operations: tuple[str, ...] = ()
    bundle_version: int = DEFAULT_BUNDLE_VERSION
    pinned_at: str = DEFAULT_PINNED_AT
    max_body_bytes: int = 1_048_576
    trust_bundle_file: Path | None = None
    # mTLS (ADR 0022): served by network/receiver_kit/serve.py when set.
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    tls_client_ca_file: Path | None = None
    require_presenter: bool = False
    allow_plaintext: bool = False
    # Signed revocation list (pv-revocation-list/0.1) from the PrivateVault
    # API's GET /v1/revocations; None only with PV_RECEIVER_ALLOW_NO_REVOCATION.
    revocation_url: str | None = None
    revocation_api_key_file: Path | None = None
    revocation_ca_file: Path | None = None
    revocation_refresh_seconds: int = 10

    @property
    def mtls(self) -> bool:
        return self.tls_cert_file is not None

    @property
    def trust_bundle(self) -> dict[str, Any]:
        if self.trust_bundle_file is not None:
            return load_trust_bundle_file(
                self.trust_bundle_file,
                organisation_id=self.organisation_id,
                issuer_keys=self.issuer_keys,
            )
        return trust_bundle(
            self.organisation_id,
            self.issuer_keys,
            bundle_version=self.bundle_version,
            pinned_at=self.pinned_at,
        )

    @property
    def trust_bundle_source(self) -> str:
        if self.trust_bundle_file is not None:
            return f"pinned file {self.trust_bundle_file}"
        return "derived from PV_ISSUER_ORGANISATION and PV_ISSUER_KEYS"

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


def _int(
    env: Mapping[str, str],
    name: str,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be <= {maximum}")
    return value


_TLS_VARS = ("PV_RECEIVER_TLS_CERT", "PV_RECEIVER_TLS_KEY", "PV_RECEIVER_CLIENT_CA")


def _tls_settings(env: Mapping[str, str]) -> dict[str, Any]:
    """mTLS is all three files or none, and none needs an explicit
    PV_RECEIVER_ALLOW_PLAINTEXT=1. With mTLS a presenter is required unless
    PV_RECEIVER_REQUIRE_PRESENTER=0; presenters need mTLS."""
    values = {name: env.get(name, "").strip() for name in _TLS_VARS}
    given = [name for name, value in values.items() if value]
    if given and len(given) != len(_TLS_VARS):
        missing = sorted(set(_TLS_VARS) - set(given))
        raise ConfigError(
            f"mTLS needs all of {', '.join(_TLS_VARS)}; missing {missing}"
        )
    allow_plaintext = _flag(env, "PV_RECEIVER_ALLOW_PLAINTEXT")
    if not given and not allow_plaintext:
        raise ConfigError(
            "the gate serves mutual TLS only: set PV_RECEIVER_TLS_CERT, "
            "PV_RECEIVER_TLS_KEY and PV_RECEIVER_CLIENT_CA, or "
            "PV_RECEIVER_ALLOW_PLAINTEXT=1 for a local demo (presenters cannot "
            "be authenticated without client certificates)"
        )
    if given and allow_plaintext:
        raise ConfigError(
            "PV_RECEIVER_ALLOW_PLAINTEXT=1 contradicts the TLS settings; set one"
        )
    explicit = env.get("PV_RECEIVER_REQUIRE_PRESENTER", "").strip()
    require_presenter = (
        _flag(env, "PV_RECEIVER_REQUIRE_PRESENTER") if explicit else bool(given)
    )
    if require_presenter and not given:
        raise ConfigError(
            "PV_RECEIVER_REQUIRE_PRESENTER=1 needs mTLS (PV_RECEIVER_TLS_CERT, "
            "PV_RECEIVER_TLS_KEY, PV_RECEIVER_CLIENT_CA): without a client "
            "certificate no presenter can be authenticated"
        )
    for name in given:
        if not Path(values[name]).is_file():
            raise ConfigError(f"{name}: {values[name]} is not a readable file")
    return {
        "tls_cert_file": Path(values["PV_RECEIVER_TLS_CERT"]) if given else None,
        "tls_key_file": Path(values["PV_RECEIVER_TLS_KEY"]) if given else None,
        "tls_client_ca_file": Path(values["PV_RECEIVER_CLIENT_CA"]) if given else None,
        "require_presenter": require_presenter,
        "allow_plaintext": allow_plaintext,
    }


def _revocation_settings(env: Mapping[str, str]) -> dict[str, Any]:
    """Where the signed revocation list comes from. Required unless
    PV_RECEIVER_ALLOW_NO_REVOCATION=1: without it a revoked permit is
    admitted until it expires."""
    url = env.get("PV_REVOCATION_URL", "").strip()
    allow_none = _flag(env, "PV_RECEIVER_ALLOW_NO_REVOCATION")
    if not url:
        if not allow_none:
            raise ConfigError(
                "PV_REVOCATION_URL is required (the PrivateVault API's "
                "GET /v1/revocations, with PV_REVOCATION_API_KEY_FILE): without "
                "it a revoked permit is admitted until it expires. Set "
                "PV_RECEIVER_ALLOW_NO_REVOCATION=1 only for a local demo"
            )
        return {}
    if allow_none:
        raise ConfigError(
            "PV_RECEIVER_ALLOW_NO_REVOCATION=1 contradicts PV_REVOCATION_URL; set one"
        )
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in {"https", "http"}:
        raise ConfigError("PV_REVOCATION_URL must be an https:// URL")
    if scheme == "http" and not _flag(env, "PV_ALLOW_HTTP_REVOCATION"):
        raise ConfigError(
            "PV_REVOCATION_URL is http://: the API key would travel in clear. "
            "Use https, or PV_ALLOW_HTTP_REVOCATION=1 inside one host"
        )
    key_file = _require(env, "PV_REVOCATION_API_KEY_FILE")
    if not Path(key_file).is_file():
        raise ConfigError(f"PV_REVOCATION_API_KEY_FILE: {key_file} is not a file")
    ca_file = env.get("PV_REVOCATION_CA_FILE", "").strip()
    if ca_file and not Path(ca_file).is_file():
        raise ConfigError(f"PV_REVOCATION_CA_FILE: {ca_file} is not a file")
    return {
        "revocation_url": url,
        "revocation_api_key_file": Path(key_file),
        "revocation_ca_file": Path(ca_file) if ca_file else None,
        "revocation_refresh_seconds": _int(
            env, "PV_REVOCATION_REFRESH_SECONDS", 10, 1, 300
        ),
    }


def settings_from_env(env: Mapping[str, str] | None = None) -> GateSettings:
    source = os.environ if env is None else env
    bundle_file = source.get("PV_TRUST_BUNDLE_FILE", "").strip()
    for name in REQUIRED_VARS:
        if bundle_file and name in DERIVED_BUNDLE_VARS:
            continue
        _require(source, name)
    organisation_id = source.get("PV_ISSUER_ORGANISATION", "").strip()
    issuer_raw = source.get("PV_ISSUER_KEYS", "").strip()
    issuer_keys = parse_issuer_keys(issuer_raw) if issuer_raw else ()
    settings = GateSettings(
        receiver_id=_require(source, "PV_RECEIVER_ID"),
        destinations=_split_list(
            _require(source, "PV_RECEIVER_DESTINATIONS"), "PV_RECEIVER_DESTINATIONS"
        ),
        organisation_id=organisation_id,
        issuer_keys=issuer_keys,
        trust_bundle_file=Path(bundle_file) if bundle_file else None,
        receipt_key_file=_key_ref(_require(source, "PV_RECEIPT_KEY_FILE")),
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
        **_tls_settings(source),
        **_revocation_settings(source),
    )
    # Fail at configuration time, not at the first request: a pinned bundle
    # file that cannot be loaded or disagrees with the issuer values refuses
    # to start the gate.
    settings.trust_bundle
    return settings


def build_gate(settings: GateSettings) -> ReceiverGate:
    """Build the gate. ``ReceiverGate`` itself refuses a receipt key that is
    also an issuer key, an unprotected write route, or a bundle without a
    signer key; those errors propagate unchanged."""
    signing_key = load_receipt_signer(settings.receipt_key_file)
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
        require_presenter=settings.require_presenter,
        # Fail closed: with a list source configured, nothing is admitted
        # until a fresh signed list is installed (network/receiver_kit/
        # revocations.py keeps it fresh).
        revocations=(
            RevocationListCache(settings.trust_bundle)
            if settings.revocation_url is not None
            else None
        ),
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
        f"  issuer organisation  {settings.trust_bundle['organisation_id']}",
        f"  issuer key ids       {', '.join(k for k, _ in settings.issuer_keys) or '(from bundle)'}",
        f"  trust bundle         {settings.trust_bundle_source}",
        f"  trust bundle digest  {settings.trust_bundle_digest}",
        f"  receipt key id       {settings.receipt_key_id}",
        f"  receipt public key   {gate.receipt_public_key}",
        f"  ledger               {settings.ledger_path}",
        f"  upstream             {settings.upstream}",
        f"  unprotected          {'; '.join(settings.unprotected_operations) or '(none)'}",
        "  client TLS           "
        + (
            f"required, CA {settings.tls_client_ca_file}"
            if settings.mtls
            else "off: PLAINTEXT, local demo only (presenters cannot be authenticated)"
        ),
        f"  presenter            {'required' if settings.require_presenter else 'checked when a permit binds one'}",
        "  revocation list      "
        + (
            f"{settings.revocation_url}, refreshed every "
            f"{settings.revocation_refresh_seconds}s; refuses all permits while stale"
            if settings.revocation_url
            else "off (revoked permits are admitted until they expire)"
        ),
        "  ledger scope         this host only (SQLite): run one receiver host",
    ]
    return "\n".join(lines)
