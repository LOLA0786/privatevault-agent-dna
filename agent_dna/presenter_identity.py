"""Presenter identity: who may present a permit to a receiver gate.

A permit binds the agent, the action and the exact bytes. On its own it
does not say who may carry it: a process that obtained agent A's permit and
A's bytes could present them once, before A did. Presenter binding closes
that: the agent's sidecar holds a TLS client certificate, the permit names
that certificate's key, and the receiver gate admits the permit only over
an mTLS connection authenticated by that key.

Identity format (ADR 0022): ``sha256:`` + hex SHA-256 of the certificate's
DER ``SubjectPublicKeyInfo``, the same value as RFC 7469's ``pin-sha256``
(there base64). It survives re-issuing a certificate for the same key and
changes when the key changes. Operators compute it with::

    openssl x509 -in client.pem -pubkey -noout \\
      | openssl pkey -pubin -outform der | sha256sum

Which presenters an agent may use is pinned by the operator in a presenter
bundle (``PV_PRESENTER_BUNDLE``), never taken from the caller alone:

    {"spec": "pv-presenter-bundle/0.1",
     "organisation_id": "org-demo",
     "presenters": {"payer-1": ["sha256:<64 hex>", "sha256:<next key>"]}}

More than one digest per agent allows a key rotation without downtime.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PRESENTER_BUNDLE_SPEC = "pv-presenter-bundle/0.1"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S
)
_SEQUENCE = 0x30
_CONTEXT_0 = 0xA0


class PresenterIdentityError(ValueError):
    """A certificate or presenter bundle could not be used."""


def _tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """(tag, content_start, end) of the DER element at ``offset``."""
    if offset + 2 > len(data):
        raise PresenterIdentityError("certificate DER is truncated")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise PresenterIdentityError("certificate DER uses an unsupported tag")
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise PresenterIdentityError("certificate DER has an invalid length")
        length = int.from_bytes(data[pos : pos + count], "big")
        if length < 0x80 or data[pos] == 0:
            raise PresenterIdentityError("certificate DER length is not minimal")
        pos += count
    end = pos + length
    if end > len(data):
        raise PresenterIdentityError("certificate DER is truncated")
    return tag, pos, end


def spki_from_certificate_der(der: bytes) -> bytes:
    """The DER SubjectPublicKeyInfo of an X.509 certificate."""
    der = bytes(der)
    tag, start, end = _tlv(der, 0)
    if tag != _SEQUENCE or end != len(der):
        raise PresenterIdentityError("not a single DER certificate")
    tag, tbs, tbs_end = _tlv(der, start)  # tbsCertificate
    if tag != _SEQUENCE:
        raise PresenterIdentityError("certificate has no tbsCertificate")
    pos = tbs
    tag, _, nxt = _tlv(der, pos)
    if tag == _CONTEXT_0:  # [0] EXPLICIT version
        pos = nxt
    # serialNumber, signature, issuer, validity, subject
    for _ in range(5):
        _, _, pos = _tlv(der, pos)
        if pos > tbs_end:
            raise PresenterIdentityError("certificate tbsCertificate is malformed")
    tag, _, spki_end = _tlv(der, pos)
    if tag != _SEQUENCE or spki_end > tbs_end:
        raise PresenterIdentityError("certificate has no subjectPublicKeyInfo")
    return der[pos:spki_end]


def presenter_identity_digest(certificate_der: bytes) -> str:
    """``sha256:<hex>`` of the certificate's SubjectPublicKeyInfo."""
    spki = spki_from_certificate_der(certificate_der)
    return "sha256:" + hashlib.sha256(spki).hexdigest()


def certificate_der_from_file(path: str | Path) -> bytes:
    """Read one certificate, PEM (first certificate) or DER."""
    raw = Path(path).read_bytes()
    match = _PEM_RE.search(raw)
    if match:
        try:
            return base64.b64decode(b"".join(match.group(1).split()), validate=True)
        except ValueError as exc:
            raise PresenterIdentityError(f"{path}: invalid PEM certificate") from exc
    return raw


def certificate_der_from_pem(pem: str | bytes) -> bytes:
    data = pem.encode("ascii") if isinstance(pem, str) else bytes(pem)
    match = _PEM_RE.search(data)
    if not match:
        raise PresenterIdentityError("no PEM certificate found")
    return base64.b64decode(b"".join(match.group(1).split()), validate=True)


@dataclass(frozen=True)
class PresenterBundle:
    """Operator-pinned presenters per agent, for one organisation."""

    organisation_id: str
    presenters: Mapping[str, frozenset[str]]
    digest: str

    def allowed(self, agent_id: str) -> frozenset[str]:
        return self.presenters.get(agent_id, frozenset())


def validate_presenter_bundle(document: Any) -> PresenterBundle:
    if not isinstance(document, Mapping):
        raise PresenterIdentityError("presenter bundle must be a JSON object")
    if set(document) != {"spec", "organisation_id", "presenters"}:
        raise PresenterIdentityError(
            "presenter bundle needs exactly spec, organisation_id, presenters"
        )
    if document["spec"] != PRESENTER_BUNDLE_SPEC:
        raise PresenterIdentityError(
            f"presenter bundle spec must be {PRESENTER_BUNDLE_SPEC}"
        )
    org = document["organisation_id"]
    if not isinstance(org, str) or not org:
        raise PresenterIdentityError("presenter bundle organisation_id is required")
    raw = document["presenters"]
    if not isinstance(raw, Mapping) or not raw:
        raise PresenterIdentityError("presenter bundle names no presenters")
    presenters: dict[str, frozenset[str]] = {}
    for agent, digests in raw.items():
        if not isinstance(agent, str) or not agent:
            raise PresenterIdentityError("presenter bundle agent ids must be strings")
        if (
            not isinstance(digests, list)
            or not digests
            or not all(isinstance(d, str) and _DIGEST_RE.fullmatch(d) for d in digests)
        ):
            raise PresenterIdentityError(
                f"presenters[{agent!r}] must be a non-empty list of sha256: digests"
            )
        if len(set(digests)) != len(digests):
            raise PresenterIdentityError(f"presenters[{agent!r}] repeats a digest")
        presenters[agent] = frozenset(digests)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return PresenterBundle(
        organisation_id=org,
        presenters=presenters,
        digest="sha256:" + hashlib.sha256(canonical).hexdigest(),
    )


def load_presenter_bundle(path: str | Path) -> PresenterBundle:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PresenterIdentityError(
            f"{path}: cannot read presenter bundle: {exc}"
        ) from exc
    return validate_presenter_bundle(document)
