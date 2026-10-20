"""Run a shell action on exactly the bytes the shell guard inspected.

Time of check vs time of use (external retest, 2026-10-16): the shell guard
reads a script or data file at decide time, but the agent runs the command
later. A file swapped in between runs unseen content. When the operator sets
``PV_SHELL_WORKDIR`` the guard pins every file it read as
``evidence.shell.pinned_files`` (real path, SHA-256 of the whole file, the
argv tokens that named it). The decision record seals that evidence, so the
pins are covered by the record hash and its signature.

This module is the executor side. ``run_pinned(arguments, decision)`` runs
nothing unless:

1. ``decision`` carries a decision record whose seal verifies;
2. that record is an ALLOW;
3. the record's ``arguments_digest`` is the digest of ``arguments`` -- the
   exact mapping the agent sent to ``/v1/decide`` -- so only the decided
   command can run;
4. every file the guard pinned is unchanged and every argv token that named
   it still resolves to it.

The pins are read from the verified record, never from a caller-supplied
evidence dict. It then copies each pinned file into a private 0700
directory (verifying the SHA-256 of the bytes it copies), points the argv at
the copies and runs. Any failure raises ``PinMismatch`` and nothing runs.

Limits, stated: the seal proves the record is intact, not who issued it --
the executor must take ``decision`` from its own ``/v1/decide`` response, not
from the model or another process. Only argv-form actions are rewritten (a
shell string is verified, not rewritten, so a race inside the verification
window remains); files a script opens or imports at run time are not
pinned; an executor that calls ``subprocess.run`` directly gets no
protection.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any

from agent_dna.decision_record import digest_arguments
from agent_dna.ledger_reads import LedgerIntegrityError, decision_from_dict
from agent_dna.shell_guard import SHELL_EVIDENCE_ITEM, shell_command

__all__ = [
    "PinMismatch",
    "allowed_shell_evidence",
    "shell_evidence_of",
    "verify_pins",
    "materialize",
    "run_pinned",
]


class PinMismatch(RuntimeError):  # noqa: N818 - a refusal, not a fault
    """A pinned file changed, moved or cannot be read. Do not execute."""


def shell_evidence_of(decision: Mapping[str, Any]) -> Mapping[str, Any]:
    """``evidence.shell`` from a /v1/decide response, a record dict, or the
    evidence dict itself."""
    if "record" in decision:
        decision = decision["record"]
    if "evidence" in decision:
        decision = decision["evidence"] or {}
    if isinstance(decision, list):  # sealed record: evidence items
        item = next(
            (
                i
                for i in decision
                if isinstance(i, Mapping) and i.get("name") == "shell_guard"
            ),
            None,
        )
        if item is None:
            raise PinMismatch("decision record carries no shell_guard evidence item")
        try:
            decision = json.loads(item["summary"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PinMismatch("shell_guard evidence item is not valid JSON") from exc
    shell = decision.get("shell") if "shell" in decision else decision
    if not isinstance(shell, Mapping) or "pinned_files" not in shell:
        raise PinMismatch("decision carries no shell evidence with pinned_files")
    return shell


def allowed_shell_evidence(
    arguments: Mapping[str, Any], decision: Mapping[str, Any]
) -> Mapping[str, Any]:
    """The pinned shell evidence of a sealed ALLOW for exactly
    ``arguments``. Raises PinMismatch otherwise."""
    record = decision.get("record") if "record" in decision else decision
    if not isinstance(record, Mapping):
        raise PinMismatch("no decision record")
    try:
        sealed = decision_from_dict(dict(record))
    except LedgerIntegrityError as exc:
        raise PinMismatch(f"decision record failed its seal check: {exc}") from exc
    if sealed.decision != "allow":
        raise PinMismatch(f"decision is {sealed.decision!r}, not an ALLOW")
    if sealed.arguments_digest != digest_arguments(dict(arguments)):
        raise PinMismatch("arguments differ from the ones this decision allowed")
    item = next(
        (
            i
            for i in sealed.evidence or []
            if isinstance(i, Mapping) and i.get("name") == SHELL_EVIDENCE_ITEM
        ),
        None,
    )
    if item is None:
        raise PinMismatch("decision record carries no shell_guard evidence item")
    try:
        shell = json.loads(item["summary"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PinMismatch("shell_guard evidence item is not valid JSON") from exc
    if not isinstance(shell, Mapping) or "pinned_files" not in shell:
        raise PinMismatch("shell_guard evidence carries no pinned_files")
    return shell


def _resolve(token: str, workdir: str) -> str:
    path = token if os.path.isabs(token) else os.path.join(workdir, token)
    return os.path.realpath(path)


def _read_verified(real: str, pin: Mapping[str, Any]) -> bytes:
    if not pin.get("hash_covers_file", False):
        raise PinMismatch(f"{real}: pin does not cover the whole file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(real, flags)
    except OSError as exc:
        raise PinMismatch(f"{real}: cannot open ({exc.strerror})") from exc
    with os.fdopen(fd, "rb") as fh:
        data = fh.read()
    if hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise PinMismatch(f"{real}: content changed since the decision")
    return data


def verify_pins(shell: Mapping[str, Any], *, workdir: str) -> None:
    """Raise PinMismatch unless every pinned file is unchanged and every
    token that named it still resolves to it."""
    for pin in shell.get("pinned_files") or []:
        real = pin["realpath"]
        for token in pin.get("tokens") or []:
            if _resolve(token, workdir) != real:
                raise PinMismatch(f"{token!r} now resolves to a different file")
        _read_verified(real, pin)


def _rewrite(arg: str, token: str, private: str) -> str:
    if arg == token:
        return private
    for sep in ("@", "="):
        if arg.endswith(sep + token):
            return arg[: len(arg) - len(token)] + private
    return arg


def materialize(
    argv: Sequence[str], shell: Mapping[str, Any], *, workdir: str, private_dir: str
) -> list[str]:
    """Copy pinned files (hash-verified) into private_dir; return argv with
    the tokens that named them pointing at the copies."""
    out = list(argv)
    for n, pin in enumerate(shell.get("pinned_files") or []):
        real = pin["realpath"]
        tokens = pin.get("tokens") or []
        for token in tokens:
            if _resolve(token, workdir) != real:
                raise PinMismatch(f"{token!r} now resolves to a different file")
        data = _read_verified(real, pin)
        dest = os.path.join(private_dir, f"{n}-{os.path.basename(real)}")
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        for token in tokens:
            out = [_rewrite(a, token, dest) for a in out]
    return out


def run_pinned(
    arguments: Mapping[str, Any],
    decision: Mapping[str, Any],
    *,
    workdir: str,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    """Run the command ``arguments`` describes, which ``decision`` (the
    caller's own ``/v1/decide`` response or its record) allowed, on the
    inspected bytes. Raises PinMismatch and runs nothing otherwise."""
    shell = allowed_shell_evidence(arguments, decision)
    try:
        form, command = shell_command(arguments)
    except ValueError as exc:
        raise PinMismatch(f"not a shell action: {exc}") from exc
    kwargs.setdefault("cwd", workdir)
    if form == "string":
        verify_pins(shell, workdir=workdir)
        return subprocess.run(command, shell=True, check=False, **kwargs)  # noqa: S602
    private = tempfile.mkdtemp(prefix="pv-pinned-")
    os.chmod(private, 0o700)
    try:
        final = materialize(command, shell, workdir=workdir, private_dir=private)
        return subprocess.run(final, check=False, **kwargs)  # noqa: S603
    finally:
        shutil.rmtree(private, ignore_errors=True)
