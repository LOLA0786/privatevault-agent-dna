"""Keep the gate's revocation list fresh, and fail closed when it cannot.

The gate holds a ``RevocationListCache`` (``config.build_gate``). It refuses
every permit with 503 ``RECEIVER_REVOCATION_LIST_STALE`` until a signed list
from the PrivateVault API is installed, and again once that list passes its
``next_update``. This module fetches ``GET /v1/revocations`` every
``PV_REVOCATION_REFRESH_SECONDS``; a failed fetch changes nothing, so an
unreachable API ends in refusals, never in admitting a revoked permit.

The list is verified against the gate's pinned trust bundle before it is
installed, and an older list never replaces a newer one. The API key is read
from its file on every fetch (so it can be rotated) and never logged.
"""

from __future__ import annotations

import json
import ssl
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any

from agent_dna.revocation_list import RevocationListCache, RevocationListError

FETCH_TIMEOUT_SECONDS = 5.0


class RevocationRefresher:
    def __init__(
        self,
        cache: RevocationListCache,
        *,
        url: str,
        api_key_file: Path,
        ca_file: Path | None = None,
        interval_seconds: int = 10,
    ) -> None:
        self.cache = cache
        self.url = url
        self.api_key_file = api_key_file
        self.ca_file = ca_file
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    def _context(self) -> ssl.SSLContext | None:
        if not self.url.lower().startswith("https://"):
            return None
        return ssl.create_default_context(
            cafile=str(self.ca_file) if self.ca_file is not None else None
        )

    def refresh_once(self) -> bool:
        """Fetch, verify and install one list. False (and nothing changed)
        on any failure."""
        try:
            api_key = self.api_key_file.read_text(encoding="utf-8").strip()
            request = urllib.request.Request(self.url, headers={"X-API-Key": api_key})
            with urllib.request.urlopen(  # noqa: S310 - scheme checked in config
                request, timeout=FETCH_TIMEOUT_SECONDS, context=self._context()
            ) as response:
                document: Any = json.loads(response.read().decode("utf-8"))
            self.cache.update(document)
        except (OSError, ValueError, RevocationListError) as exc:
            # OSError covers URLError, HTTPError, timeouts and TLS failures.
            self.last_error = f"{type(exc).__name__}: {exc}"
            print(
                f"revocation list refresh failed ({self.last_error}); the gate "
                "refuses all permits once its current list expires",
                file=sys.stderr,
                flush=True,
            )
            return False
        self.last_error = None
        return True

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.refresh_once()

    def start(self) -> None:
        """Fetch now, then keep fetching in a daemon thread."""
        if self._thread is not None:
            return
        self.refresh_once()
        self._thread = threading.Thread(
            target=self._run, name="pv-revocation-refresh", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=FETCH_TIMEOUT_SECONDS + 1)
            self._thread = None


def start_refresher(gate: Any, settings: Any) -> RevocationRefresher | None:
    """Start keeping ``gate``'s list fresh, if the settings name a source."""
    if settings.revocation_url is None or gate.revocations is None:
        return None
    refresher = RevocationRefresher(
        gate.revocations,
        url=settings.revocation_url,
        api_key_file=settings.revocation_api_key_file,
        ca_file=settings.revocation_ca_file,
        interval_seconds=settings.revocation_refresh_seconds,
    )
    refresher.start()
    return refresher
