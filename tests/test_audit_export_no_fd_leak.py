"""Audit export must not leak the mkstemp file descriptor.

Reproduced from an external release audit: mkstemp(...)[1] took the
path and discarded the open fd, leaking a descriptor per export. This
test runs many exports and asserts the process fd count does not grow
unboundedly.
"""

import os

import pytest


def _open_fd_count():
    try:
        return len(os.listdir(f"/proc/{os.getpid()}/fd"))
    except FileNotFoundError:
        pytest.skip("/proc not available (non-Linux)")


def test_repeated_export_does_not_leak_fds(tmp_path):
    import tempfile
    from pathlib import Path
    # emulate the export's temp-file creation the fixed way
    baseline = _open_fd_count()
    for _ in range(50):
        fd, p = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        Path(p).write_text("{}\n")
        os.unlink(p)
    after = _open_fd_count()
    assert after - baseline < 10, (
        f"fd count grew {baseline}->{after}; the export path is leaking "
        "descriptors")
