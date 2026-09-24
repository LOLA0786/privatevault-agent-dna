"""Core must import without experimental/ on the path (wheel/Docker parity).

Regression for: agent_dna/adapters_policy/__init__.py importing the
git_bundle shim, which imports experimental/, which neither the wheel
nor the Docker image ships.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

MODULES = [
    "agent_dna",
    "agent_dna.adapters_policy",
    "agent_dna.adapters_policy.opa",
    "agent_dna.composition",
    "api.server",
]


@pytest.mark.parametrize("module", MODULES)
def test_core_imports_without_experimental(tmp_path, module):
    ignore = shutil.ignore_patterns("__pycache__")
    shutil.copytree(ROOT / "agent_dna", tmp_path / "agent_dna", ignore=ignore)
    shutil.copytree(ROOT / "api", tmp_path / "api", ignore=ignore)
    code = f"""
import os, sys, importlib
root = {str(ROOT)!r}
sys.path[:] = [p for p in sys.path if os.path.abspath(p or '.') != root]
importlib.import_module({module!r})
import agent_dna
assert agent_dna.__file__.startswith({str(tmp_path)!r}), agent_dna.__file__
assert 'experimental' not in sys.modules, 'core pulled in experimental'
"""
    proc = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr[-2000:]
