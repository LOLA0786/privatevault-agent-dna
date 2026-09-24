"""Architecture is enforced, not described.

The map in docs/architecture/ is generated from imports by
tools/archmap.py. These tests fail when the map is stale or when the code
breaks a boundary the map currently shows holding.
"""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("archmap", ROOT / "tools" / "archmap.py")
archmap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(archmap)

# Deprecated shim; delete the shim and this allowance together.
ALLOWED_CORE_TO_EXPERIMENTAL = [
    "agent_dna.adapters_policy.git_bundle -> experimental.adapters.git_bundle (top)",
]
RUST_BRIDGE_IN_CORE = ["agent_dna.signer_bridge"]

GRAPH = archmap.build()


def test_committed_map_is_current():
    assert archmap.main(["--check"]) == 0, "run: python tools/archmap.py"


def test_no_import_time_cycles():
    assert GRAPH["cycles"] == []


def test_core_imports_experimental_only_via_known_shim():
    assert GRAPH["core_to_experimental"] == ALLOWED_CORE_TO_EXPERIMENTAL


def test_only_signer_bridge_crosses_into_rust():
    in_core = [m for m in GRAPH["rust_bridge"] if m.split(".")[0] in archmap.CORE_ROOTS]
    assert in_core == RUST_BRIDGE_IN_CORE


def _tree(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return archmap.build(tmp_path)


def test_negative_control_detector_finds_a_planted_cycle(tmp_path):
    g = _tree(
        tmp_path,
        {
            "agent_dna/__init__.py": "",
            "agent_dna/a.py": "from . import b\n",
            "agent_dna/b.py": "from . import a\n",
        },
    )
    assert g["cycles"] == [["agent_dna.a", "agent_dna.b"]]


def test_negative_control_detector_finds_core_to_experimental(tmp_path):
    g = _tree(
        tmp_path,
        {
            "agent_dna/__init__.py": "",
            "agent_dna/x.py": "import experimental.y\n",
            "experimental/__init__.py": "",
            "experimental/y.py": "",
        },
    )
    assert g["core_to_experimental"] == ["agent_dna.x -> experimental.y (top)"]


def test_negative_control_lazy_import_is_not_a_cycle(tmp_path):
    g = _tree(
        tmp_path,
        {
            "agent_dna/__init__.py": "",
            "agent_dna/a.py": "from . import b\n",
            "agent_dna/b.py": "def f():\n    from . import a\n",
        },
    )
    assert g["cycles"] == []
    assert ["agent_dna.b", "agent_dna.a", "lazy"] in g["edges"]


def test_map_ignores_edits_that_do_not_change_imports(tmp_path):
    files = {
        "agent_dna/__init__.py": "",
        "agent_dna/a.py": "from . import b\n",
        "agent_dna/b.py": "",
    }
    before = _tree(tmp_path, files)
    (tmp_path / "agent_dna/b.py").write_text(
        "# comment\nX = 1\n\ndef f():\n    return X\n"
    )
    after = archmap.build(tmp_path)
    assert archmap.render_md(before) == archmap.render_md(after)
    assert archmap.render_json(before) == archmap.render_json(after)


def test_map_changes_when_an_import_is_added(tmp_path):
    files = {"agent_dna/__init__.py": "", "agent_dna/a.py": "", "agent_dna/b.py": ""}
    before = _tree(tmp_path, files)
    (tmp_path / "agent_dna/a.py").write_text("from . import b\n")
    after = archmap.build(tmp_path)
    assert archmap.render_json(before) != archmap.render_json(after)
