"""Engineering Standard rule 1, machine-checked: nothing under
tests/connector/ may import mocking machinery. The enforcement
path is tested real or not at all."""

from pathlib import Path

FORBIDDEN = (
    "unittest.mock",
    "from mock import",
    "import mock",
    "mocker.",
    "MagicMock",
    "monkeypatch",
)


def test_no_mocks_on_enforcement_path():
    here = Path(__file__).parent
    offenders = []
    for f in here.glob("*.py"):
        if f.name == "test_standard_no_mocks.py":
            continue
        text = f.read_text()
        for token in FORBIDDEN:
            if token in text:
                offenders.append(f"{f.name}: {token}")
    assert not offenders, "mocking machinery on the enforcement path:\n" + "\n".join(
        offenders
    )
