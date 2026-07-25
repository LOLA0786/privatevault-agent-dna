"""Published package, API and API-document versions must stay aligned."""

import tomllib
from pathlib import Path

from api.server import app


def test_product_versions_match():
    metadata = tomllib.loads(Path("pyproject.toml").read_text())
    package_version = metadata["project"]["version"]
    api_document = Path("docs/API-SURFACE.md").read_text()

    assert package_version == "0.3.0"
    assert app.version == package_version
    assert f"Version {package_version}." in api_document
