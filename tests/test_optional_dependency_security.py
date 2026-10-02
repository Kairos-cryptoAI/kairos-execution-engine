"""Keep the optional CCXT dependency graph outside affected urllib3 releases."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_urllib3_security_floor_is_scoped_to_the_ccxt_extra():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = project["project"]["optional-dependencies"]
    assert "urllib3>=2.8.0,<3" in extras["ccxt"]
    other_requirements = (
        project["project"]["dependencies"] + extras["evedex"] + project["dependency-groups"]["dev"]
    )
    assert not any(requirement.startswith("urllib3") for requirement in other_requirements)


def test_locked_optional_transport_and_upstream_pin_are_compatible():
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = {package["name"]: package for package in lock["package"]}
    urllib3_version = tuple(map(int, packages["urllib3"]["version"].split(".")))
    ccxt_version = tuple(map(int, packages["ccxt"]["version"].split(".")))
    assert (2, 8, 0) <= urllib3_version < (3, 0, 0)
    assert (4, 5, 85) <= ccxt_version < (5, 0, 0)
    assert {"name": "urllib3"} in packages["ccxt"]["dependencies"]
