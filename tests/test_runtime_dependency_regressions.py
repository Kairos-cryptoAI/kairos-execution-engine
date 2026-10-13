"""Small offline guards for the HTTP dependency's reference-leak fix."""

from __future__ import annotations

import gc
import sys
from importlib.metadata import version

import pytest
from multidict import CIMultiDict
from packaging.version import Version


def test_multidict_excludes_known_vulnerable_versions() -> None:
    assert Version(version("multidict")) >= Version("6.9.1")


@pytest.mark.parametrize("operation", ["reflected_union", "subtract"])
def test_items_set_operations_release_operand_references(operation: str) -> None:
    marker = object()
    operand = [(f"temporary-header-{index}", marker) for index in range(64)]
    view = CIMultiDict({"retained-header": "synthetic"}).items()
    gc.collect()
    expected = sys.getrefcount(marker)
    if operation == "reflected_union":
        computed = operand | view
        assert len(computed) == 65
    else:
        computed = view - operand
        assert len(computed) == 1
    del computed
    gc.collect()
    assert sys.getrefcount(marker) == expected
