"""The legacy local custody import does not require the EVEDEX crypto extra."""

import subprocess
import sys


def test_local_custody_import_works_without_eth_utils():
    program = r"""
import builtins
original = builtins.__import__
def blocked(name, *args, **kwargs):
    if name == "eth_utils" or name.startswith("eth_utils."):
        raise ModuleNotFoundError("synthetic missing optional dependency")
    return original(name, *args, **kwargs)
builtins.__import__ = blocked
import kairos_execution.local_custody
"""
    result = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
