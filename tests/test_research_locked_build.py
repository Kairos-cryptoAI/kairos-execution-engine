"""Security and reproducibility checks for the offline research builder."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "research" / "build_fee_v2_offline.py"
spec = importlib.util.spec_from_file_location("research_fee_v2_offline", SCRIPT)
assert spec is not None and spec.loader is not None
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def test_build_environment_drops_credentials_and_python_path():
    env = builder._safe_environment(
        {
            "PATH": "path",
            "SYSTEMROOT": "system",
            "OPENAI_API_KEY": "secret",
            "EVEDEX_API_KEY": "secret",
            "PYTHONPATH": "untrusted",
            "UV_OVERRIDE": "untrusted",
        }
    )
    assert env == {"PATH": "path", "SYSTEMROOT": "system"}


def _tar(*entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        for name, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = 3
                archive.addfile(item, io.BytesIO(b"abc"))
            else:
                item.linkname = "../../other"
                archive.addfile(item)
    return data.getvalue()


def test_source_archive_extracts_plain_files(tmp_path):
    builder._extract_archive(_tar(("package/module.py", tarfile.REGTYPE)), tmp_path)
    assert (tmp_path / "package/module.py").read_bytes() == b"abc"


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../outside", tarfile.REGTYPE),
        ("bad", tarfile.SYMTYPE),
        ("C:/escape", tarfile.REGTYPE),
        ("x\\escape", tarfile.REGTYPE),
    ],
)
def test_source_archive_rejects_traversal_and_links(tmp_path, name, kind):
    with pytest.raises(ValueError, match="unsafe"):
        builder._extract_archive(_tar((name, kind)), tmp_path)


def test_installed_package_hash_changes_on_tampering_and_ignores_bytecode(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "main.py").write_text("value = 1\n", encoding="utf-8")
    original = builder._package_hash(package)
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "main.pyc").write_bytes(b"untrusted-cache")
    assert builder._package_hash(package) == original
    (package / "main.py").write_text("value = 2\n", encoding="utf-8")
    assert builder._package_hash(package) != original


def test_verification_refuses_preexisting_bytecode_and_cache_directories(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "main.py").write_text("value = 1\n", encoding="utf-8")
    builder._assert_verified_package_tree(package, boundary=tmp_path)
    (package / "stale.pyc").write_bytes(b"untrusted")
    with pytest.raises(ValueError, match="bytecode"):
        builder._assert_verified_package_tree(package, boundary=tmp_path)
    (package / "stale.pyc").unlink()
    (package / "__pycache__").mkdir()
    with pytest.raises(ValueError, match="bytecode"):
        builder._assert_verified_package_tree(package, boundary=tmp_path)


def test_verification_refuses_links_in_package_or_its_output_ancestors(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this test host")
    with pytest.raises(ValueError, match="symlink or reparse"):
        builder._assert_verified_package_tree(link, boundary=tmp_path)


def test_windows_reparse_attribute_is_rejected_even_without_symlink_mode(tmp_path, monkeypatch):
    candidate = tmp_path / "junction"
    candidate.mkdir()
    real_lstat = Path.lstat

    class ReparseStat:
        st_mode = real_lstat(candidate).st_mode
        st_file_attributes = 0x400

    def lstat_with_reparse(path):
        return ReparseStat() if path == candidate else real_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat_with_reparse)
    with pytest.raises(ValueError, match="symlink or reparse"):
        builder._assert_verified_package_tree(candidate, boundary=tmp_path)


def test_probe_interpreter_flags_do_not_execute_pth_files(tmp_path):
    marker = tmp_path / "pth-was-executed"
    (tmp_path / "attack.pth").write_text(
        f"import pathlib;pathlib.Path({str(marker)!r}).write_text('unexpected')\n", encoding="utf-8"
    )
    (tmp_path / "example.py").write_text("value = 42\n", encoding="utf-8")
    code = f"import sys;sys.path.insert(0,{str(tmp_path)!r});import example;assert example.value==42"
    subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code], check=True)
    assert not marker.exists()
    assert not (tmp_path / "__pycache__").exists()


def test_site_packages_layout_does_not_discover_ambient_paths(tmp_path):
    actual = builder._site_packages(tmp_path, python_version="3.11.15")
    assert actual.is_relative_to(tmp_path / ".venv")
    assert actual.name == "site-packages"
    with pytest.raises(ValueError, match="invalid pinned Python"):
        builder._site_packages(tmp_path, python_version="../3.11")


def test_commit_must_have_exact_trusted_signature_before_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(builder, "_run", lambda *args, **kwargs: "bad untrusted U")
    with pytest.raises(ValueError, match="signature"):
        builder._verified_archive(
            tmp_path,
            {"commit": "a" * 40},
            "b" * 40,
            env={},
        )


def test_node_runtime_major_is_checked_without_claiming_live(monkeypatch, tmp_path):
    monkeypatch.setattr(builder, "_run", lambda *args, **kwargs: "v24.20.0")
    assert builder._node_status("node", cwd=tmp_path, env={}, required=22)["status"] == "UNSUPPORTED"
    monkeypatch.setattr(builder, "_run", lambda *args, **kwargs: "v22.22.0")
    assert builder._node_status("node", cwd=tmp_path, env={}, required=22)["status"] == "SUPPORTED"


def test_existing_output_is_never_overwritten(tmp_path):
    destination = tmp_path / "existing"
    destination.mkdir()
    marker = destination / "keep"
    marker.write_text("preserved", encoding="utf-8")
    with pytest.raises(ValueError, match="must be new"):
        builder.build(
            destination=destination,
            runtime_root=tmp_path,
            repositories={name: tmp_path / "repo" for name in ("execution", "core", "persistence")},
            uv="uv",
            node=None,
        )
    assert marker.read_text(encoding="utf-8") == "preserved"


def test_output_cannot_escape_runtime_or_enter_checkout(tmp_path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    repo = runtime / "repo"
    repo.mkdir()
    repositories = {name: repo for name in ("execution", "core", "persistence")}
    with pytest.raises(ValueError, match="designated runtime"):
        builder.build(
            destination=tmp_path / "outside",
            runtime_root=runtime,
            repositories=repositories,
            uv="uv",
            node=None,
        )
    with pytest.raises(ValueError, match="inside a source checkout"):
        builder.build(
            destination=repo / "output", runtime_root=runtime, repositories=repositories, uv="uv", node=None
        )
