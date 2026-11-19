"""Synthetic local role-password file regressions; no database or account calls."""

from __future__ import annotations

import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from kairos_execution import protected_files
from kairos_execution.local_custody import _regular_protected_file
from kairos_execution.production_provisioning import (
    ROLE_NAMES,
    ProvisionedDatabaseV1,
    ProvisioningError,
    _write_secret,
)


def _manifest(password_file: Path) -> ProvisionedDatabaseV1:
    return ProvisionedDatabaseV1(
        version="kairos.production-database.v1",
        host="127.0.0.1",
        port=5432,
        database="synthetic_database",
        database_uuid="synthetic-uuid",
        policy_namespace="synthetic",
        roles={role: f"synthetic_{role}" for role in ROLE_NAMES},
        password_files={role: str(password_file) for role in ROLE_NAMES},
        context={},
    )


def _grant_public_read(path: Path, *, directory: bool = False) -> None:
    if os.name == "nt":
        grant = "*S-1-1-0:(OI)(CI)(R)" if directory else "*S-1-1-0:(R)"
        subprocess.run(["icacls", str(path), "/grant", grant], check=True, capture_output=True, timeout=5)
    else:
        path.chmod(0o755 if directory else 0o644)


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_every_role_password_is_private_under_permissive_parent(tmp_path, role):
    _grant_public_read(tmp_path, directory=True)
    if os.name == "nt":
        before = subprocess.run(["icacls", str(tmp_path)], check=True, capture_output=True, timeout=5).stdout
    else:
        before = tmp_path.stat().st_mode
    password_file = tmp_path / f"synthetic.{role}.password"
    _write_secret(password_file, "synthetic-password")
    assert _regular_protected_file(password_file) == password_file.resolve()
    manifest = replace(_manifest(password_file), password_files={role: str(password_file)})
    assert manifest.dsn(role) == (
        f"postgresql://synthetic_{role}:synthetic-password@127.0.0.1:5432/synthetic_database"
    )
    if os.name == "nt":
        assert (
            subprocess.run(["icacls", str(tmp_path)], check=True, capture_output=True, timeout=5).stdout
            == before
        )
    else:
        assert tmp_path.stat().st_mode == before


def test_role_password_consumer_refuses_broadened_permissions(tmp_path):
    password_file = tmp_path / "runtime.password"
    _write_secret(password_file, "synthetic-password")
    _grant_public_read(password_file)
    with pytest.raises(ProvisioningError, match="private|protected"):
        _manifest(password_file).dsn("runtime")


def test_role_password_writer_rejects_link_parent(tmp_path):
    target = tmp_path / "actual"
    target.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("synthetic directory symlink creation is unavailable")
    with pytest.raises(ProvisioningError):
        _write_secret(alias / "owner.password", "synthetic-password")
    assert not (target / "owner.password").exists()


def test_role_password_writer_never_overwrites_existing_file(tmp_path):
    password_file = tmp_path / "owner.password"
    password_file.write_bytes(b"original-synthetic-value")
    with pytest.raises(ProvisioningError):
        _write_secret(password_file, "replacement-synthetic-value")
    assert password_file.read_bytes() == b"original-synthetic-value"


def test_acl_validation_failure_writes_no_secret_and_has_no_exception_context(tmp_path, monkeypatch):
    password_file = tmp_path / "owner.password"

    def reject(*args, **kwargs):
        raise PermissionError("synthetic-private-marker")

    monkeypatch.setattr(protected_files, "_validate_open_file", reject)
    with pytest.raises(ProvisioningError) as error:
        _write_secret(password_file, "synthetic-private-marker")
    assert password_file.read_bytes() == b""
    assert "synthetic-private-marker" not in str(error.value)
    assert error.value.__context__ is None


def test_consumer_checks_before_reading_bytes(tmp_path, monkeypatch):
    password_file = tmp_path / "runtime.password"
    _write_secret(password_file, "synthetic-password")
    _grant_public_read(password_file)

    def forbidden(*args, **kwargs):
        pytest.fail("reading an unprotected file must be refused before any bytes are read")

    monkeypatch.setattr(protected_files.os, "fdopen", forbidden)
    with pytest.raises(ProvisioningError) as error:
        _manifest(password_file).dsn("runtime")
    assert error.value.__context__ is None


def test_new_nested_directories_and_secret_are_private(tmp_path):
    password_file = tmp_path / "new" / "nested" / "owner.password"
    _write_secret(password_file, "synthetic-password")
    assert _regular_protected_file(password_file) == password_file.resolve()
    for directory in (password_file.parent, password_file.parent.parent):
        if os.name == "nt":
            protected_files._assert_private_windows_acl(directory)
        else:
            assert directory.stat().st_mode & 0o077 == 0


def test_consumer_rejects_file_with_hardlink_alias(tmp_path):
    password_file = tmp_path / "runtime.password"
    _write_secret(password_file, "synthetic-password")
    alias = tmp_path / "alias.password"
    try:
        os.link(password_file, alias)
    except OSError:
        pytest.skip("synthetic file hardlink creation is unavailable")
    with pytest.raises(ProvisioningError):
        _manifest(password_file).dsn("runtime")


def test_consumer_rejects_final_symlink_and_oversized_password(tmp_path):
    password_file = tmp_path / "runtime.password"
    _write_secret(password_file, "x" * 8193)
    with pytest.raises(ProvisioningError):
        _manifest(password_file).dsn("runtime")
    alias = tmp_path / "alias.password"
    try:
        alias.symlink_to(password_file)
    except OSError:
        pytest.skip("synthetic file symlink creation is unavailable")
    with pytest.raises(ProvisioningError):
        _manifest(alias).dsn("runtime")


@pytest.mark.skipif(os.name != "nt", reason="Windows deny-delete directory/file handles")
@pytest.mark.parametrize("writing", [False, True])
def test_windows_handles_pin_parent_and_file_through_validation_and_use(tmp_path, monkeypatch, writing):
    directory = tmp_path / "passwords"
    directory.mkdir()
    password_file = directory / "runtime.password"
    if not writing:
        _write_secret(password_file, "synthetic-password")
    validate = protected_files._validate_open_file
    calls = []

    def attempt_swap(path, descriptor, **kwargs):
        calls.append(path)
        with pytest.raises(OSError):
            directory.rename(tmp_path / "moved")
        with pytest.raises(OSError):
            path.unlink()
        validate(path, descriptor, **kwargs)

    monkeypatch.setattr(protected_files, "_validate_open_file", attempt_swap)
    if writing:
        _write_secret(password_file, "synthetic-password")
    else:
        assert "synthetic-password@" in _manifest(password_file).dsn("runtime")
    assert calls == [password_file, password_file]
    assert password_file.read_text() == "synthetic-password"


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point open and parent validation")
def test_parent_replaced_with_link_before_open_is_refused(tmp_path, monkeypatch):
    directory, moved = tmp_path / "passwords", tmp_path / "moved"
    directory.mkdir()
    opened = protected_files._Windows.open
    replaced = False

    def replace_before_open(self, path, **kwargs):
        nonlocal replaced
        if path == directory and not replaced:
            directory.rename(moved)
            try:
                directory.symlink_to(moved, target_is_directory=True)
            except OSError:
                moved.rename(directory)
                pytest.skip("synthetic directory symlink creation is unavailable")
            replaced = True
        return opened(self, path, **kwargs)

    monkeypatch.setattr(protected_files._Windows, "open", replace_before_open)
    with pytest.raises(ProvisioningError):
        _write_secret(directory / "owner.password", "synthetic-password")
    assert not (moved / "owner.password").exists()
