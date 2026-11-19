"""Exclusive private-file creation and reads bound to the validated open object.

Windows creates files/directories with a protected user/SYSTEM DACL, rather than
relying on POSIX mode bits. Ancestor directory handles deny rename/delete while
the final file is opened, validated and used. POSIX walks directories via pinned
descriptors with O_NOFOLLOW. Existing directories are never chmodded or re-ACLed.
"""

from __future__ import annotations

import ctypes
import os
import stat
from contextlib import ExitStack, contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .local_custody import LocalCustodyError, _assert_private_windows_acl

# POSIX-only names are absent from the Windows type stubs.
_posix_os: Any = os


class ProtectedFileError(PermissionError):
    """A local file cannot be safely created or read; contains no private data."""


def _absolute_path(path: Path) -> Path:
    if not isinstance(path, Path) or ".." in path.parts:
        raise ProtectedFileError("protected file path is invalid")
    path = Path(os.path.abspath(path))
    if os.name == "nt" and (
        str(path).startswith(("\\\\?\\", "\\\\.\\"))
        or any(":" in part or part.endswith((".", " ")) for part in path.parts[1:])
    ):
        raise ProtectedFileError("protected file path is invalid")
    return path


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _Windows:
    """Only the Win32 operations needed to create and pin local private files."""

    def __init__(self) -> None:
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        ptr = ctypes.c_void_p
        self.kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_SecurityAttributes),
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
        self.kernel.CreateDirectoryW.restype = wintypes.BOOL
        self.kernel.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ptr,
            wintypes.DWORD,
        ]
        self.kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.LocalFree.argtypes = [ptr]
        self.kernel.LocalFree.restype = ptr
        self.advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(ptr)]
        self.advapi.OpenProcessToken.restype = wintypes.BOOL
        self.advapi.GetTokenInformation.argtypes = [
            ptr,
            wintypes.DWORD,
            ptr,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.advapi.GetTokenInformation.restype = wintypes.BOOL
        self.advapi.ConvertSidToStringSidW.argtypes = [ptr, ctypes.POINTER(ptr)]
        self.advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ptr),
            ptr,
        ]
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

    @contextmanager
    def security(self, *, directory: bool):
        token, sid_text, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        try:
            if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
                raise ctypes.WinError(ctypes.get_last_error())
            buffer, needed = ctypes.create_string_buffer(1024), wintypes.DWORD()
            if not self.advapi.GetTokenInformation(token, 1, buffer, len(buffer), ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
                raise ctypes.WinError(ctypes.get_last_error())
            identity = ctypes.wstring_at(sid_text)
            inheritance = "OICI" if directory else ""
            sddl = f"O:{identity}D:P(A;{inheritance};FA;;;{identity})(A;{inheritance};FR;;;SY)"
            if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        finally:
            if descriptor:
                self.kernel.LocalFree(descriptor)
            if sid_text:
                self.kernel.LocalFree(sid_text)
            if token:
                self.kernel.CloseHandle(token)

    def attributes(self, handle: int) -> int:
        # FILE_ATTRIBUTE_TAG_INFO: attributes and reparse tag (FileAttributeTagInfo=9).
        info = (wintypes.DWORD * 2)()
        if not self.kernel.GetFileInformationByHandleEx(handle, 9, info, ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return info[0]

    def open(self, path: Path, *, directory: bool, write: bool = False, security: Any = None) -> int:
        access = 0x20000 | (0x80 if directory else (0x40000000 if write else 0x80000000))
        # Ancestors deny delete/rename; new files deny all sharing until close.
        sharing = 3 if directory else (0 if write else 1)
        flags = 0x00200000 | (0x02000000 if directory else 0x80)
        handle = self.kernel.CreateFileW(
            str(path),
            access,
            sharing,
            ctypes.byref(security) if security is not None else None,
            1 if write else 3,
            flags,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            attributes = self.attributes(handle)
            if attributes & 0x400 or bool(attributes & 0x10) != directory:
                raise ProtectedFileError("protected path contains a link or unexpected file type")
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        return handle

    def mkdir(self, path: Path, security: _SecurityAttributes) -> None:
        if not self.kernel.CreateDirectoryW(str(path), ctypes.byref(security)):
            raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def _windows_parent(path: Path, *, create: bool):
    api = _Windows()
    with ExitStack() as stack, api.security(directory=True) as security:
        current = Path(path.anchor)
        for part in (None, *path.parent.parts[1:]):
            if part is not None:
                current /= part
            created = False
            try:
                handle = api.open(current, directory=True)
            except OSError as exc:
                if not create or getattr(exc, "winerror", None) not in (2, 3):
                    raise
                api.mkdir(current, security)
                created = True
                handle = api.open(current, directory=True)
            stack.callback(api.kernel.CloseHandle, handle)
            if created:
                _assert_private_windows_acl(current, handle=handle)
        yield api


@contextmanager
def _posix_parent(path: Path, *, create: bool):
    flags = os.O_RDONLY | _posix_os.O_DIRECTORY | _posix_os.O_NOFOLLOW
    with ExitStack() as stack:
        descriptor = os.open(path.anchor, flags)
        stack.callback(os.close, descriptor)
        for part in path.parent.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
                info = os.fstat(child)
                if info.st_mode & 0o077 or info.st_uid != _posix_os.getuid():
                    os.close(child)
                    raise ProtectedFileError("new protected directory is not private") from None
            stack.callback(os.close, child)
            descriptor = child
        yield descriptor


def _validate_open_file(path: Path, descriptor: int, *, windows_handle: int | None = None) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ProtectedFileError("protected file must be a regular file without aliases")
    if windows_handle is not None:
        _assert_private_windows_acl(path, handle=windows_handle)
    elif info.st_mode & 0o077 or info.st_uid != _posix_os.getuid():
        raise ProtectedFileError("protected file permissions must be private")


@contextmanager
def _open_private(path: Path, *, write: bool):
    with ExitStack() as stack:
        handle = None
        if os.name == "nt":
            import msvcrt

            api = stack.enter_context(_windows_parent(path, create=write))
            security = stack.enter_context(api.security(directory=False)) if write else None
            handle = api.open(path, directory=False, write=write, security=security)
            try:
                descriptor = msvcrt.open_osfhandle(
                    handle, (os.O_WRONLY if write else os.O_RDONLY) | os.O_BINARY
                )
            except BaseException:
                api.kernel.CloseHandle(handle)
                raise
        else:
            parent = stack.enter_context(_posix_parent(path, create=write))
            flags = _posix_os.O_NOFOLLOW | _posix_os.O_NONBLOCK
            flags |= os.O_WRONLY | os.O_CREAT | os.O_EXCL if write else os.O_RDONLY
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent)
        stack.callback(os.close, descriptor)
        _validate_open_file(path, descriptor, windows_handle=handle)
        yield descriptor
        _validate_open_file(path, descriptor, windows_handle=handle)


def write_new_private_file(path: Path, content: bytes) -> None:
    """Write only a new private file; failure may leave a private partial file."""
    succeeded = False
    try:
        path = _absolute_path(path)
        with _open_private(path, write=True) as descriptor:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(descriptor)
        succeeded = True
    except (OSError, LocalCustodyError, ValueError):
        pass
    if not succeeded:
        raise ProtectedFileError("new protected file could not be created privately")


def read_private_file(path: Path, *, maximum_bytes: int = 8192) -> bytes:
    """Read the same regular private object whose owner/permissions were checked."""
    result = None
    try:
        path = _absolute_path(path)
        with _open_private(path, write=False) as descriptor:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(maximum_bytes + 1)
            if len(content) > maximum_bytes:
                raise ProtectedFileError("protected file exceeds its size bound")
        result = content
    except (OSError, LocalCustodyError, ValueError):
        pass
    if result is None:
        raise ProtectedFileError("protected file is unavailable or not private")
    return result


def create_private_directory(path: Path) -> None:
    """Create one new directory under existing non-link parents with private ACLs."""
    succeeded = False
    try:
        path = _absolute_path(path)
        if os.name == "nt":
            with _windows_parent(path, create=False) as api, api.security(directory=True) as security:
                api.mkdir(path, security)
                handle = api.open(path, directory=True)
                try:
                    _assert_private_windows_acl(path, handle=handle)
                finally:
                    api.kernel.CloseHandle(handle)
        else:
            with _posix_parent(path, create=False) as parent:
                os.mkdir(path.name, mode=0o700, dir_fd=parent)
                descriptor = os.open(
                    path.name,
                    os.O_RDONLY | _posix_os.O_DIRECTORY | _posix_os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                try:
                    info = os.fstat(descriptor)
                    if info.st_mode & 0o077 or info.st_uid != _posix_os.getuid():
                        raise ProtectedFileError("new protected directory is not private")
                finally:
                    os.close(descriptor)
        succeeded = True
    except (OSError, LocalCustodyError, ValueError):
        pass
    if not succeeded:
        raise ProtectedFileError("new protected directory could not be created privately")
