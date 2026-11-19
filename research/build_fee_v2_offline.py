"""Build the pinned fee-V2 research source set without network or authority.

This is an offline verification fixture, not a production launcher. The
independent account, signing, venue and operator admission gates remain closed.
The output directory must not already exist and is never a project checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

LOCK_PATH = Path(__file__).with_name("fee-v2-source-lock.json")
_SOURCE_NAMES = ("execution", "core", "persistence")
_ENV_KEYS = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
)


def _safe_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    source = dict(os.environ if source is None else source)
    return {key: value for key, value in source.items() if key.upper() in _ENV_KEYS}


def _run(args: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if result.returncode:
        # Do not echo process output: it may contain local paths or inherited tool diagnostics.
        raise RuntimeError(f"{Path(args[0]).name} failed with exit code {result.returncode}")
    return result.stdout.strip()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _package_hash(root: Path) -> str:
    if not root.is_dir():
        raise ValueError("installed package directory is absent")
    digest = hashlib.sha256()
    files = sorted(
        (
            p
            for p in root.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix not in {".pyc", ".pyo"}
        ),
        key=lambda p: p.relative_to(root).as_posix(),
    )
    if not files:
        raise ValueError("installed package tree is empty")
    for path in files:
        if path.is_symlink():
            raise ValueError("symlinks cannot establish installed package identity")
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _assert_plain_path(path: Path) -> None:
    """Reject symlinks and Windows junctions/reparse points without following them."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("symlink or reparse point in verified package path")


def _assert_verified_package_tree(root: Path, *, boundary: Path) -> None:
    """Check the package and its output-local ancestors without loading Python code."""
    if not root.is_relative_to(boundary) or root == boundary:
        raise ValueError("package path must stay inside the build output")
    _assert_plain_path(boundary)
    current = boundary
    for part in root.relative_to(boundary).parts:
        current /= part
        _assert_plain_path(current)
    if not root.is_dir():
        raise ValueError("installed package directory is absent")
    for current_dir, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(current_dir)
        for name in (*directories, *filenames):
            path = base / name
            _assert_plain_path(path)
            if name.lower() == "__pycache__" or path.suffix.lower() in {".pyc", ".pyo"}:
                raise ValueError("bytecode cannot establish verified package identity")


def _site_packages(execution: Path, *, python_version: str) -> Path:
    """Use the explicit venv layout; do not import site or process .pth files."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", python_version):
        raise ValueError("invalid pinned Python version")
    major, minor, _patch = python_version.split(".")
    venv = execution / ".venv"
    return (
        venv / "Lib" / "site-packages"
        if os.name == "nt"
        else venv / "lib" / f"python{major}.{minor}" / "site-packages"
    )


def _extract_archive(data: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            if (
                not parts
                or member.name.startswith("/")
                or "\\" in member.name
                or any(part in {"..", "."} or ":" in part for part in parts)
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("unsafe source archive entry")
        archive.extractall(destination, filter="data" if sys.version_info >= (3, 12) else None)


def _verified_archive(repo: Path, spec: dict, trusted: str, *, env: dict[str, str]) -> bytes:
    if not repo.is_dir():
        raise ValueError("source repository is absent")
    commit = spec["commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source lock commit is invalid")
    identity = _run(["git", "-C", str(repo), "log", "-1", "--format=%H %GF %G?", commit], cwd=repo, env=env)
    if identity != f"{commit} {trusted} G":
        raise ValueError("source commit signature, fingerprint, or identity is not trusted")
    tree = _run(["git", "-C", str(repo), "rev-parse", commit + "^{tree}"], cwd=repo, env=env)
    if tree != spec["tree"]:
        raise ValueError("source tree differs from the research lock")
    result = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", commit],
        cwd=repo,
        env=env,
        capture_output=True,
        check=True,
    )
    if _sha256(result.stdout) != spec["archive_sha256"]:
        raise ValueError("source archive differs from the research lock")
    return result.stdout


def _file_url_path(value: str) -> Path:
    parts = urlsplit(value)
    if parts.scheme != "file" or parts.netloc not in {"", "localhost"}:
        raise ValueError("installed package is not the local pinned source")
    return Path(url2pathname(unquote(parts.path))).resolve()


def _node_status(node: str | None, *, cwd: Path, env: dict[str, str], required: int) -> dict:
    if not node:
        return {"status": "MISSING", "required_major": required}
    try:
        version = _run([node, "--version"], cwd=cwd, env=env)
    except (OSError, RuntimeError):
        return {"status": "UNAVAILABLE", "required_major": required}
    match = re.fullmatch(r"v(\d+)\.\d+\.\d+", version)
    return {
        "status": "SUPPORTED" if match and int(match.group(1)) == required else "UNSUPPORTED",
        "required_major": required,
        "observed_version": version,
    }


def build(
    *, destination: Path, runtime_root: Path, repositories: dict[str, Path], uv: str, node: str | None
) -> dict:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    if lock.get("schema") != "kairos.fee-v2.offline-research-source-lock.v1":
        raise ValueError("unsupported research source lock")
    if set(repositories) != set(_SOURCE_NAMES):
        raise ValueError("all three exact repositories are required")
    destination = destination.resolve()
    runtime_root = runtime_root.resolve()
    if not destination.is_relative_to(runtime_root) or destination == runtime_root:
        raise ValueError("destination must be inside the designated runtime root")
    if any(destination.is_relative_to(repo.resolve()) for repo in repositories.values()):
        raise ValueError("destination cannot be inside a source checkout")
    if destination.exists() or not destination.parent.is_dir():
        raise ValueError("destination must be new and its parent must exist")
    env = _safe_environment()
    # Discourage incidental Python caches during local package builds. This is
    # not a sandbox; verification below rejects any cache that still appears.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if _run([uv, "--version"], cwd=destination.parent, env=env).split()[:2] != ["uv", lock["uv_version"]]:
        raise ValueError("unexpected uv version")
    # Capture and verify all signed snapshots before making output or installing anything.
    archives = {
        name: _verified_archive(
            repositories[name], lock["sources"][name], lock["trusted_signing_fingerprint"], env=env
        )
        for name in _SOURCE_NAMES
    }
    destination.mkdir()
    for name, archive in archives.items():
        target = destination / name
        target.mkdir()
        _extract_archive(archive, target)
    execution = destination / "execution"
    execution_package = execution / "kairos_execution"
    _assert_verified_package_tree(execution_package, boundary=destination)
    original_execution_hash = _package_hash(execution_package)
    if _sha256((execution / "uv.lock").read_bytes()) != lock["base_uv_lock_sha256"]:
        raise ValueError("base Python lock differs")
    if (
        _sha256((execution / "kairos_execution/evedex_sidecar/package-lock.json").read_bytes())
        != lock["sidecar_package_lock_sha256"]
    ):
        raise ValueError("sidecar lock differs")
    _run(
        [uv, "sync", "--offline", "--locked", "--all-extras", "--group", "dev", "--python", "3.11"],
        cwd=execution,
        env=env,
    )
    python = execution / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if _run([str(python), "--version"], cwd=destination, env=env) != f"Python {lock['python_version']}":
        raise ValueError("unexpected Python version")
    # --no-config is essential: the baseline project overrides would otherwise
    # silently reinstall old Core/Persistence Git commits, despite local paths.
    _run(
        [
            uv,
            "pip",
            "install",
            "--no-config",
            "--python",
            str(python),
            "--offline",
            "--no-deps",
            "--reinstall",
            str(destination / "core"),
            str(destination / "persistence"),
        ],
        cwd=destination,
        env=env,
    )
    _run([uv, "pip", "check", "--no-config", "--python", str(python)], cwd=destination, env=env)
    site_packages = _site_packages(execution, python_version=lock["python_version"])
    trees = {
        "execution": execution_package,
        "core": site_packages / "kairos_core",
        "persistence": site_packages / "kairos_persistence",
    }

    def verify_trees() -> dict[str, str]:
        actual = {}
        for name, tree_path in trees.items():
            _assert_verified_package_tree(tree_path, boundary=destination)
            actual[name] = _package_hash(tree_path)
            expected = (
                original_execution_hash
                if name == "execution"
                else lock["sources"][name]["package_tree_sha256"]
            )
            if actual[name] != expected:
                raise ValueError(f"{name} package tree differs from the pinned source")
        return actual

    # Importing can execute code. Check paths, caches and source hashes BEFORE
    # the first package probe, not merely after it.
    verified_hashes = verify_trees()
    probe = (
        "import sys;sys.path[:0]=" + repr([str(execution), str(site_packages)]) + ";"
        "import importlib.metadata as m,json,kairos_core,kairos_persistence,kairos_execution;"
        "from kairos_core.contracts import TradeExecutionEventV2;"
        "print(json.dumps({'core_path':kairos_core.__file__,'persistence_path':kairos_persistence.__file__,"
        "'execution_path':kairos_execution.__file__,'core_origin':m.distribution('kairos-core').read_text('direct_url.json'),"
        "'persistence_origin':m.distribution('kairos-persistence').read_text('direct_url.json')}))"
    )
    # -S prevents site/.pth execution; -I ignores ambient Python settings;
    # -B prevents new bytecode. Pre-existing package bytecode was refused above.
    observed = json.loads(_run([str(python), "-I", "-S", "-B", "-c", probe], cwd=destination, env=env))
    if Path(observed["execution_path"]).resolve() != (execution / "kairos_execution/__init__.py").resolve():
        raise ValueError("execution was imported from a different source")
    packages = {}
    for name in ("core", "persistence"):
        installed = Path(observed[name + "_path"]).resolve().parent
        if installed != trees[name].resolve():
            raise ValueError("package was imported from a different installed tree")
        origin = json.loads(observed[name + "_origin"])
        if _file_url_path(origin["url"]) != (destination / name).resolve():
            raise ValueError("installed package origin differs from the pinned local snapshot")
        packages[name] = {"installed_tree_sha256": verified_hashes[name], "origin": "verified_local_snapshot"}
    if verify_trees() != verified_hashes:
        raise ValueError("package tree changed during its probe")
    receipt = {
        "schema": "kairos.fee-v2.offline-research-build.v1",
        "source_lock_sha256": _sha256(LOCK_PATH.read_bytes()),
        "source_commits": {name: lock["sources"][name]["commit"] for name in _SOURCE_NAMES},
        "base_uv_lock_sha256": lock["base_uv_lock_sha256"],
        "installed_packages": packages,
        "execution_package_sha256": verified_hashes["execution"],
        "python_version": lock["python_version"],
        "uv_version": lock["uv_version"],
        "host_node": _node_status(node, cwd=destination, env=env, required=lock["required_node_major"]),
        "network_operations_requested": False,
        "network_isolation_enforced": False,
        "trading_authority": False,
        "live_ready": False,
        "scope": "offline source installation only; no venue/account/source qualification or sidecar startup",
    }
    (destination / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runtime-root", default=Path("D:/Kairos/runtime"), type=Path)
    parser.add_argument("--execution-repo", required=True, type=Path)
    parser.add_argument("--core-repo", required=True, type=Path)
    parser.add_argument("--persistence-repo", required=True, type=Path)
    parser.add_argument("--uv", default=shutil.which("uv"))
    parser.add_argument("--node", default=shutil.which("node"))
    args = parser.parse_args()
    if not args.uv:
        parser.error("uv 0.12.3 must already be installed")
    receipt = build(
        destination=args.output.resolve(),
        runtime_root=args.runtime_root.resolve(),
        repositories={name: getattr(args, name + "_repo").resolve() for name in _SOURCE_NAMES},
        uv=args.uv,
        node=args.node,
    )
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
