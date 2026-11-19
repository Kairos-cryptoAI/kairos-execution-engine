# Fee V2: isolated offline research build

This lock prepares a deterministic **research-only** source set from three
previously signed Git objects. It does not update `current-release.json`, the
normal dependency locks, a global environment, deployment, credentials, or
trading authority. It cannot qualify EVEDEX, an account, signing, or LIVE.

The baseline execution `uv.lock` pins old Core and Persistence commits. Running
`uv sync --locked` alone therefore does **not** install V2. The bootstrap first
uses that lock for third-party dependencies, then installs signed local Git
snapshots of the two V2 packages with `uv pip install --no-config --no-deps`.
`--no-config` is required: the execution project's override-dependencies would
otherwise silently restore the old Git versions. The complete installed Python
package trees are independently hashed against the lock.

Prerequisites: local Git objects with trusted GPG signatures, Python 3.11.15,
uv 0.12.3, and a populated offline uv cache for the pinned Python dependencies.
No credentials or network calls are required by this procedure. Offline mode is
requested explicitly; the script itself is not an OS network or filesystem
sandbox. Subprocess environments use an allow-list that excludes common credential
variables, `PYTHONPATH`, and uv overrides, but subprocesses retain ordinary user
profile, cache, filesystem access and a PATH. Package build hooks are not
prevented from reading accessible files or initiating their own network
operations. Treat source and tool executables as trusted.

Run from the execution checkout, selecting a **new** child directory of
`D:/Kairos/runtime`:

```powershell
python research/build_fee_v2_offline.py `
  --output D:/Kairos/runtime/feev2-research-example `
  --execution-repo D:/Kairos/kairos-execution-engine `
  --core-repo D:/Kairos/research/evedex-fee-v2-core `
  --persistence-repo D:/Kairos/research/evedex-fee-v2-persistence
```

Existing output paths, destinations outside the designated runtime root, and
destinations inside a source checkout are refused. Repositories may be dirty:
only the exact signed objects in the lock are archived; working-tree changes
are never treated as part of the source set. If a pinned commit, trusted signing
fingerprint, archive/tree hash, lock hash, or installed package hash differs,
the build fails. The source lock pins the archived commits, not the bootstrap
script itself; retain a signed, reviewed version of the script with the receipt.
Two fresh builds of the hardened probe on 8 November 2026 produced the same
receipt SHA-256 `f73472bcafb4a9ed07f23b3dc5ebb99e52ef666b24e5bc1a10740f9925727faa`.

Before importing project packages, the bootstrap rejects symlinks and Windows
reparse points in verified package paths, rejects pre-existing bytecode there,
and checks the installed Core/Persistence and extracted Execution source trees.
The probe uses `-I -S -B` and explicitly adds the verified local paths, so it
does not process `site` or `.pth` files. It repeats the tree checks afterwards.
This check concerns the project package source and that probe only: normal
subsequent Python or pytest invocations can process `.pth` files, and third-party
dependencies, build hooks, interpreter integrity, filesystem/network isolation
and production runtime remain separately unqualified.

`build-receipt.json` reports the source commits and installed hashes. The
sidecar lock is checked but the script does not install or start it. It checks
the selected host `node --version` against the sidecar's required major 22;
`SUPPORTED` only means the major version matches, not that dependencies,
process isolation, exchange access, or execution are qualified. On this host
8 November's Node was v24.20.0, so the receipt correctly reports `UNSUPPORTED`.
The separate Node 22 Docker test is a test result, not a Windows runtime install.

Use the isolated environment directly, not `uv run`/`uv sync` after the overlay:
those commands can re-apply the baseline Git overrides. For example:

```powershell
cd D:/Kairos/runtime/feev2-research-example/execution
& .venv/Scripts/python.exe -m pytest -q -p no:cacheprovider `
  tests/test_market_ioc_admission.py tests/test_market_ioc_deadline.py `
  tests/test_market_ioc_lifecycle.py tests/test_execution_fee_v2_research.py
```

Synthetic PostgreSQL tests need a separately owned disposable local database;
never point their admin DSN at an existing application database. User-specific
account evidence and credentials are deliberately absent from this source set.
