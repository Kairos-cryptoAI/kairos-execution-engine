# Bounded entry verification — 2026-09-12

Engineering test evidence only. Every venue response and 24-hour observation in
this test is synthetic. No real DEV order, paid API call, signing key, original
API file, primary database or previous test database was used.

## Results

- Windows, actual Git-locked installed dependencies: **416 unit tests passed**,
  43 integration tests deselected; Ruff, format (55 files), mypy (25 source
  files), Bandit and source/wheel build passed.
- Linux real session/arm/journal -> strict Risk contract -> engine -> fake venue:
  **1 passed in 1.86s**.
- Linux remaining journal and lifecycle fault/race suite:
  **42 passed in 10.51s**.
- Post-run isolated DB: 16 migrations, one synthetic session `ABORTED` with one
  reserved attempt, 1,441 synthetic observations and one durable dispatch claim.
  PostgreSQL reported no OOM or restart. Legacy fixture cleanup is test-only;
  this disposable database is not an operational qualification backup.

The composition test proves that the real dispatch claim is visible on a second
database connection before the fake venue call; concurrent stop waits for the
dispatch lock; replay does not send a second entry; a restarted engine without
scope authorization can reconcile its existing SL/TP and close at timeout.
Separate unit cases run the production dispatch context through real asyncio
timeout and task cancellation against a transaction model. Separate persistence
PostgreSQL tests cover committed-claim retention through injected process loss.

## Immutable environment identities

- Test image: `sha256:0d166cc738173d35697e95283c23855e4232d10586fc83d790a1fb7fd3986f66`.
- TimescaleDB: `timescale/timescaledb@sha256:61f891691050da6032023c01ea885730eeeba06b7c17b403e7d0b9c49c37dfe9`
  (`2.28.3-pg16`, matching the CI integration version).
- Python `3.11.15`; uv `0.12.3`; their base image digests are in
  [Dockerfile.integration](../tests/Dockerfile.integration).
- Installed persistence Git commit:
  `730ff1a878305ffef80a07a615795208a0372091`; verified from installed
  `direct_url.json`, not inferred from a local checkout.
- Both production imports resolve under `/app/.venv/lib/python3.11/site-packages/`;
  `/work` contains tests only. No local package bind mounts or editable
  dependency substitutions were used.

Raw working-copy SHA-256 values at build/test time (Windows line endings may
differ from a later Git-normalized checkout):

| File | SHA-256 |
| --- | --- |
| `kairos_execution/paper_engine.py` | `2a4fdd7f05747699a7ee86004a40e5c4d782ad255c42fff9c7251b9bfe51204c` |
| `kairos_execution/canary_admission.py` | `7be89dfbcbe055a5b19adccbcc81389c89c1b69bdc97490fdc0e57b2658f6a7b` |
| `kairos_execution/config.py` | `a8c79821b400954ff803044c9e88b62315ec566872c98f27567657a3eea3dc1b` |
| `uv.lock` | `50123312269dfce34e01c033ce69a37a4c74679df354a27653def692807a7d7b` |
| `tests/test_integration_canary_execution.py` | `572b8283d50092c5107b68a01d7a24b5a30315c5d653d172d547eebe26cc468a` |

## Exact local commands

Run from the execution repository root. The credential below is an intentionally
public disposable test value. These commands created a NEW internal network and
NEW tmpfs database; they do not connect to a deployed PAPER project.

```powershell
docker build --file tests/Dockerfile.integration --tag kairos-execution-bounded-integration:20260912 .
docker network create --internal kairos-bounded-exec-test-20260912
docker run -d --name kairos-bounded-exec-postgres-20260912 --network kairos-bounded-exec-test-20260912 --network-alias timescaledb --memory 768m --shm-size 128m --tmpfs /var/lib/postgresql/data:rw,nosuid,size=512m --env POSTGRES_USER=kairos --env POSTGRES_PASSWORD=synthetic_canary_ci_only --env POSTGRES_DB=kairos_execution_test_202609120002 timescale/timescaledb@sha256:61f891691050da6032023c01ea885730eeeba06b7c17b403e7d0b9c49c37dfe9 postgres -c shared_buffers=64MB -c max_connections=30 -c max_worker_processes=8 -c timescaledb.max_background_workers=4
docker exec kairos-bounded-exec-postgres-20260912 pg_isready -U kairos -d kairos_execution_test_202609120002
docker run --rm --name kairos-bounded-exec-gate-20260912 --network kairos-bounded-exec-test-20260912 --read-only --tmpfs /tmp:rw,nosuid,size=256m --cap-drop ALL --security-opt no-new-privileges:true --env KAIROS_PERSISTENCE_DATABASE_URL=postgresql://kairos:synthetic_canary_ci_only@timescaledb:5432/kairos_execution_test_202609120002 --env KAIROS_EXECUTION_TEST_DATABASE=kairos_execution_test_202609120002 kairos-execution-bounded-integration:20260912 python -m pytest -q -p no:cacheprovider --tb=short tests/test_integration_canary_execution.py
docker run --rm --name kairos-bounded-exec-gate-20260912 --network kairos-bounded-exec-test-20260912 --read-only --tmpfs /tmp:rw,nosuid,size=256m --cap-drop ALL --security-opt no-new-privileges:true --env KAIROS_PERSISTENCE_DATABASE_URL=postgresql://kairos:synthetic_canary_ci_only@timescaledb:5432/kairos_execution_test_202609120002 --env KAIROS_EXECUTION_TEST_DATABASE=kairos_execution_test_202609120002 kairos-execution-bounded-integration:20260912 python -m pytest -q -p no:cacheprovider --tb=short tests/test_integration_paper_engine.py tests/test_integration_journal.py
```

Inspection confirmed PGDATA is a 512MiB tmpfs, `Mounts=[]`, and
`5432/tcp=null`: no persistent volume or host port. The isolated test database
and network were left running for the delivery review; their data is volatile.

Actual 24-hour DEV observation, scenario coverage, seven-day soak and strategy
alpha evaluation remain independent requirements. This report does not set
`PAPER_QUALIFIED`, `ALPHA_READY` or `LIVE_READY` to true.
