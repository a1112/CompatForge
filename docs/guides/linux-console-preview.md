# Linux x86_64 Console Preview

This developer preview runs only the repository's fixed Windows Console fixture.
It does not establish Beta, Tier 1, GUI or arbitrary application support. The
[implementation status](../implementation/phase-2-3-linux-x86_64-runtime-provider-preview.md)
remains `implemented-awaiting-linux-canary` until a real canary receipt exists.

## Prerequisites

- A controlled Linux x86_64 host with readable `/proc`, including same-UID live
  process `environ` access. Unreadable state fails verification; it is not skipped.
- An explicitly supplied MinGW-w64 x86_64 compiler and release CompatForge CLI,
  both addressed by absolute path.
- An explicit Runtime quartet: materialized root, relative Wine entry, relative
  Wineserver entry, and declared fixed release version. Both entries must be true
  x86_64 ELF executables, not shell wrappers, and report the same declared release.
- A Runtime that works with `env_clear`, without inherited `LD_LIBRARY_PATH`,
  `HOME` or `PATH`. No Wine download, installation or discovery is performed.
- Three new, absent, disjoint Runtime Store, Storage and Evidence roots outside
  the repository and materialized Runtime. The runner refuses reuse and overlap.

X11 is not used or forwarded. `hostDisplayDetected` records only the host's
environment; `displayForwarded` remains false. Network policy is recorded as
`deny`, but Linux network isolation is not validated. Only this reviewed fixture
is within scope.

## Run once

Build from the repository root, keeping build artifacts outside Git:

```bash
umask 077
CF_BUILD_ROOT=/tmp/compatforge-linux-preview-build
CARGO_TARGET_DIR="$CF_BUILD_ROOT" cargo build -p compatforge-cli --release --locked
CF_CLI="$CF_BUILD_ROOT/release/compatforge-cli"
```

Set the following explicit paths for your controlled host. The paths below are
placeholders; the three output roots must not exist. Do not create them manually.

```bash
CF_MINGW=/absolute/path/to/x86_64-w64-mingw32-gcc
CF_RUNTIME_ROOT=/absolute/path/to/fixed-wine-runtime
CF_RUNTIME_STORE=/absolute/new/path/runtime-store
CF_STORAGE_ROOT=/absolute/new/path/storage
CF_EVIDENCE_ROOT=/absolute/new/path/evidence
CF_WINE_ENTRY=bin/wine64
CF_WINESERVER_ENTRY=bin/wineserver
CF_WINE_VERSION=REPLACE_WITH_EXACT_RELEASE_VERSION

python3 -S -B tools/run_linux_console_preview.py \
  --cli "$CF_CLI" \
  --compiler "$CF_MINGW" \
  --materialized-root "$CF_RUNTIME_ROOT" \
  --runtime-store-root "$CF_RUNTIME_STORE" \
  --storage-root "$CF_STORAGE_ROOT" \
  --evidence-root "$CF_EVIDENCE_ROOT" \
  --wine "$CF_WINE_ENTRY" \
  --wineserver "$CF_WINESERVER_ENTRY" \
  --version "$CF_WINE_VERSION"
```

The runner compiles `tests/fixtures/windows_console_smoke.c`, checks its PE and
digest, bootstraps the context, compares pre/post canonical plans, executes
PreparedLaunch, and verifies events and cleanup. The supervised stdout/stderr
budget is 1 MiB combined; overflow fails the launch. The 60-second Guest budget
does not cover bootstrap or cleanup; the runner also enforces an overall deadline.

If unrelated desktop processes prevent same-UID `/proc` inspection, a controlled
user/mount/PID namespace can provide a fully visible test process tree. For a
real Wine run, place an explicitly supplied Tini init before the runner so
orphaned children are reaped. With `CF_INIT` set to the absolute Tini executable,
prefix the same Python command and arguments above with:

```bash
unshare --user --map-current-user --mount --pid --fork --mount-proc "$CF_INIT" --
```

This is a command prefix, not a standalone command. The real canary must pass
its own cleanup checks before the namespace exits; namespace teardown is not
cleanup evidence. Plain Python as PID 1 does not provide general orphan reaping.
See [Tini's upstream documentation](https://github.com/krallin/tini).

The lower-level forms below describe the same APIs for diagnosis. They are not
additional steps to run against the canary's newly created roots. Provider
configuration and bootstrap inputs follow `linux-provider.schema.json` and
`linux-bootstrap-request.schema.json` respectively:

```text
compatforge-cli provider linux probe <provider-config.json>
compatforge-cli provider linux context <provider-config.json> <storage-root>
compatforge-cli local linux context <bootstrap-request.json> [<private-context-output.json>]
compatforge-cli prepared-plan <context-config.json> <absolute-executable-path> <launch-request.json>
compatforge-cli prepared-launch <context-config.json> <absolute-executable-path> <launch-request.json>
```

Use the private output argument to avoid printing the bootstrap CoreConfig.
Contexts, plans, executable artifacts and detailed logs contain private paths
and must stay outside Git.

## Interpret evidence

A successful run exits zero and prints `linux-console-preview-passed`. Its
`public-summary.json` contains only the closed public projection:

| Fields | Required meaning |
| --- | --- |
| `schemaVersion`, `checkpoint` | `1`, `linux-x86_64-runtime-provider-preview` |
| `hostOs`, `hostArchitecture` | `linux`, `x86_64` |
| `hostDisplayDetected`, `displayForwarded` | Host observation boolean; forwarding false |
| `runtimePackId`, `runtimeVersion`, `runtimePackDigest` | Fixed Pack identity, declared release and SHA-256 |
| `guestDigest`, `planDigest` | SHA-256 of the Guest and canonical plan |
| `planCorrelation` | `pre-post-canonical-match`; no receipt from the executing process's internal plan |
| `runtimeEventKinds` | Allowed event kinds, one initial `started`, one final `exited`, one `wine-server-stop-requested` |
| `exitCode`, `cleanupStatus` | `0`, `complete` |
| `consoleValidated`, `graphicsValidated` | true, false |
| `runtimeEvidenceScope`, `runtimeTreeValidated` | `entrypoints-only`, false |
| `networkIsolationValidated` | false |

Validate the public projection with `validate_public_summary` in the runner
before copying it into the status page, together with the exact tested Git
commit. Synthetic CI helpers prove plumbing only and cannot supply this receipt.

Pack evidence covers entrypoints only, not the complete Runtime tree. Pathname
TOCTOU between hashing and execution and product-level detached-client cleanup
remain follow-up work. Runner cleanup observations are test evidence, not a
general Linux orphan recovery implementation.

## Failures and removal

| Closed category | Next check |
| --- | --- |
| `contract` | Explicit arguments, schemas, absent roots and path separation |
| `integrity` | Fixed release, ELF entrypoints and all bound digests |
| `unsupported-host` | Linux x86_64 host requirement |
| `test-infrastructure` | Explicit tools, private file access and same-UID `/proc` visibility |
| `execution` | Private command diagnostics, exit status, marker, events and timeout |
| `cleanup` | Private failure evidence and exact prefix/process lifecycle |

Preserve failure evidence. Do not treat a zero Guest exit code as success if
cleanup failed. A retry requires three new absent roots and retains the old run.

Removal is limited to the caller-owned Preview roots: Runtime Store, Storage
and Evidence. First confirm the runner and its owned processes are stopped and
cleanup has completed; if cleanup is uncertain, preserve the roots for diagnosis.
Review the exact paths and ownership before removing those roots. Keep any
needed private evidence separately. Do not remove the materialized Runtime,
shared stores, other Wine prefixes, or change global configuration. This preview
does not activate a system Runtime; removing its private roots needs no system
rollback.
