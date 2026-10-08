# Linux x86_64 Console Preview implementation

The Linux Runtime Provider, CLI trust chain, bounded Console runner and synthetic
Ubuntu workflow are implemented. On 2026-09-25, a real Wine 11.0 Console canary
passed on Ubuntu 26.04.1 x86_64 against committed source revision
`4abfbd0fd271e14316e6e8241a0933a9ea1bf8d3`. The runner's complete,
validated public receipt is:

```json
{
  "status": "linux-console-preview-passed",
  "consoleValidated": true,
  "canaryCommit": "4abfbd0fd271e14316e6e8241a0933a9ea1bf8d3",
  "canaryReceipt": {
    "checkpoint": "linux-x86_64-runtime-provider-preview",
    "cleanupStatus": "complete",
    "consoleValidated": true,
    "displayForwarded": false,
    "exitCode": 0,
    "graphicsValidated": false,
    "guestDigest": "sha256:a727b128e871847d39b2528b20b73143feef2b90025331cbf7a8fcd4d4c4ff94",
    "hostArchitecture": "x86_64",
    "hostDisplayDetected": false,
    "hostOs": "linux",
    "networkIsolationValidated": false,
    "planCorrelation": "pre-post-canonical-match",
    "planDigest": "sha256:3905cc590682085e326ee6d530edc1e85c4e7df44bb4c5ed257a7049b5e11992",
    "runtimeEventKinds": ["started", "output", "wine-server-stop-requested", "exited"],
    "runtimeEvidenceScope": "entrypoints-only",
    "runtimePackDigest": "sha256:ae3b3e18ea4e2fda594ab5e3259f9176a795385cae390f831a731ce65e06c106",
    "runtimePackId": "wine-linux-x86-64-local-preview",
    "runtimeTreeValidated": false,
    "runtimeVersion": "11.0",
    "schemaVersion": "1"
  }
}
```

This status is not a claim that every offline gate has passed on every host.
Beta, Tier 1, GUI and general application compatibility remain outside this slice.

## Implemented surfaces

- `compatforge-provider-linux`: closed configuration, x86_64 ELF verification,
  fixed entrypoint digests, bounded version probes and Runtime Store association.
- `provider linux probe`, `provider linux context`, `local linux context` and
  the existing `prepared-plan` / `prepared-launch` chain: explicit inputs,
  private context output, trusted Guest binding and cleanup acknowledgement.
- Process supervision: Runtime identity revalidation, startup cleanup,
  a combined 1 MiB stdout/stderr budget and bounded completion.
- `run_linux_console_preview.py`: fixed Console fixture, plan correlation,
  process observations, failure evidence and closed public summary.
- `linux-provider-preview.yml`: synthetic ELF helpers and offline gates.
  Synthetic helper success does not validate real Wine or Guest execution.

## Verification and prerequisites

Run the repository validator, Linux Python contract tests, `cargo fmt --all --check`,
`cargo check --workspace --all-targets --locked`, `cargo test --workspace --locked`,
`cargo clippy --workspace --all-targets --locked -- -D warnings`, and the release
CLI build. Keep Cargo output and all evidence outside Git. The workflow also
checks real synthetic ELF execution, Pack installation and context wiring.
Use `umask 077` for local validation: bootstrap fixtures intentionally reject
group-writable Store control directories.

The real canary requires an explicit MinGW-w64 compiler and Runtime quartet
(root, Wine, Wineserver, fixed release). Wine and Wineserver must be true ELF
executables, not shell wrappers, reporting the same declared release and working
under `env_clear` without caller `LD_LIBRARY_PATH`, `HOME` or `PATH`. Readable
`/proc` with same-UID `environ` access is mandatory. See the
[operator guide](../guides/linux-console-preview.md) for exact commands, evidence
fields, troubleshooting and removal of caller-owned Preview roots.

On 2026-09-10, the desktop host exposed unreadable same-UID live process
environments in two native Python observer tests. Running the suite in a fresh
user/mount/PID namespace with its own `/proc` resolved this prerequisite without
changing host permissions or skipping unreadable processes:

```bash
unshare --user --map-current-user --mount --pid --fork --mount-proc \
  python3 -S -B -m unittest tests.test_linux_provider_contracts -q
```

All 92 Python tests passed in that namespace, including rejection of unreadable
live environments. This result applies to the isolated test process tree; it
does not establish visibility of the desktop host's processes.

A historical real Wine 11.0 canary on Ubuntu 26.04 x86_64 had passed in a fresh
namespace with Tini as init, but it used uncommitted source changes. Running
Python as PID 1 without an init had previously failed cleanup; that evidence
was kept. On 2026-09-25, the canary was repeated against the exact committed
revision above in a Hyper-V Ubuntu 26.04.1 VM with WineHQ Wine 11.0 and an
explicit Ubuntu MinGW-w64 compiler. Tini was PID 1 in a private mount/PID
namespace; the canary's own cleanup checks completed before namespace teardown.
The CLI copied for the root-owned runner was byte-identical to the release
build (SHA-256 `e1b1783074e098b98e0005ec85a77895b893963fc62534f62b304246301321c3`).
The public summary passed `validate_public_summary` and has SHA-256
`ef80dd04d59dfd776d75187cf0ac78810e1bb30648b6421eb00dbf2a175e4e25`.
Private evidence and the verification receipt remain outside Git.

The same validation run found and fixed mount-namespace `nsfs` parsing (opaque
namespace roots remain ineligible for Runtime filesystem identity), explicit
linker lookup and zero-output C fixture compilation, and cleanup of an owned
test directory whose permissions had intentionally been reduced. After those
fixes, the workspace Rust tests under `umask 077`, formatting, Clippy, release
build, repository contracts and synthetic ELF/CLI workflow steps passed. Together
with the isolated Python suite, the local offline checks passed. The 2026-09-25
VM run repeated the Linux Python suite (94 tests), workspace Rust tests,
formatting, Clippy, repository validation and release CLI build before the
committed canary.

## Evidence limits and next gate

X11 is not used or forwarded; `graphicsValidated` and `displayForwarded` remain
false. `runtimeEvidenceScope` is `entrypoints-only`, `runtimeTreeValidated` is
false, and `networkIsolationValidated` is false: the recorded network policy
does not prove Linux network isolation. Pathname TOCTOU and product-level
detached-client cleanup remain follow-up work.

The checkpoint records the tested 40-character commit and only the runner's
complete path-free public summary in `canaryReceipt`. Its success cleanup value
is `complete`, as enforced by `validate_public_summary`. Private contexts,
plans, binaries and logs stay outside Git.
