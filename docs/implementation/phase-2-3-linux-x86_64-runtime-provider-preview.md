# Linux x86_64 Console Preview implementation

The Linux Runtime Provider, CLI trust chain, bounded Console runner and synthetic
Ubuntu workflow are implemented. A local Wine canary passed, but its tested
source changes have not yet been committed. Until a receipt is bound to an exact
committed revision, the checkpoint retains this machine-checked awaiting state:

```json
{
  "status": "implemented-awaiting-linux-canary",
  "consoleValidated": false,
  "canaryCommit": null,
  "canaryReceipt": null
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

A subsequent real Wine 11.0 canary on Ubuntu 26.04 x86_64 passed in a fresh
namespace with Tini as init: the fixed Console marker appeared once, exitCode
was 0 and cleanupStatus was complete before namespace teardown. Running Python
as PID 1 without an init had previously failed cleanup; that evidence was kept.
WineHQ package signatures and package SHA-256 values were verified, and the
compiler came from Ubuntu's MinGW-w64 packages. Private evidence and source/CLI
digest receipts remain outside Git. Recording a committed canary revision is
pending verification of a committed source revision; this local pass does not yet change the
checkpoint status above.

The same validation run found and fixed mount-namespace `nsfs` parsing (opaque
namespace roots remain ineligible for Runtime filesystem identity), explicit
linker lookup and zero-output C fixture compilation, and cleanup of an owned
test directory whose permissions had intentionally been reduced. After those
fixes, the workspace Rust tests under `umask 077`, formatting, Clippy, release
build, repository contracts and synthetic ELF/CLI workflow steps passed. Together
with the isolated Python suite, the local offline checks passed. A real Wine
canary still needs its own explicit Runtime and cleanup evidence.

## Evidence limits and next gate

X11 is not used or forwarded; `graphicsValidated` and `displayForwarded` remain
false. `runtimeEvidenceScope` is `entrypoints-only`, `runtimeTreeValidated` is
false, and `networkIsolationValidated` is false: the recorded network policy
does not prove Linux network isolation. Pathname TOCTOU and product-level
detached-client cleanup remain follow-up work.

After a real pass, change the state to `linux-console-preview-passed`, set
`consoleValidated` to true, record the tested 40-character commit and copy only
the runner's complete path-free public summary into `canaryReceipt`. Its success
cleanup value is `complete`, as enforced by `validate_public_summary`. Keep
private contexts, plans, binaries and logs outside Git. Without that receipt,
retain the awaiting state even if every synthetic and offline gate passes.
