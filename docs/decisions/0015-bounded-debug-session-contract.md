# ADR 0015: bounded debug session contract before provider execution

Status: accepted for Stage 2 Task 5. Real breakpoints and DAP are Task 6 gates.

## Authority and identity

`compatforge-cli debug-session <debug-request.json>` sends a validated request to
the existing private Linux user service socket. The service already requires a
caller-owned 0700 runtime directory, a 0600 socket and matching kernel peer UID.
No TCP endpoint is opened. The command does not accept a host PID, debugger
path, debugger console text, expression, shell command or environment override.
The debug payload is limited to 64 KiB inside the service's 1 MiB outer frame.

A target names an application, selected generation and declared launcher. Before
provider launch, the service reuses the desktop launch inventory, which verifies
the selected Ready generation, frozen Runtime Pack binding and installed launcher
digests. The generic supervisor stores that target and the owning UID, and
returns an unpredictable 256-bit capability with an opaque session ID. Both UID
and capability are checked on subsequent operations. A client's disconnect from
the service socket alone does not transfer ownership or terminate a session.

The v1 commands are `launch`, `status`, `terminate` and `disconnect`. The
supervisor checks state transitions and invokes a backend once for each terminal
operation; a cleanup failure retains the owned session and surfaces an error.
At most eight live sessions are admitted. Successful terminal sessions release
admission immediately; only the most recent 32 terminal handles are retained
for idempotent replies. An evicted handle receives `unauthorized`, and an active
session is never evicted to reclaim terminal history.
Its explicit `shutdown` retries all owned sessions and reports failure. Task 6
must wire that cleanup into the service shutdown gate when replacing the
unavailable backend with a real process provider. An unexpected owner-process
exit still relies on the provider's owned process-tree cleanup contract.

## Runtime binding and current availability

`packaging/linux/debugger-runtime.json` names the current Wine Runtime Pack but
sets `available: false` and leaves WineDbg/GDB digests null. The isolated ForgeOS
v3 guest has WineDbg but no GDB, so a debugger cannot be claimed as installed.
`DebuggerPackageBinding::trusted` rejects a missing binary pin, a provider ID
change or a Runtime Pack digest mismatch. `PinnedDebugger::verify_executable`
checks each binary digest separately. Task 6 will obtain measured package
artifacts, pin their digests and verify the actual files before execution.
No untrusted debugger path is accepted from the public request.

The production service currently uses `UnavailableBackend`: an eligible launch
returns `unavailable` without creating a session. Tests use a synthetic backend
only to exercise ownership, idempotency and state logic. These tests do not prove
WineDbg/GDB, breakpoints, DAP or IDE debugging. MSVC/PDB and .NET remain separate
capability gates.

## Dependency decision

The new `compatforge-debug` crate uses the existing pinned workspace `serde`,
`serde_json` and `sha2`. It adds `getrandom = 0.2.16` solely to obtain session
capabilities from the operating system CSPRNG; failure refuses a session.
Upstream: https://github.com/rust-random/getrandom/tree/v0.2.16 . License:
MIT OR Apache-2.0. `Cargo.lock` records the exact transitive resolution;
release packaging must retain its license notice. The provider remains separate
from the contract, so this dependency does not expose a debugger or network
listener by itself.
