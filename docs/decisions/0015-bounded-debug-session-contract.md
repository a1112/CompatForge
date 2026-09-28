# ADR 0015: bounded managed Windows debug session

Status: accepted for Stage 2 Tasks 5 and 6. Task 5 established the authority
contract; Task 6 supplies the Linux WineDbg/GDB provider and stdio DAP adapter.

## Authority and identity

`compatforge-cli debug-session <request.json>` talks to the private Linux user
service socket. The service checks its caller-owned 0700 runtime directory,
0600 socket and matching peer UID. A launch names a registered application,
its **currently selected** Ready generation and declared launcher. The service
holds its operation lock through selected-generation verification and provider
startup, then pins the application and Bottle against update, rollback and
uninstall until the debug process tree is confirmed gone.

The supervisor returns an opaque session ID and 256-bit random capability.
Subsequent operations check UID and capability. At most eight sessions may be
live; the last 32 terminal handles permit idempotent replies. `terminate` and
`disconnect` release a session only after provider cleanup succeeds. Service
shutdown attempts all owned sessions. On a service crash, the worker's private
PID namespace and `unshare --kill-child` kill descendants; a replacement
service refuses a debug session directory while any Wine process retains its
owned prefix, then reclaims process-free stale directories.

No request supplies an arbitrary executable, host PID, debugger binary,
environment, command line, GDB console command or network listener. The
selected managed executable, pinned Runtime Pack, WineDbg, GDB and worker bytes
are verified before spawn. The worker runs under the ordinary account in a
private user, network and PID namespace. Its fixed WineDbg TCP port is visible
only on that namespace's loopback. Control traffic is bounded JSON over the
worker's inherited stdin/stdout; only the CLI's DAP interface faces an IDE.

## Public DAP boundary

`compatforge-cli debug-adapter <managed-debug-launch.json>` opens one managed
session and speaks framed DAP on stdin/stdout. The launch file contains the
same selected target as `debug-session`. The IDE's `launch` metadata is
discarded and replaced with that target; the GDB `attach` target, executable
and source mappings are synthesized by the service. An IDE cannot attach to a
host process or choose a debugger path. DAP output has positive monotonic
sequence numbers, including rejected requests and terminal replies.

Only `initialize`, `launch`, `setBreakpoints`, `configurationDone`, `threads`,
`continue`, `pause`, `next`, `stepIn`, `stepOut`, `stackTrace`, `scopes`,
`variables`, `terminate` and `disconnect` are admitted. Source paths in
breakpoints must match a reviewed one-to-one `sourceMap`; source paths returned
by GDB are mapped back to the public paths, and unmapped source locations are
omitted. `evaluate`, REPL, memory access, disassembly, reverse DAP requests
such as `runInTerminal`, and unknown commands are rejected. The initialize
reply advertises only configuration-done and terminate support. Frames,
control lines, collections and wait times are bounded; a single oversized
backend response becomes a failed DAP response without terminating its target.

## Availability and limits

The image must install and pin WineDbg and the GDB runtime, then copy the
root-owned `debuggerRuntime` template into the ordinary user's service config.
Existing users require the explicit `user-init --refresh-debugger` migration;
modified configs are preserved and rejected. The default `sourceMap` is empty,
so source breakpoints require a reviewed mapping in a candidate configuration.

The isolated ForgeOS v7 evidence in `docs/evidence/2026-09-29-debug-service-v7.md`
established real x64 C breakpoints, reverse source paths, stack, local,
stepIn/stepOut/next, pause, a Wine exception stop, unsafe request denial,
cleanup and normal reboot persistence against the final pinned bundle. Wine
`RaiseException` appears as a GDB `signal` stop without structured SEH fields;
pause appears with the generic `stopped` reason.
MSVC/PDB and .NET debugging are unverified, as is full Windows debugger parity.

## Dependency decision

`compatforge-debug` uses workspace `serde`, `serde_json`, `sha2` and
`getrandom = 0.2.16` for the operating-system CSPRNG. `Cargo.lock` records the
exact resolution. The dependency is MIT OR Apache-2.0 and release packaging
retains its notice: <https://github.com/rust-random/getrandom/tree/v0.2.16>.
