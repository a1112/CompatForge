# Pinned Bottle Execution for macOS Acceptance

**Date:** 2026-08-22

**Status:** Approved design addendum

## Problem

The macOS GUI acceptance runner now installs SumatraPDF at the deterministic Bottle path
`C:\CompatForge\SumatraPDF\SumatraPDF.exe`. Holding and revalidating the pathname detects most
substitutions, but it cannot prevent a foreign process from replacing or overwriting the file
after validation and before Wine opens it. A post-launch check detects the drift too late: Wine
may already have consumed foreign bytes.

The Python runner cannot close this boundary alone. CompatForge inspection, prepared planning,
and process supervision currently accept a logical Bottle pathname. The final Wine process also
opens that pathname. The trust chain therefore needs an opt-in execution lease that keeps the
logical Bottle identity separate from the bytes actually consumed by Wine.

## Scope

This addendum applies only to the SumatraPDF path used by the local macOS dual-Runtime acceptance
workflow. It does not change the public `LaunchPlan` JSON schema, the FFI ABI, the normal 7-Zip or
Notepad++ launch path, or the default `BottleInPlace` behavior.

The implementation may add private CLI and Rust APIs needed to carry the lease through inspection,
prepared planning, and process creation. One closed CLI invocation owns the complete
capture-to-launch session; the Python runner does not perform a separate Sumatra inspection or
planning call before that session. Those APIs must remain opt-in and must not be reachable from
default CI, PATH lookup, a shell, ambient environment variables, or network access.

## Chosen Architecture

### Logical path and execution bytes

The logical path remains the reviewed Bottle path. It is used for Bottle containment, policy,
working-directory selection, evidence, and sibling-resource semantics.

The execution bytes are captured once through a no-follow regular-file handle after the installer
completes. The lease also holds every directory handle from the reviewed Bottle root to the source
entry. The capture enforces the existing size bound, single-link and reparse restrictions, and
computes the SHA-256 digest used by inspection and planning. A `create_new` staging file is unlinked
immediately after creation and before any source byte is copied; `nlink == 0` is required before the
first write. The anonymous file is synchronized, rewound, inspected, and held until Wine has
inherited it.

The acceptance-only launch command passes the inherited descriptor to Wine through
`/dev/fd/<descriptor>`. On macOS the command uses Wine's Unix-path launch entry point. The original
Bottle directory remains the working directory so SumatraPDF retains its expected surrounding
context.

### Rust components

- `compatforge-inspect` gains an internal inspection entry point that reads a caller-provided
  regular file handle without reopening a pathname.
- `compatforge-guest-artifact` owns the pinned executable lease: logical Bottle binding, held source
  and directory identities, verified inspection result, digest, size, and anonymous execution file.
  A small platform module contains the only audited `openat`/`fstatat` boundary; the rest of the
  crate remains safe Rust.
- `compatforge-orchestrator` uses a private `PinnedBottle` prepared-executable variant. It prepares
  and authorizes only when the caller supplies the same lease, and keeps the serialized plan
  unchanged. Ordinary `authorize()` refuses this private variant so it cannot reopen the pathname.
- `compatforge-process` receives the lease through a private in-process API, inherits the anonymous
  descriptor into the Wine child, substitutes only the first execution argument, and retains the
  logical path in policy evidence.
- `compatforge-cli` exposes a closed acceptance-only prepared command that performs capture,
  inspection, planning, authorization, evidence-file publication, and launch within one process so
  the lease never has to be serialized or reopened. It accepts only Bottle id `gui-sumatrapdf`, the
  fixed relative executable location, `BottleInPlace`, x86-64, and no guest arguments.
- `run_gui_baseline.py` uses this command only for the fixed SumatraPDF executable. Other applications
  retain their current commands.

## Data Flow

1. The installer writes the fixed SumatraPDF executable inside the current Bottle.
2. The runner rejects missing, linked, hardlinked, reparse, wrong-location, or duplicate legacy
   installations.
3. The acceptance-only CLI opens the fixed path component-by-component with held no-follow directory
   handles and creates the anonymous file before reading source bytes.
4. Rust computes and inspects the anonymous bytes, then writes canonical inspection and ordinary
   plan evidence to caller-supplied create-new output files.
5. The orchestrator compiles and authorizes the ordinary Bottle plan using a private pinned variant
   and the same lease; it never calls the pathname-based Bottle verifier.
6. The process supervisor revalidates the held source/directory identities, rewinds the anonymous
   file, duplicates one descriptor in the parent, clears `CLOEXEC`, and launches exactly
   `wine start.exe /unix /dev/fd/<descriptor>`. Existing process-group setup remains the only
   `pre_exec` hook.
7. The parent closes the process-owned duplicate immediately after spawn and keeps the caller-owned
   lease until process attachment succeeds or the failure path has reaped the child.

No nonce, descriptor number, anonymous path, or host developer path enters persisted evidence.

## Failure Semantics

- Any pathname, parent identity, reparse, link-count, size, digest, or Bottle-containment failure is
  an integrity failure before process creation.
- A short read, changed-during-read result, failure to become anonymous before writing, anonymous-file
  write/sync/rewind failure, descriptor inheritance failure, or Wine launch failure is closed and
  path-redacted.
- The implementation never falls back to the original naked pathname after the pinned path is
  selected.
- Cleanup and process-tree failures remain fatal and retain their existing precedence.
- If CrossOver or Whisky cannot launch the inherited descriptor on a real Mac, Task 10 stops. It
  must not silently fall back to pathname execution.

## Compatibility Checkpoint

The repository can verify the descriptor lifetime, command construction, schema stability, and
failure closure on Windows and host-independent tests. Before the Python runner selects the new
command, a focused CrossOver and Whisky spike must verify `start.exe /unix /dev/fd/<descriptor>` on
the real Apple Silicon acceptance host while the source pathname is unavailable. Both Runtimes must
launch the fixed SumatraPDF build successfully. Failure stops implementation and reopens the design;
it cannot be deferred until after runner integration.

## Testing

Required RED/GREEN coverage includes:

- same-inode overwrite after initial binding;
- no separate Sumatra inspection can be substituted between capture and planning;
- Bottle, parent, and executable substitution before and during inspect, plan, and launch;
- hardlink or reparse insertion after binding;
- staging is unlinked and has `nlink == 0` before the first copied byte;
- anonymous execution bytes remain the initially captured digest;
- child receives the inherited descriptor and never the naked fixed path;
- descriptor is closed on every preparation, spawn, timeout, and cleanup failure;
- persisted plan, compact evidence, and stdout contain no descriptor number or anonymous host path;
- stable pinned error codes contain no storage, temporary, developer, or executable path;
- default `BottleInPlace`, immutable artifacts, 7-Zip, and Notepad++ remain byte-compatible;
- public `LaunchPlan` JSON and FFI ABI remain unchanged; and
- real CrossOver and Whisky launch checkpoint on macOS.
