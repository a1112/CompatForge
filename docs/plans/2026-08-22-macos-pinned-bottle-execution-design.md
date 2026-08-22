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
computes the SHA-256 digest used by inspection and planning.

For each Sumatra session, the Python caller opens its already-bound repository-external work root
no-follow and keeps that directory descriptor alive until all CLI evidence has been verified. It
creates two empty output files there with independent 128-bit names, `O_EXCL|O_NOFOLLOW`, and mode
`0600`, immediately unlinks them, and retains their descriptors. Python passes the reviewed work-root
path, its directory descriptor, and both anonymous output descriptors through `pass_fds`; the
installed CLI has no repository-root input, so Python contract tests establish repository
externality. The CLI duplicates each inherited descriptor with `F_DUPFD_CLOEXEC`, immediately
restores `FD_CLOEXEC` on every raw inherited descriptor, and owns only the duplicates. It proves the
duplicated directory still names the supplied path, requires effective-user ownership, and rejects
lexical or physical overlap with the storage root, Bottle root, source path, Runtime roots, or
another CLI-known writable root. Inside that held directory Rust generates a
128-bit OS-random name, calls
`openat(O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600)`, validates an empty single-link regular
file, and calls `unlinkat` immediately. No PE byte may be copied until `fstat` confirms the opened
file is still the same inode, has size zero, and has `st_nlink == 0`. Collision retries are bounded.
The name necessarily exists briefly as filesystem metadata but never enters a log, serialized
evidence, return value, or retained directory entry after `unlinkat`. The unlinked ordinary file is
synchronized, rewound, inspected, and held until Wine has inherited it.

This design explicitly does not defend against a malicious principal that has directory-search
permission and can enumerate or correctly guess the 128-bit name and open the file during the small
successful `openat`-to-`unlinkat` interval. That normally means the same effective UID, but an ACL or
filesystem configuration may grant another principal equivalent access despite restrictive mode bits.
Same-name pre-creation loses to `O_EXCL`; after `unlinkat` no pathname can acquire the inode. Closing
that interval would require a privileged broker, a private filesystem, or another platform primitive
outside this phase. All later pathname, directory, source, evidence-output, and process substitution
races remain in scope and must fail closed.

Evidence handoff has no named output or cleanup race. The CLI validates the two inherited output
duplicates as distinct, zero-length, unlinked regular files, writes at most 1,048,576 canonical bytes
to each, syncs and rewinds them, and returns each bounded byte length and SHA-256 in one final closed
path-free stdout receipt after the existing byte-compatible RuntimeEvent lines. After the CLI exits,
Python rewinds and reads its original descriptors, requires the same zero-link identities, applies
the same 1,048,576-byte bound, and compares length and digest before parsing the in-memory bytes.
Only descriptor close remains; no pathname unlink is used for either evidence output.

The acceptance-only launch command passes the inherited descriptor to Wine through
`/dev/fd/<descriptor>`. On macOS the command uses Wine's Unix-path launch entry point. The original
Bottle directory remains the working directory so SumatraPDF retains its expected surrounding
context.

### Rust components

- `compatforge-inspect` gains an internal inspection entry point that reads a caller-provided
  regular file handle without reopening a pathname.
- `compatforge-guest-artifact` owns the pinned executable lease: logical Bottle binding, held source
  and directory identities, verified inspection result, digest, size, and unlinked execution file.
  A small platform module contains the only audited `openat`/`fstatat` boundary; the rest of the
  crate remains safe Rust. The crate exposes a safe, opaque, non-serializable
  `HeldExternalWorkRoot` wrapper. Its safe constructor validates an inherited descriptor number,
  sets `FD_CLOEXEC` on that raw descriptor, obtains its own `OwnedFd` with `F_DUPFD_CLOEXEC`, and
  never closes or assumes ownership of the raw input. It exposes no raw-descriptor accessor. A
  sibling `InheritedEvidenceFile` wrapper applies the same duplication and CLOEXEC rule to the two
  anonymous output descriptors. The CLI may then use only identity revalidation, bounded canonical
  output, and unlinked-file capture methods.
- `compatforge-orchestrator` uses a private `PinnedBottle` prepared-executable variant. It prepares
  and authorizes only when the caller supplies the same lease, and keeps the serialized plan
  unchanged. Ordinary `authorize()` refuses this private variant so it cannot reopen the pathname.
- `compatforge-process` receives the lease through a private in-process API, inherits the unlinked
  descriptor into the Wine child, rebuilds the complete Wine argument vector, and retains the
  logical path in policy evidence.
- `compatforge-cli` exposes a closed acceptance-only prepared command that performs capture,
  inspection, planning, authorization, held-work-root evidence publication, and launch within one
  process so the lease never has to be serialized or reopened. It accepts only Bottle id
  `gui-sumatrapdf`, the fixed relative executable location, `BottleInPlace`, x86-64, and no guest
  arguments.
- `run_gui_baseline.py` uses this command only for the fixed SumatraPDF executable. Other applications
  retain their current commands.

## Data Flow

1. The installer writes the fixed SumatraPDF executable inside the current Bottle.
2. The runner rejects missing, linked, hardlinked, reparse, wrong-location, or duplicate legacy
   installations.
3. Python holds the existing work root plus two pre-unlinked output files, then the acceptance-only
   CLI duplicates the inherited descriptors, binds the directory to the reviewed path, and opens the
   fixed source path component-by-component with held no-follow directory handles, creates one random
   ordinary file relative to the held work-root descriptor, and unlinks it before reading source
   bytes.
4. Rust computes and inspects the unlinked bytes, then writes canonical inspection and ordinary
   plan evidence to the two validated unlinked output descriptors.
5. The orchestrator compiles and authorizes the ordinary Bottle plan using a private pinned variant
   and the same lease; it never calls the pathname-based Bottle verifier.
6. The process supervisor revalidates the held source/directory identities and source digest,
   rewinds the unlinked file, duplicates one descriptor in the parent, clears `CLOEXEC`, and
   launches exactly `wine start.exe /unix /dev/fd/<descriptor>`. Existing process-group setup
   remains the only `pre_exec` hook.
7. The parent closes the process-owned duplicate immediately after spawn and keeps the caller-owned
   lease until process attachment succeeds or the failure path has reaped the child.
8. After the existing RuntimeEvent lines, the CLI returns one final fixed output length/digest
   receipt. Python reads both original anonymous output descriptors, verifies them against that
   receipt, and closes them. No pathname-only cross-process handoff or output unlink occurs.

The canonical ordinary plan and external full evidence retain their already-authorized logical
Bottle, Runtime, storage and working-directory paths. Compact evidence, stdout and all pinned error
messages remain path-free. Descriptor numbers, random staging names, anonymous paths, temporary paths
and developer paths never enter any persisted evidence.

## Failure Semantics

- Any pathname, parent identity, reparse, link-count, size, digest, or Bottle-containment change
  observed by the final lease revalidation is an integrity failure before process creation. Changes
  after that boundary cannot affect the unlinked bytes; a post-spawn revalidation still reports
  them as integrity failures and terminates the managed process.
- A short read, changed-during-read result, collision retry exhaustion,
  failure to unlink before writing, unlinked-file write/sync/rewind failure, descriptor inheritance
  failure, or Wine launch failure is closed and path-redacted.
- The implementation never falls back to the original naked pathname after the pinned path is
  selected.
- Cleanup and process-tree failures remain fatal and retain their existing precedence.
- If CrossOver or Whisky cannot launch the inherited descriptor on a real Mac, the pinned-execution
  phase stops. It must not silently fall back to pathname execution.

## Compatibility Checkpoint

The repository can verify the descriptor lifetime, command construction, schema stability, and
failure closure on Windows and host-independent tests. Before the Python runner selects the new
command, a focused CrossOver and Whisky spike must verify `start.exe /unix /dev/fd/<descriptor>` on
the real Apple Silicon acceptance host. The spike calls the same Rust capture, prepare, authorize,
and `start_pinned_bottle` APIs as the CLI from a test-only macOS harness.
`start_pinned_bottle` returns a live managed handle before the caller performs the post-spawn source
revalidation, so the harness can deterministically mutate the logical source in that interval
without adding a production CLI hook, stdin, environment switch, or timing race. It then verifies
the expected window from the captured digest, calls the production revalidation and managed
termination path, and requires zero residual processes. Both Runtimes must launch the fixed
SumatraPDF build successfully. Failure stops implementation and reopens the design; it cannot be
deferred until after runner integration.

## Testing

Required RED/GREEN coverage includes:

- same-inode overwrite after initial binding;
- no separate Sumatra inspection can be substituted between capture and planning;
- Bottle, parent, and executable substitution before and during inspect, plan, and launch;
- hardlink or reparse insertion after binding;
- the staging name has 128 bits of OS randomness, collision retries are bounded, and the name is
  never emitted;
- the ordinary staging file is created relative to the held private work root, unlinked before the
  first copied byte, and verified as the same zero-link inode;
- the acknowledged directory-search-capable principal `openat`-to-`unlinkat` trust boundary is
  documented and no test claims a stronger guarantee from mode bits alone;
- anonymous execution bytes remain the initially captured digest;
- child receives the inherited descriptor and never the naked fixed path;
- descriptor is closed on every preparation, spawn, timeout, and cleanup failure;
- persisted plan/full evidence contain only their existing authorized logical paths;
- CLI-to-Python output-fd substitution, duplicate/closed/stdin/stdout/stderr fd, digest/size mismatch,
  over-limit bytes, directory-path substitution, ACL-capable create-to-unlink opener boundary, and
  close-failure mutants are covered through anonymous descriptors and the stdout receipt;
- compact evidence and stdout contain no host path;
- no output contains a descriptor number, random staging name, or anonymous path;
- stable pinned error codes contain no storage, temporary, developer, or executable path;
- default `BottleInPlace`, immutable artifacts, 7-Zip, and Notepad++ remain byte-compatible;
- public `LaunchPlan` JSON and FFI ABI remain unchanged; and
- real CrossOver and Whisky launch checkpoint on macOS.
