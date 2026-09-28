# ADR 0013: Managed application generations and service ownership

Status: accepted implementation of the Windows application lifecycle stage.

## Decision

CompatForge installs each reviewed application version into a new physical Bottle,
`bottles/gen-job-<time>-<counter>/prefix`. The application's logical `bottleId`
remains a conflict group. A bounded schema v1 record under
`service/generations/<application-id>.json` contains the selected generation,
retained generations, and the current operation lease. `JsonStore` supplies its
existing atomic replacement, file sync, and directory sync. A single replacement
commits the verified generation, selection, and released lease together.

The generation records the complete application definition and its SHA-256,
installed application version, exact runtime binding/pack digest/provider version,
and the digest of every declared launcher. Install requests require the reviewed
installer SHA-256 and exact recipe arguments. Installer argument overrides, runtime environment overrides, and a launcher
selector are rejected. The only installer session overrides are local `DISPLAY`
(`:number[.screen]`) and an absolute `XAUTHORITY` path, so the existing desktop
user can authorize Wine to connect to its display. Launch requests still accept
bounded argv values for opening files. No shell or arbitrary executor is added.

Only a successful installer exit **and** a successful bounded supervisor join
allow launcher verification and selection. Every launcher must be a real,
inspectable PE file under the generation's `drive_c`; linked ancestors are
rejected. Preparation failures, cancellation, failed cleanup, and missing
launchers retain the old selection. A later definition upsert cannot redirect
the selected generation's launcher or runtime. Launch and rollback recheck
launcher digests and the saved runtime against the supplied core configuration;
runtime changes fail closed.

Generation state is the installation commit authority. Job reads reconcile
installer status with that state, so an installer exit record saved immediately
before activation cannot alone report an installed application. On an atomic
replacement's directory-sync error the lifecycle store attempts to restore the
previous complete record. If restoration also fails, that application's state
is blocked in the current service with a durability-uncertain error. Disk faults
can still require storage repair; no durability or power-loss guarantee is made
after both writes fail. The service must remain stopped until the persisted
selection and lease have been inspected in that situation.

Rollback selects a previously verified generation. Uninstall clears selection.
Both retain all prefixes, prior generations, and personal files; neither runs the
guest uninstaller. Rollback does not reverse user-data migrations. Data deletion
and desktop integration removal are outside this first lifecycle implementation.
The retained-generation limit is 32, reusing `compatforge-bottle`'s version history
bound. Reaching it rejects another install; it never silently prunes data.

`compatforge-bottle`'s existing offline migration/snapshot store remains the owner
of immutable imported Bottle versions. Its whole-prefix import transaction is
not a live installer sandbox. Managed installers therefore use fresh ordinary
Bottle prefixes and the service's small selection record; no second runtime pack
store is introduced. Existing `PreparedLaunch`, guest artifact verification,
runtime pack verification, and `ProcessSupervisor` remain execution boundaries.

## Ownership and recovery

One service holds exclusive OS file locks for both service and core storage roots
for its lifetime. A second instance, including one using a different service root
with the same storage root, fails before recovery. Lock files are retained and
never unlinked. A process-local operation mutex serializes preparation and
application mutations; all owned handles, including failed cleanup handles,
remain conflicts until cleanup has been confirmed. Service metadata is bounded
to 4 MiB per record with bounded collections and IDs. Roots, metadata, launcher
paths, and lock paths reject symbolic links and Windows reparse points.

The dependency is `fs4 = 0.8.4` with only `sync`, MIT OR Apache-2.0, from
[fs4's upstream repository](https://github.com/al8n/fs4-rs) and
[the crates.io release](https://crates.io/crates/fs4/0.8.4). Its published
`rust-version` is 1.75.0, compatible with this workspace's 1.78 MSRV. It uses
rustix/Windows platform locking behind a safe API. Standard-library file locking
would require Rust 1.89. Both workspace and excluded Tauri lockfiles are updated.
Locks coordinate cooperating CompatForge services; they are not protection from
the account owner modifying its own storage or a separate legacy CLI process.

OS lock release does not prove a crashed service's Wine processes have exited.
Before runtime effects, each operation persists the current Linux kernel boot UUID.
Startup quarantines leftover leases even when the job contains a successful exit.
Normal explicit service shutdown persists cancellation/failure and releases leases
only after joins succeed. A successful retry of an owned cleanup handle can also
release its quarantine.

The first crash recovery implementation requires a host reboot. The typed
`applications.recover` operation reads only the fixed
`/proc/sys/kernel/random/boot_id`, bounds the read, validates the UUID, and requires
it to differ from the saved UUID. Same-boot recovery fails with a reboot-required
message. Missing/invalid boot identity reports `recoveryCapability: unavailable`
and cannot clear quarantine; this recovery capability is currently Linux-only.
No user-supplied boot ID, PID kill, executable, or cleanup hook is accepted.
Linux containers that do not expose a trustworthy host boot change must retain
quarantine; restarting the service or container is insufficient.

Legacy application records and files are preserved. Existing files and old
successful installer jobs do not become certified generations. Interrupted legacy
jobs create a quarantine lease using the boot observed during migration, requiring
a subsequent verified reboot. The original mutable Bottle is never adopted or
deleted. Existing definitions are not silently rewritten when seeding defaults;
operators can upsert the reviewed updated recipe before a new install.

## Validation scope

Service tests cover cancellation, changed installer hash, missing one of multiple
launchers, retained old selection, rollback/uninstall data retention, interrupted
jobs, unavailable/same/different boot recovery, runtime drift, invalid metadata,
linked launcher paths on Unix, active/uncleared handle conflicts, duplicate root
ownership, normal shutdown reopening, and the generic API. Supervisor and real
Linux installer/GUI acceptance are separate gates. Synthetic boot UUID tests are
state-machine tests, not evidence of a real host reboot.
