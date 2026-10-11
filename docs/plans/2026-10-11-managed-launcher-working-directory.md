# Managed launcher working directory

**Goal:** Repair Artha's managed startup using a reviewed launcher directory confined to its selected generation, then repeat formal application acceptance. The 2026-10-11 heartbeat explicitly authorizes this route.

**Architecture:** Add optional `launchers[].workingDirectory`, relative to that generation's `prefix/drive_c`. Missing fields keep existing runtime/default directory selection and omit serialization, preserving legacy definition digests. Validate portable nonempty normal components; reject absolute paths, traversal, Windows prefixes, missing/non-directory targets and symlinks/reparse points in every ancestor. Resolve only the selected generation's frozen definition. Pass the resolved directory through an in-memory job-specific context for prepare and authorization; never modify daemon configuration, runtime pins, executable digests, historical generations or requests. Existing process directory checks remain the final boundary. This is an existing owned-filesystem boundary, not an atomic defense against a concurrent same-user rename.

**Tech stack:** Rust service/model/lifecycle, existing orchestrator and process supervisor, JSON schema, Linux offline build, existing strict SSH and noVNC GUI.

**Alternatives considered:** A global runtime directory breaks other applications. Shell wrappers and copied GUI resources bypass the application definition. An arbitrary request directory expands the untrusted protocol. A launcher field in the frozen generation is the smallest scoped change.

## Tasks

1. Record fresh complete 221 Core / 75 Store baseline and existing trust/data pins. Reuse clean `fix/managed-msi-install` worktree at cfc9b6c, matching deployed v10.
2. Add failing model tests for explicit directory support, unsafe paths and legacy JSON/digest preservation. Add field, validation and schema.
3. Add real-filesystem tests for generation containment, missing/file/symlink targets, selected frozen definition, installer/default behavior and retained executable digest. Implement resolution and scoped preparation context; recheck before authorization.
4. Run relevant Linux service/orchestrator/process regressions and build a separately named binary from a pinned source archive. Review change before deployment. Preserve the original binary and full state; normal stop/restart only after all tasks are terminal, compare all historical fields and trust afterward.
5. Register a revised Artha definition and install a new generation without rewriting the original failed generation. Run formal managed GUI lookups, history export, normal exit and a new managed process reopening history. Only after these pass create separate acceptance evidence and perform independent local market generation/lifecycle verification. Stop dependent changes on any failed checkpoint.
6. Preserve all old signed files byte-for-byte; append repair/GUI/failure/publication evidence, update actual totals, review and ordinarily commit/push authorized branches. Keep private checkpoints, credentials and signing keys outside Git. Update the existing half-hour heartbeat with actual end state.

## Acceptance boundaries

Artha remains pending and Windows remains 29 until formal GUI and verified local publication complete. Earlier diagnostic copies are not formal acceptance. English lookups and ASCII history are the intended limited scope; advanced functions, Chinese paths/input, full bundled-license closure, guest downloads, new-machine registration, migration and cross-version upgrades remain unverified.
