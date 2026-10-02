# Managed MSI installation implementation

Status: implementation in the isolated `fix/managed-msi-install` worktree under the user's standing rolling installation, repair and local publication authorization. This does not declare a newly accepted application or authorize changing authentication. Server work remains the previously requested design.

## Baseline and scope

Start at Linux generation/debug baseline `8abaae24917e0483c2829ab19aae4b47c37ae62f`. Apply the previously reviewed stage2 profile/preparing delta: all eleven normalized preimages match its recorded pins. The live binary remains `12c0404f79f2d063e2e5e71d42981ebbecd102b5770d363588f1e7c1a4938f62`; no deployment occurs until the combined baseline and new tests pass. This branch also retains newer debug fixes from the canonical Linux branch, so it is not described as a byte-identical live source snapshot. Preserve current selected generations, historical runtime bindings, original configuration, TUF root and failures.

Use the existing rolling MSI design's recommended managed installation path. A typed `PreparedInstall` authorizes a pinned MSI package and the runtime-owned PE `msiexec`, while sharing the existing process supervisor and durable generation lease. Do not interpret MSI as PE, allow arbitrary installer arguments, search PATH for tools, perform host reboot, extract CAB as an installation substitute, or overwrite selected generations.

## Sequential implementation and verification

1. Record baseline tests and source pins. Preserve the deployed inspector's documented validation behavior before rebuilding. Commit baseline integration separately from new MSI behavior.
2. Add failing contract tests for the actual 1,299,197,952-byte JASP package, 2 GiB boundary, booleans, transformed/remote commands and unknown fields. Introduce closed Rust request/handler/package types; update Python and schema together. Initially accept empty properties and a small explicitly validated standard property set, never `TRANSFORMS`, response files or URL-valued properties.
3. Add failing package tests for wrong size/hash/name/architecture, non-installer compound files, source and stored-object substitution, symbolic links and oversized input. Implement bounded streaming immutable staging. Inspect actual MSI installer type and summary architecture with a pinned MSI/compound-file reader; never raise the PE bound.
4. Add failing `PreparedInstall` tests for absent/replaced runtime tool, context/plan/package drift and altered command parameters. Bind trusted msiexec path, digest, architecture and runtime-pack identity; construct only `/i`, staged package, closed UI, reboot suppression and validated properties. Retain immutable package evidence and revalidate it at process spawn.
5. Extend service registration with an optional typed MSI handler/size/architecture, retaining byte-compatible serialization and behavior for existing EXE definitions. Reuse generation staging, runtime binding, preparing ownership, events, cancellation, timeouts and expected-launcher validation. Reboot-required exit is recorded without host reboot; full exit information limitations of Unix Wine must be explicit.
6. Verify all affected Rust/Python/schema contracts on Windows and Linux, including existing generation/debug/appearance/cancellation tests. Review security and lifecycle before deploying to the idle isolated VM. Record backups and source/binary hashes; preserve all historical data and trust.
7. Pin official Qalculate! 5.12.0 x64 MSI, license and SHA-256. Use it as the first smaller real MSI canary. Install through the service, exercise actual GUI arithmetic/unit/matrix or export and reopen workflows. Retain every failure. Later validate the originally blocked JASP CSV analysis/save/reopen workflow; a canary does not claim every MSI works.
8. Only publish a signed local candidate after actual GUI acceptance, verified-cache reinstall/update to a new generation, new-generation workflow, rollback, data preservation and restart persistence. Update ledger/report with distinct candidate/installed/GUI-accepted/published states and verify TUF monotonicity. Completion stays 15/1000 until all app gates pass.

## Sources and limits

- Existing design: `2026-09-30-rolling-msi-integration-design.md` on the PeaZip branch, retained as historical proposed design rather than retroactively changing its approval statement.
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
- https://learn.microsoft.com/en-us/windows/win32/msi/template-summary
- https://docs.rs/msi/0.10.0/msi/struct.Package.html and `SummaryInfo`: inspect installer type and Template Summary architecture. Dependencies and resolved versions must be locked; registry contents are not instructions.
- https://qalculate.github.io/downloads.html and fixed upstream `Qalculate/libqalculate` v5.12.0 release: 70,448,128-byte MSI, SHA-256 `f677d8c3c63c7757e6efc7bee7d4ccded725437194dce94485fc3fb713692e25`.

Build-root free space is approximately 0.74 GB and build-volume free space 4.88 GB. Use expanded fast storage for an isolated source/cache when necessary. Do not delete other build sources, evidence or data. GUI passwords and signing keys remain outside source control.
