# macOS Acceptance Acknowledgement Hardening Design

**Date:** 2026-08-22

**Status:** Approved

## Purpose

Close four integration findings before the real Apple Silicon acceptance matrix:

1. remove a tracked developer-specific Python path;
2. replace prefilled interaction booleans with observation-time acknowledgements;
3. make the SumatraPDF installation location independent of ambient user state; and
4. restore the existing Mac-Win workflow contract after adding the macOS acceptance CI job.

This remains developer-local acceptance. It is not a public beta, release, signing, notarization, DMG, or cross-repository modification scope.

## Operator acknowledgement architecture

The interaction example becomes a closed **plan**, not evidence. It names the required checks for each `roundId` and `runtimeId`, but its contents cannot directly produce an accepted application result.

After a GUI application is installed, launched, and its expected window is observed, the GUI runner creates one canonical challenge. Each challenge binds:

- `schemaVersion`;
- `roundId`;
- `runtimeId` and `runtimeVersion`;
- `appId`;
- Runtime Pack digest;
- installer asset digest;
- the exact required interaction names; and
- a fresh random nonce.

The challenge is written create-new, no-follow, and atomically beneath an external acknowledgement root. The runner then waits for a matching acknowledgement with a fixed deadline.

A second-terminal helper starts once and watches the entire run. It validates each challenge, displays the required checks, prompts the operator after the observed interaction, and writes a canonical acknowledgement containing the challenge digest, all bound identity fields, the nonce, and literal `true` values for every required check. It exits only after twelve valid GUI acknowledgements:

- three GUI applications;
- two Runtimes; and
- two rounds.

Console remains automatically verified. The twelve GUI acknowledgements and four Console results form the sixteen acceptance paths.

## Filesystem and process boundaries

The orchestrator accepts two distinct external roots:

- `interaction-plan-root`, which is read-only; and
- `acknowledgement-root`, whose `challenges` subtree is owned by the runner and whose `receipts` subtree is owned by the helper.

All roots and descendants use the existing no-follow, regular-file, bounded-read, identity-revalidation, create-new, and safe-cleanup rules. A challenge or receipt may be consumed once. Replays, duplicate names, unknown fields, stale nonces, wrong digests, linked entries, directory substitution, or post-read identity changes fail closed.

The orchestrator and GUI runner do not read stdin. Unit and CI tests inject deterministic acknowledgement callbacks and nonces. The real helper alone is interactive, in the second terminal selected by the operator.

## Evidence and failure semantics

- A negative operator answer or acknowledgement timeout produces `unverified / application-interaction-unverified` and can never produce `accepted`.
- A malformed, replayed, mismatched, linked, or substituted acknowledgement produces `failed / application-interaction-invalid`.
- An unsafe acknowledgement root or directory identity change is integrity-fatal and stops later applications.
- Application and process-group cleanup remains bounded and mandatory. Cleanup failure remains fatal.
- Partial challenge or receipt files are never accepted and are never overwritten.

Compact evidence contains only the closed interaction booleans derived from a validated acknowledgement. Full external evidence may additionally retain the redacted challenge digest and acknowledgement outcome, but never absolute paths, nonce values, or raw diagnostics in compact stdout.

## Deterministic SumatraPDF installation

SumatraPDF is installed with its officially supported `-d` option into the fixed Bottle path `C:\CompatForge\SumatraPDF`. The reviewed installed executable is therefore `drive_c/CompatForge/SumatraPDF/SumatraPDF.exe`.

The GUI runner removes its ambient `USER` fallback. It does not enumerate or infer Wine profiles. 7-Zip and Notepad++ retain their existing fixed Program Files paths.

Reference: [SumatraPDF installer command-line arguments](https://github.com/sumatrapdfreader/sumatrapdf/blob/master/docs/md/Installer-cmd-line-arguments.md).

## Repository integration closure

The implementation plan replaces the developer-specific Python path with an environment-independent Python 3.11+ placeholder or lookup command. The repository validator reviews the new macOS acceptance planning documents for developer path leakage.

The existing Mac-Win workflow oracle is updated narrowly to recognize the new macOS dual-runtime contract job. Default CI runs that legacy workflow contract so later workflow changes cannot bypass either trust surface.

## Verification

Tests must prove:

- prefilled interaction plans cannot produce accepted evidence;
- acknowledgements are created after their matching challenges and are single-use;
- every identity field, digest, required-check set, and nonce is bound;
- negative answers, timeout, helper interruption, replay, malformed JSON, symlink, hardlink, reparse point, and namespace substitution fail closed;
- the helper handles exactly twelve GUI acknowledgements without blocking CI stdin;
- SumatraPDF installation and lookup work with an empty child environment and reject path drift;
- the legacy Mac-Win workflow contract and the macOS CI contract both pass; and
- repository validator, Python suites, Rust workspace, Tauri tests, clippy, formatting, DCO, LF, and artifact checks remain green.

Only after these checks pass may the branch proceed to the real Mac Tasks 10–12.
