# Phase 2.3 M0 Fresh-Bottle Soak Freeze Design

## Status

- Date: 2026-08-30
- Status: approved for implementation
- Base: `main` at `7c9561257fe21e0c9e077f3046c3b3785c1c30f2`
- Scope: CompatForge only
- Reference Runtime: CrossOver, explicitly selected and identity-bound
- Gate: 60 verified cycles across five certification applications

## Decision Summary

Phase 2.3 M0 will freeze the Phase 2.2 lifecycle evidence before any real
capability probe or Linux Provider work begins. The previous soak stopped after
cycle 23 and contains a hard failure, so it cannot be resumed or cited as passing
evidence. The replacement run starts from a new external output root and uses the
current merged acceptance baseline.

The run will execute the five certification applications through one explicitly
selected CrossOver Runtime for 60 fresh-Bottle cycles. This is 300 application
lifecycle executions. The already completed dual-Runtime acceptance remains the
separate evidence for CrossOver/Whisky parity; M0 does not expand to 120 cycles or
split the required 60 cycles between Runtime identities.

## Boundaries

This work changes only CompatForge. It does not modify or authorize changes to
FOS, ForgeOS, ForgeTools, or Mac-Win. Implementation takes place in the isolated
`agent/phase-2-3-m0-soak-freeze` worktree.

All installers, portable archives, screenshots, raw logs, Runtime materialization,
Bottle state, and soak output remain outside the repository on the Mac host. Git
contains only source, contracts, tests, instructions, and a redacted final report.

This milestone does not:

- constitute a public beta, release, notarization, signing, or distribution gate;
- replace the human interaction attestation required for application acceptance;
- claim Whisky has completed a 60-cycle soak;
- add a real MSI execution path, Linux Provider, .NET/WPF, or D3D probe;
- expand compatibility claims beyond the exact Host, Runtime, backend, asset, and
  test-suite identities recorded by the evidence.

## Fixed Matrix

The soak uses the existing `CERTIFICATION_ASSETS` closed set:

| Application | Guest | Package boundary |
|---|---|---|
| 7-Zip 26.01 x86 | i386 | fixed PE installer |
| VLC 3.0.21 | x86_64 | fixed PE installer |
| WinMerge 2.16.58 x64 | x86_64 | bounded portable ZIP, then PE inspection |
| Audacity 3.7.8 x86 | i386 | fixed PE installer |
| Everything 1.4.1.1032 x86 | i386 | fixed PE installer |

The application set, asset digests, cycle count, test-suite version, and Runtime
selection are immutable for a run. Changing any field requires a new output root.

## Runtime Selection Contract

`tools/run_gui_soak.py` currently delegates Runtime discovery to each invocation
of `tools/run_gui_baseline.py`. That is insufficient for long-run evidence because
candidate ordering could select a different Runtime without changing the soak
configuration.

The soak CLI will require the same closed explicit selection already accepted by
the GUI runner:

```text
--runtime-id crossover
--wine-root /absolute/materialized/runtime/root
--wine relative/wine/entrypoint
--wineserver relative/wineserver/entrypoint
--version fixed-version
```

The quartet is all-or-nothing, `runtime-id` is closed to the existing Runtime ID
set, and M0 documentation invokes it only with `crossover`. Every cycle forwards
the exact same values to the GUI runner.

The soak configuration binds the requested Runtime selection so `--resume` cannot
change the root, entrypoints, version, Runtime ID, applications, cycle count, or
test-suite version. The first verified bootstrap establishes the stable receipt
projection: Runtime ID, Runtime version, architecture, and Runtime Pack digest.
Every subsequent cycle must reproduce that projection. Any drift is an integrity
failure and stops the run before it can be reported as verified.

Absolute Runtime paths may exist in the external local configuration needed for
safe resume, but they must not enter the committed report or the redacted summary
projection.

## Asset Preflight and Network Boundary

The five assets are downloaded, if necessary, in a separate opt-in preflight.
Each cache entry is then checked against the fixed filename, size boundary, and
SHA-256 already declared in `download_gui_assets.py`.

The canary and formal soak do not use `--allow-network`. A missing or invalid
cache entry blocks execution before cycle 1. Network availability therefore
cannot change the meaning of a soak cycle, and a transient download error cannot
be misclassified as an application lifecycle regression.

## Execution Flow

1. Verify the exact source commit, clean worktree, supported Python, Rust gates,
   frontend build, and repository contracts.
2. Verify an interactive, unlocked Apple Silicon desktop and the exact CrossOver
   Runtime descriptor selected for the run.
3. Validate all five cached asset digests without executing an application.
4. Run one five-application canary with the final Runtime selection in a dedicated
   external output root.
5. Inspect the canary's Runtime receipt, application checks, cleanup, screenshots,
   and residual-process evidence. The canary does not count toward the 60 cycles.
6. Create a new empty formal output root and run 60 cycles offline.
7. After every cycle, append one canonical record to `cycles.jsonl`, flush and
   sync it, then atomically replace `summary.json`.
8. Stop at the first non-verified cycle. Never use later success to overwrite or
   dilute an earlier failure.
9. On success, validate all raw evidence and produce a path-free stage report.

The Runtime Store and read-only asset cache may be reused. Each cycle has its own
storage root, work root, screenshots, logs, and fresh application Bottles.

## Resume and Restart Semantics

Resume is allowed only when every committed cycle record is `verified`, the
configuration matches byte-for-byte in meaning, and the stable Runtime receipt
projection still matches. An interrupted partial cycle is moved to the bounded
`aborted` area before the same ordinal is retried.

If a committed cycle is `failed` or `unverified`, that output root is terminal for
gate purposes. After fixing code, Runtime state, assets, or desktop infrastructure,
the operator must create a new empty formal root and restart from cycle 1.

## Classification and Fail-Closed Rules

Each application must contain these six passed lifecycle checks:

- installer inspection;
- target window visible;
- non-empty screenshot;
- lifecycle exit;
- Bottle cleanup;
- no residual processes.

Classification is closed:

- unavailable desktop observation, locking, or screenshot infrastructure is
  `unverified` with `test-infrastructure` and blocks M0 without becoming a product
  regression;
- Runtime, installer, recipe, window, exit, cleanup, or residual failure is a
  hard failure and fails M0;
- absent human functional attestation may remain `policy-blocked` when all six
  lifecycle checks passed and is not a soak hard failure;
- malformed, incomplete, unknown, duplicated, or identity-drifted evidence fails
  closed and stops the run.

## Exit Gate

M0 passes only if all of the following are true:

- `requestedCycles = 60` and `completedCycles = 60`;
- all 60 cycle records are `verified`;
- all 300 application lifecycle projections pass all six required checks;
- `hardFailures = 0`;
- `infrastructureBlocked = 0`;
- every Bottle cleanup succeeds;
- every residual process set is empty;
- all cycles bind the same CrossOver Runtime ID, version, architecture, and Pack
  digest;
- the repository, Python contracts, Rust workspace, frontend, formatting, and
  exact-head remote CI gates pass.

Any other outcome may remain useful Preview or blocked evidence but does not close
M0.

## Test Strategy

Implementation follows test-driven development. Contract tests first establish
red cases for:

- missing, partial, duplicate, or unknown Runtime selection;
- failure to forward the exact Runtime selection into every cycle command;
- resume with a changed Runtime root, entrypoint, version, application set, cycle
  count, or test-suite version;
- first-cycle and later-cycle Runtime receipt mismatch;
- Runtime identity drift after a verified prefix;
- unsafe promotion of `test-infrastructure` or `policy-blocked` evidence;
- absolute Runtime paths leaking into redacted summaries;
- a missing or invalid fixed asset entering a formal offline cycle.

Focused soak tests run after every change. Full repository contract tests, the
macOS acceptance contract suites, Rust fmt/check/test/clippy, the desktop build,
`git diff --check`, and a clean artifact scan run before handoff. Exact-head CI is
required before the Mac formal run is treated as final evidence.

## Documentation Closure

This milestone adds an implementation plan and, after the Mac run, a redacted M0
report. It also adds chronological follow-up notes to existing documents:

- the dual-Runtime acceptance report records that its local changes were reviewed,
  committed, merged, and passed exact-head CI;
- the pinned execution design records how the earlier Whisky blocker was resolved,
  without deleting the original staged finding;
- the Phase 2.3 design marks M0 complete only after the new 60-cycle gate passes.

Once M0 and the already merged M1 minimum contract slice are both complete, the
next design checkpoint is the real x86_64 Win32 capability probe on macOS. Linux,
MSI execution, .NET/WPF, and D3D remain later gated work.
