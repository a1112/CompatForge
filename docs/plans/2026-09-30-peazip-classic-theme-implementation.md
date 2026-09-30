# PeaZip Classic Theme Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reproduce the verified PeaZip classic-theme workaround in every reviewed managed install generation, then accept and publish the real Windows application.

**Architecture:** Carry a closed optional appearance value from ApplicationDefinition through LaunchRequest into the authorized LaunchPlan. Apply fixed registry commands after Wine bootstrap inside the existing process startup transaction and prefix lease, with bounded supervision and readback. Preserve default serialization, provider defaults, current selected generations and existing TUF trust.

**Tech Stack:** Rust/serde, existing CompatForge process supervisor and Wine 11.14, ForgeStore signed catalogue, Python acceptance evidence helpers and noVNC GUI.

---

### Task 1: Closed profile contract and authorization

Files: `crates/compatforge-domain/src/lib.rs`, `crates/compatforge-service/src/model.rs`, `crates/compatforge-service/src/registry.rs`, `crates/compatforge-service/src/jobs.rs`, `crates/compatforge-orchestrator/src/lib.rs`; fixture constructors in provider/FFI tests.

1. Add serde-based tests using the existing fixture JSON: insert `wineAppearance: "classic"`, deserialize, serialize, and assert the value survives. This should fail with unknown-field rejection before implementation. Also verify absent-field serialization stays exactly equal to the old fixture and unsupported enum values fail.
2. Run `cargo test -p compatforge-domain -p compatforge-service -p compatforge-orchestrator --locked --offline` and retain the expected failing test evidence.
3. Define `WineAppearance::Classic` and default-omitted `Option<WineAppearance>` fields on application/request/plan. Propagate the reviewed application value, compile it into the plan, reject appearance on non-Wine or unmanaged-prefix plans, and preserve deterministic PreparedLaunch reauthorization. Initialize legacy Rust constructors with None.
4. Add authorization tests proving appearance survives and alteration of the prepared profile is rejected. Run the focused packages; verify existing fixtures and definition digests remain unchanged when absent.

### Task 2: Supervised fixed registry configuration

Files: `crates/compatforge-process/src/lib.rs` and its existing startup-transaction tests.

1. Extend the pinned runtime fixture to emulate only the fixed `reg.exe add` and `reg.exe query` operations. Add tests that deserialize a classic plan, then assert registry add/query precede guest spawn; absent profile must issue neither command. Initially the classic workflow should fail until configuration exists.
2. Run `cargo test -p compatforge-process classic_ --locked --offline` and observe failure for missing commands.
3. Add an AppearancePreparation startup stage after Wineboot. Use the authorized pinned runtime, prefix and fixed arguments to write ThemeActive REG_SZ 0, then read back the value. Run commands through existing bounded auxiliary-child/process-tree helpers, revalidate runtime/prefix evidence at spawn, bound output, and fail closed on nonzero, mismatch or timeout. Startup cleanup retains the Wine-session lease until server termination completes.
4. Test failed add, mismatched query, bounded timeout, non-Wine rejection and no guest execution after failure. Run the full process package and relevant supervisor tests.

### Task 3: Deployed-source integration and real GUI regression

Files: isolated build copy `/srv/forge-apps-build/rolling-1000-compatforge-peazip-classic`, ForgeStore evidence/ledger, approved design status.

1. Preserve the actual deployed source baseline and apply the narrow reviewed patch to a new build copy; never replace its existing generation or GUI-idle logic with the older local service.
2. Compile and run domain, service, orchestrator and process tests offline against that source. Export the tested patch and binary hash evidence. Only stage the new CLI after all relevant tests pass and the current managed job is terminal.
3. Upsert the pinned PeaZip definition with classic profile and submit a normal managed install. Verify its new generation has the setting without external registry edits. Launch through the service; inspect Add/Extract/Settings captions and perform ZIP/CRC/byte comparisons for English and Chinese filenames through the GUI. Reproduce and investigate the preserved path guard without disabling it.
4. Confirm normal launch exit and prefix isolation. Preserve failed installation/launch attempts and previous generations.

### Task 4: Signed local market activation and rollback

Files: `ForgeStore/catalogue/candidate-v11/tuf`, `ForgeStore/docs/evidence`, `ForgeStore/docs/windows-1000-progress.json`; private preparation/signing cache only for binaries and signing material.

1. Ensure ForgeStore's reviewed-recipe validation binds the appearance value to signed target metadata; add mismatch tests before changing validation if required.
2. Prepare candidate-v11 using verified candidate-v10 targets plus PeaZip installer and acceptance receipt. Sign metadata version 20 with the existing root; verify signatures and target digests, keeping keys and installer binaries outside git.
3. Observe local market activation and a verified-cache update to a fresh classic generation. Test launch, rollback, service restart, selected-generation identity and retained fixture bytes.
4. Increment distinct accepted count only after all gates pass. Run evidence/ledger consistency checks, staged diff/credential checks, and commit reviewed implementation and evidence.

Execution: continue in this chat under the user's approved design; no additional execution-choice prompt is needed. Existing worktree is `L:/project/FOS/.worktrees/compatforge-peazip-classic` on `fix/peazip-classic-theme`.
