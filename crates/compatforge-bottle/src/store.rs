//! Transactional publication of immutable Bottle versions.
//!
//! Task 7 owns import and active-version binding.  Verification and rollback
//! commands are intentionally kept out of this module until the later task;
//! the import boundary still exposes `verify_active` so a published version
//! can be authenticated by callers before they use it.

use crate::contract::{BottleActiveRef, ImportReceipt, MAX_VERSION_HISTORY, MAX_VERSION_JSON_BYTES};
use crate::snapshot::{BottleSnapshot, SnapshotEntry, MAX_FILE_BYTES, MAX_PATH_DEPTH};
use crate::{BottleMigrationError, BottleMigrationPlan, BottleStore, DiagnosticCode};
use compatforge_domain::{validate_digest, validate_id, SCHEMA_VERSION_V1};
use compatforge_runtime::RuntimePackStore;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const COPY_BUFFER_SIZE: usize = 64 * 1024;
// A materialized version contains at most the snapshot entry bound plus its
// three authenticated root files and a small amount of directory structure.
const MAX_TRANSACTION_ENTRIES: usize = 100_000 + 32;
// Materialized transaction paths add `version/prefix/` in front of the guest
// path.  Keep the guest-facing MAX_PATH_DEPTH contract exact while allowing
// that authenticated store scaffolding to surround a legal deepest entry.
const MAX_TRANSACTION_PATH_DEPTH: usize = MAX_PATH_DEPTH + 2;
const OWNER_MARKER: &[u8] = b"compatforge-bottle-transaction-v1\n";
static IMPORT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportPhase {
    Preflight,
    Staged,
    VersionPublished,
    RefPublished,
}

#[cfg(test)]
thread_local! {
    #[cfg(not(target_os = "macos"))]
    static IMPORT_FAILURE_ORDINAL: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static IMPORT_ORDINAL: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAIL_NEXT_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_WRITE_REPLACEMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    #[cfg(not(target_os = "macos"))]
    static ROLLBACK_FAILURE_ORDINAL: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    #[cfg(not(target_os = "macos"))]
    static ROLLBACK_ORDINAL: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    #[cfg(not(target_os = "macos"))]
    static FAIL_ROLLBACK_POSTCOMMIT_READBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static IMPORT_STAGE_HOOK: std::cell::RefCell<Option<ImportTestHook>> = const { std::cell::RefCell::new(None) };
    static CLEANUP_STAGE_HOOK: std::cell::RefCell<Option<CleanupTestHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct ImportTestHook {
    stage: ImportTestStage,
    hook: Box<dyn FnOnce()>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportTestStage {
    AfterFinalValidation,
}

#[cfg(test)]
fn run_import_test_hook(stage: ImportTestStage) {
    let hook = IMPORT_STAGE_HOOK.with(|slot| {
        let matches = slot.borrow().as_ref().is_some_and(|candidate| candidate.stage == stage);
        matches.then(|| slot.borrow_mut().take().expect("a matching import hook exists").hook)
    });
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
struct CleanupTestHook {
    relative: PathBuf,
    hook: Box<dyn FnOnce()>,
}

#[cfg(test)]
fn run_cleanup_test_hook(relative: &Path) {
    let hook = CLEANUP_STAGE_HOOK.with(|slot| {
        let matches = slot
            .borrow()
            .as_ref()
            .is_some_and(|candidate| candidate.relative == relative);
        matches.then(|| slot.borrow_mut().take().expect("a matching cleanup hook exists").hook)
    });
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_cleanup_test_hook(_relative: &Path) {}

#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn fail_import_at_ordinal(ordinal: usize) {
    IMPORT_FAILURE_ORDINAL.with(|failure| failure.set(Some(ordinal)));
    IMPORT_ORDINAL.with(|current| current.set(0));
}

#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn reset_import_failure() {
    IMPORT_FAILURE_ORDINAL.with(|failure| failure.set(None));
    IMPORT_ORDINAL.with(|current| current.set(0));
}

#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn fail_rollback_at_ordinal(ordinal: usize) {
    ROLLBACK_FAILURE_ORDINAL.with(|failure| failure.set(Some(ordinal)));
    ROLLBACK_ORDINAL.with(|current| current.set(0));
}

#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn reset_rollback_failure() {
    ROLLBACK_FAILURE_ORDINAL.with(|failure| failure.set(None));
    ROLLBACK_ORDINAL.with(|current| current.set(0));
}

#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn fail_rollback_postcommit_readback() {
    FAIL_ROLLBACK_POSTCOMMIT_READBACK.with(|failure| failure.set(true));
}

#[cfg(test)]
pub(crate) fn fail_next_write() {
    FAIL_NEXT_WRITE.with(|failure| failure.set(true));
}

#[cfg(all(test, unix))]
pub(crate) fn fail_next_write_with_replacement() {
    FAIL_NEXT_WRITE.with(|failure| failure.set(true));
    FAIL_NEXT_WRITE_REPLACEMENT.with(|replacement| replacement.set(true));
}

#[cfg(test)]
fn take_write_failure(path: &Path) -> bool {
    if !FAIL_NEXT_WRITE.with(|failure| failure.replace(false)) {
        return false;
    }
    if FAIL_NEXT_WRITE_REPLACEMENT.with(|replacement| replacement.replace(false)) {
        let replacement = path.with_extension("foreign");
        let _ = fs::write(&replacement, b"foreign replacement");
        let _ = fs::remove_file(path);
        let _ = fs::rename(replacement, path);
    }
    true
}

fn checkpoint() -> Result<(), BottleMigrationError> {
    #[cfg(test)]
    {
        let _ordinal = IMPORT_ORDINAL.with(|current| {
            let next = current.get().saturating_add(1);
            current.set(next);
            next
        });
        #[cfg(not(target_os = "macos"))]
        if IMPORT_FAILURE_ORDINAL.with(|failure| failure.get() == Some(_ordinal)) {
            return Err(transaction_failed());
        }
    }
    Ok(())
}

fn rollback_checkpoint() -> Result<(), BottleMigrationError> {
    #[cfg(all(test, not(target_os = "macos")))]
    {
        let ordinal = ROLLBACK_ORDINAL.with(|current| {
            let next = current.get().saturating_add(1);
            current.set(next);
            next
        });
        if ROLLBACK_FAILURE_ORDINAL.with(|failure| failure.get() == Some(ordinal)) {
            return Err(transaction_failed());
        }
    }
    Ok(())
}

impl BottleStore {
    /// Import only after independently re-verifying the Runtime Pack digest
    /// referenced by the plan.  The plain [`import`](Self::import) API remains
    /// useful when the caller has already authenticated the plan's runtime
    /// binding; this wrapper makes that proof explicit at the transaction
    /// boundary.
    pub fn import_with_runtime(
        &self,
        plan: &BottleMigrationPlan,
        runtime_store: &RuntimePackStore,
    ) -> Result<ImportReceipt, BottleMigrationError> {
        plan.validate()?;
        let runtime = runtime_store
            .verified_manifest(&plan.runtime_pack.digest)
            .map_err(|_| runtime_mismatch())?;
        if runtime.id != plan.runtime_pack.id || runtime.digest != plan.runtime_pack.digest {
            return Err(runtime_mismatch());
        }
        self.import(plan)
    }

    /// Materialize one fully authenticated snapshot into an immutable version,
    /// then atomically switch the Bottle's current reference.  The source
    /// Bottle is never opened by this operation.
    pub fn import(&self, plan: &BottleMigrationPlan) -> Result<ImportReceipt, BottleMigrationError> {
        let _guard = IMPORT_LOCK.lock().map_err(|_| transaction_failed())?;
        plan.validate()?;
        validate_id("bottle.id", &plan.bottle.id).map_err(|_| invalid_manifest())?;
        validate_digest("migration.planDigest", &plan.plan_digest).map_err(|_| invalid_manifest())?;
        let snapshot = self.verify_snapshot(&plan.snapshot_digest)?;
        if snapshot.bottle_id != plan.bottle.id {
            return Err(snapshot_corrupt());
        }
        if plan.bottle.runtime_pack != plan.runtime_pack {
            return Err(runtime_mismatch());
        }
        checkpoint()?;

        let manifest_bytes = canonical_json(&plan.bottle).map_err(|_| invalid_manifest())?;
        let migration_bytes = plan.canonical_json()?;
        bounded_bytes(&manifest_bytes)?;
        bounded_bytes(&migration_bytes)?;
        let version_path = self.version_path(&plan.bottle.id, &plan.plan_digest)?;
        let active_path = self.active_path(&plan.bottle.id)?;

        ensure_store_layout(self.root(), &plan.bottle.id)?;
        let current_state = read_active_bytes(&active_path, &plan.bottle.id)?;
        let current = current_state.as_ref().map(|(value, _bytes, _identity)| value.clone());
        if let Some(current) = &current {
            validate_active_version(self, current)?;
        }

        // An already complete version is a no-op candidate.  Verify every
        // byte before trusting it; a same-name unequal tree is a collision.
        if path_exists(&version_path)? {
            if !version_matches(self, &version_path, plan, &snapshot, &manifest_bytes, &migration_bytes)? {
                return Err(target_collision());
            }
            let previous = current.as_ref().map(|value| value.active_plan_digest.clone());
            if previous.as_deref() == Some(plan.plan_digest.as_str()) {
                return Ok(ImportReceipt {
                    schema_version: SCHEMA_VERSION_V1.into(),
                    bottle_id: plan.bottle.id.clone(),
                    plan_digest: plan.plan_digest.clone(),
                    previous_plan_digest: current.and_then(|value| value.history.last().cloned()),
                    activated: false,
                });
            }
        }

        let transaction_root = transaction_path(self.root(), &plan.bottle.id, &plan.plan_digest)?;
        let next_ref = next_active_ref(plan, current.as_ref());
        let ref_bytes = canonical_json(&next_ref).map_err(|_| invalid_manifest())?;
        bounded_bytes(&ref_bytes)?;
        let mut cleanup_expectations =
            transaction_expectations(&snapshot, &manifest_bytes, &migration_bytes, &ref_bytes);
        let transaction_identity = create_transaction(&transaction_root)?;
        bind_cleanup_expectation(&transaction_root, Path::new(".owner"), &mut cleanup_expectations)?;
        let mut phase = ImportPhase::Preflight;
        let result = (|| {
            let staged_version = transaction_root.join("version");
            ensure_dir(&staged_version)?;
            bind_cleanup_expectation(&transaction_root, Path::new("version"), &mut cleanup_expectations)?;
            checkpoint()?;
            materialize_version(
                self,
                &staged_version,
                plan,
                &snapshot,
                &manifest_bytes,
                &migration_bytes,
                &mut cleanup_expectations,
            )?;
            checkpoint()?;
            verify_staged_version(
                self,
                &staged_version,
                plan,
                &snapshot,
                &manifest_bytes,
                &migration_bytes,
            )?;
            checkpoint()?;
            let staged_ref = transaction_root.join("current.json");
            write_new_file(&staged_ref, &ref_bytes)?;
            bind_cleanup_expectation(&transaction_root, Path::new("current.json"), &mut cleanup_expectations)?;
            verify_file_bytes(&staged_ref, &ref_bytes)?;
            phase = ImportPhase::Staged;
            checkpoint()?;

            if !path_exists(&version_path)? {
                checkpoint()?;
                publish_version(&staged_version, &version_path)?;
            } else if !version_matches(self, &version_path, plan, &snapshot, &manifest_bytes, &migration_bytes)? {
                return Err(target_collision());
            }
            phase = ImportPhase::VersionPublished;
            checkpoint()?;

            // Revalidate the complete target while the old ref is still the
            // visible state.  This is the last fallible check before the
            // active-ref replacement (the namespace switch is the commit
            // point).
            checkpoint()?;
            if !version_matches(self, &version_path, plan, &snapshot, &manifest_bytes, &migration_bytes)? {
                return Err(transaction_failed());
            }
            // The test-only hook runs between two independent final
            // validations; the second validation and active-ref readback are
            // intentionally kept immediately before the namespace commit.
            #[cfg(test)]
            run_import_test_hook(ImportTestStage::AfterFinalValidation);
            if !version_matches(self, &version_path, plan, &snapshot, &manifest_bytes, &migration_bytes)? {
                return Err(transaction_failed());
            }
            let latest_state = read_active_bytes(&active_path, &plan.bottle.id).map_err(|_| transaction_failed())?;
            if latest_state != current_state {
                return Err(transaction_failed());
            }
            checkpoint()?;

            checkpoint()?;
            publish_ref(&staged_ref, &active_path)?;
            phase = ImportPhase::RefPublished;
            Ok(ImportReceipt {
                schema_version: SCHEMA_VERSION_V1.into(),
                bottle_id: plan.bottle.id.clone(),
                plan_digest: plan.plan_digest.clone(),
                previous_plan_digest: current.as_ref().map(|value| value.active_plan_digest.clone()),
                activated: true,
            })
        })();

        match result {
            Ok(receipt) => {
                let _ = cleanup_transaction(&transaction_root, transaction_identity, &cleanup_expectations);
                Ok(receipt)
            }
            Err(error) => {
                // Ref publication is the commit point.  Do not report a
                // rollback failure after it: leaving an immutable version is
                // safe, while changing the active pointer again is not.
                if phase != ImportPhase::RefPublished {
                    let _ = cleanup_transaction(&transaction_root, transaction_identity, &cleanup_expectations);
                }
                Err(error)
            }
        }
    }

    /// Return the plan digest selected by the current ref, if any.
    pub fn active_plan(&self, bottle_id: &str) -> Result<Option<String>, BottleMigrationError> {
        validate_id("bottle.id", bottle_id).map_err(|_| invalid_manifest())?;
        let path = self.active_path(bottle_id)?;
        read_active_ref(&path, bottle_id).map(|value| value.map(|value| value.active_plan_digest))
    }

    /// Reauthenticate the current version, its snapshot graph, and all
    /// materialized prefix bytes.  Runtime Pack content can be additionally
    /// checked with [`BottleStore::verify_active_with_runtime`].
    pub fn verify_active(&self, bottle_id: &str) -> Result<(), BottleMigrationError> {
        validate_id("bottle.id", bottle_id).map_err(|_| invalid_manifest())?;
        let active_path = self.active_path(bottle_id)?;
        let active_parent = active_path.parent().ok_or_else(snapshot_corrupt)?;
        verify_directory_chain(active_parent, snapshot_corrupt)?;
        let active = read_active_ref(&active_path, bottle_id)?.ok_or_else(rollback_unavailable)?;
        self.verify_ref_target(bottle_id, &active.active_plan_digest, None)?;
        for digest in &active.history {
            self.verify_ref_target(bottle_id, digest, None)?;
        }
        Ok(())
    }

    /// Verify the exact Runtime Pack object referenced by the active plan.
    pub fn verify_active_with_runtime(
        &self,
        bottle_id: &str,
        runtime_store: &RuntimePackStore,
    ) -> Result<(), BottleMigrationError> {
        validate_id("bottle.id", bottle_id).map_err(|_| invalid_manifest())?;
        let active_path = self.active_path(bottle_id)?;
        let active_parent = active_path.parent().ok_or_else(snapshot_corrupt)?;
        verify_directory_chain(active_parent, snapshot_corrupt)?;
        let active = read_active_ref(&active_path, bottle_id)?.ok_or_else(rollback_unavailable)?;
        self.verify_ref_target(bottle_id, &active.active_plan_digest, Some(runtime_store))?;
        for digest in &active.history {
            self.verify_ref_target(bottle_id, digest, Some(runtime_store))?;
        }
        Ok(())
    }

    /// Verify and reactivate the most recent historical version.  Every byte
    /// reachable from the historical plan is authenticated before staging the
    /// new ref; the active ref is reread immediately before its atomic switch.
    /// A failed verification or staged write never changes the active ref.
    pub fn rollback(&self, bottle_id: &str) -> Result<ImportReceipt, BottleMigrationError> {
        self.rollback_inner(bottle_id, None)
    }

    /// Runtime-bound rollback variant.  In addition to the Bottle graph it
    /// independently verifies the exact Runtime Pack manifest and objects
    /// named by the historical plan before switching the active ref.
    pub fn rollback_with_runtime(
        &self,
        bottle_id: &str,
        runtime_store: &RuntimePackStore,
    ) -> Result<ImportReceipt, BottleMigrationError> {
        self.rollback_inner(bottle_id, Some(runtime_store))
    }

    fn rollback_inner(
        &self,
        bottle_id: &str,
        runtime_store: Option<&RuntimePackStore>,
    ) -> Result<ImportReceipt, BottleMigrationError> {
        let _guard = IMPORT_LOCK.lock().map_err(|_| transaction_failed())?;
        validate_id("bottle.id", bottle_id).map_err(|_| invalid_manifest())?;
        let active_path = self.active_path(bottle_id)?;
        let active_parent = active_path.parent().ok_or_else(rollback_corrupt)?;
        let active_parent_identity = verify_directory_chain(active_parent, rollback_corrupt)?;
        let current_bytes = read_active_bytes(&active_path, bottle_id).map_err(map_rollback_error)?;
        let (current, current_ref_bytes, current_identity) = current_bytes.as_ref().ok_or_else(rollback_unavailable)?;
        let current = current.clone();
        let target_digest = current.history.last().cloned().ok_or_else(rollback_unavailable)?;
        rollback_checkpoint()?;

        // Verify the visible active version as well as the historical target.
        // This prevents a rollback from laundering an already-corrupt current
        // ref and gives callers one fixed corruption diagnostic.
        self.verify_ref_target(bottle_id, &current.active_plan_digest, runtime_store)
            .map_err(map_rollback_error)?;
        rollback_checkpoint()?;
        // Authenticate every retained historical target before selecting the
        // newest one.  A corrupt non-selected history entry must not be
        // silently discarded by a successful rollback.
        let mut target_plan = None;
        for digest in &current.history {
            let plan = self
                .verify_ref_target(bottle_id, digest, runtime_store)
                .map_err(map_rollback_error)?;
            if digest == &target_digest {
                target_plan = Some(plan);
            }
        }
        let target_plan = target_plan.ok_or_else(rollback_corrupt)?;
        rollback_checkpoint()?;

        let next_ref = BottleActiveRef {
            schema_version: SCHEMA_VERSION_V1.into(),
            bottle_id: bottle_id.into(),
            active_plan_digest: target_digest.clone(),
            history: current
                .history
                .iter()
                .take(current.history.len().saturating_sub(1))
                .cloned()
                .collect(),
        };
        next_ref.validate().map_err(map_rollback_error)?;
        let ref_bytes = next_ref.canonical_json().map_err(|_| rollback_corrupt())?;
        bounded_bytes(&ref_bytes).map_err(map_rollback_error)?;
        rollback_checkpoint()?;

        // Use the same owned transaction namespace as import.  No immutable
        // version is rewritten; only the mutable ref is staged and replaced.
        ensure_store_layout(self.root(), bottle_id).map_err(map_rollback_error)?;
        let transaction_root = self.root().join("transactions").join(bottle_id);
        let transaction_identity = create_transaction(&transaction_root).map_err(map_rollback_error)?;
        let transaction_parent = transaction_root.parent().ok_or_else(transaction_failed)?;
        let transaction_parent_identity = verify_directory_chain(transaction_parent, transaction_failed)?;
        let owner_expectation = CleanupExpectation::new(CleanupKind::Bytes(OWNER_MARKER.to_vec()));
        let mut expectations = BTreeMap::from([(PathBuf::from(".owner"), owner_expectation)]);
        bind_cleanup_expectation(&transaction_root, Path::new(".owner"), &mut expectations)
            .map_err(map_rollback_error)?;
        let staged_ref = transaction_root.join("current.json");
        let result = (|| {
            rollback_checkpoint()?;
            write_new_file(&staged_ref, &ref_bytes)?;
            expectations.insert(
                PathBuf::from("current.json"),
                CleanupExpectation::new(CleanupKind::Bytes(ref_bytes.clone())),
            );
            bind_cleanup_expectation(&transaction_root, Path::new("current.json"), &mut expectations)?;
            let staged_identity = expectations
                .get(Path::new("current.json"))
                .and_then(|expectation| expectation.identity)
                .ok_or_else(transaction_failed)?;
            rollback_checkpoint()?;
            verify_owned_bytes(&staged_ref, staged_identity, &ref_bytes)?;
            rollback_checkpoint()?;

            // Re-read and byte-compare the current ref immediately before the
            // replacement.  A same-byte replacement is rejected by identity,
            // not mistaken for our original state.
            let latest = read_active_bytes(&active_path, bottle_id)?;
            let Some((latest_ref, latest_bytes, latest_identity)) = latest else {
                return Err(rollback_corrupt());
            };
            if latest_ref != current || latest_bytes != *current_ref_bytes || latest_identity != *current_identity {
                return Err(rollback_corrupt());
            }
            if verify_directory_chain(active_parent, rollback_corrupt)? != active_parent_identity
                || verify_directory_chain(transaction_parent, transaction_failed)? != transaction_parent_identity
                || cleanup_identity(&transaction_root).map_err(|_| transaction_failed())? != transaction_identity
            {
                return Err(rollback_corrupt());
            }
            rollback_checkpoint()?;
            publish_ref(&staged_ref, &active_path)?;
            // The rename above is the commit point.  Readback is retained as
            // best-effort evidence, but no post-commit failure may turn a
            // successful namespace switch into an error that invites a
            // second rollback attempt against an already changed ref.
            let readback = {
                #[cfg(all(test, not(target_os = "macos")))]
                {
                    if FAIL_ROLLBACK_POSTCOMMIT_READBACK.with(|failure| failure.replace(false)) {
                        Err(transaction_failed())
                    } else {
                        read_active_bytes(&active_path, bottle_id)
                    }
                }
                #[cfg(any(not(test), all(test, target_os = "macos")))]
                {
                    read_active_bytes(&active_path, bottle_id)
                }
            };
            if let Ok(Some((committed_ref, committed_bytes, _))) = readback {
                let _matches = committed_ref == next_ref && committed_bytes == ref_bytes;
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                let _ = cleanup_transaction(&transaction_root, transaction_identity, &expectations);
                let receipt = ImportReceipt {
                    schema_version: SCHEMA_VERSION_V1.into(),
                    bottle_id: bottle_id.into(),
                    plan_digest: target_plan.plan_digest,
                    previous_plan_digest: Some(current.active_plan_digest),
                    activated: true,
                };
                Ok(receipt)
            }
            Err(error) => {
                let _ = cleanup_transaction(&transaction_root, transaction_identity, &expectations);
                Err(map_rollback_error(error))
            }
        }
    }

    fn verify_ref_target(
        &self,
        bottle_id: &str,
        plan_digest: &str,
        runtime_store: Option<&RuntimePackStore>,
    ) -> Result<BottleMigrationPlan, BottleMigrationError> {
        let version = self.version_path(bottle_id, plan_digest)?;
        let version_parent = version.parent().ok_or_else(snapshot_corrupt)?;
        verify_directory_chain(version_parent, snapshot_corrupt)?;
        let version_identity = cleanup_identity(&version).map_err(|_| snapshot_corrupt())?;
        let migration_path = version.join("migration.json");
        let migration_bytes = read_bounded(&migration_path, MAX_VERSION_JSON_BYTES)?;
        let plan: BottleMigrationPlan = parse_closed(&migration_bytes)?;
        plan.validate()?;
        if plan.bottle.id != bottle_id || plan.plan_digest != plan_digest {
            return Err(snapshot_corrupt());
        }
        let expected_migration = plan.canonical_json()?;
        if expected_migration != migration_bytes {
            return Err(snapshot_corrupt());
        }
        let snapshot = self.verify_snapshot(&plan.snapshot_digest)?;
        if snapshot.bottle_id != bottle_id {
            return Err(snapshot_corrupt());
        }
        let manifest_bytes = canonical_json(&plan.bottle).map_err(|_| snapshot_corrupt())?;
        if !version_matches(self, &version, &plan, &snapshot, &manifest_bytes, &expected_migration)? {
            return Err(snapshot_corrupt());
        }
        if let Some(runtime_store) = runtime_store {
            let runtime = runtime_store
                .verified_manifest(&plan.runtime_pack.digest)
                .map_err(|_| runtime_mismatch())?;
            if runtime.id != plan.runtime_pack.id || runtime.digest != plan.runtime_pack.digest {
                return Err(runtime_mismatch());
            }
        }
        if cleanup_identity(&version).map_err(|_| snapshot_corrupt())? != version_identity {
            return Err(snapshot_corrupt());
        }
        Ok(plan)
    }

    fn version_path(&self, bottle_id: &str, plan_digest: &str) -> Result<PathBuf, BottleMigrationError> {
        validate_id("bottle.id", bottle_id).map_err(|_| invalid_manifest())?;
        let hex = digest_hex(plan_digest).ok_or_else(invalid_manifest)?;
        Ok(self.root().join("versions").join(bottle_id).join(hex))
    }

    fn active_path(&self, bottle_id: &str) -> Result<PathBuf, BottleMigrationError> {
        validate_id("bottle.id", bottle_id).map_err(|_| invalid_manifest())?;
        Ok(self.root().join("refs").join(bottle_id).join("current.json"))
    }
}

fn expected_prefix_entries(
    snapshot: &BottleSnapshot,
    manifest_bytes: &[u8],
) -> Result<BTreeMap<String, PrefixEntry>, BottleMigrationError> {
    let mut expected = BTreeMap::new();
    for entry in &snapshot.entries {
        let path = entry_path(entry).to_owned();
        if expected
            .insert(path.clone(), PrefixEntry::from_snapshot(entry))
            .is_some()
        {
            return Err(snapshot_corrupt());
        }
    }
    expected.insert(
        "manifest.json".into(),
        PrefixEntry::Bytes {
            bytes: manifest_bytes.to_vec(),
        },
    );
    Ok(expected)
}

type CleanupIdentity = crate::platform::StableIdentity;

#[derive(Debug, Clone)]
enum CleanupKind {
    Bytes(Vec<u8>),
    Digest { size: u64, digest: String },
    Directory,
    Link { target: String, link_path: String },
}

#[derive(Debug, Clone)]
struct CleanupExpectation {
    kind: CleanupKind,
    identity: Option<CleanupIdentity>,
}

impl CleanupExpectation {
    fn new(kind: CleanupKind) -> Self {
        Self { kind, identity: None }
    }
}

fn transaction_expectations(
    snapshot: &BottleSnapshot,
    manifest_bytes: &[u8],
    migration_bytes: &[u8],
    ref_bytes: &[u8],
) -> BTreeMap<PathBuf, CleanupExpectation> {
    let mut expected = BTreeMap::new();
    expected.insert(
        PathBuf::from(".owner"),
        CleanupExpectation::new(CleanupKind::Bytes(OWNER_MARKER.to_vec())),
    );
    expected.insert(
        PathBuf::from("version/manifest.json"),
        CleanupExpectation::new(CleanupKind::Bytes(manifest_bytes.to_vec())),
    );
    expected.insert(
        PathBuf::from("version/migration.json"),
        CleanupExpectation::new(CleanupKind::Bytes(migration_bytes.to_vec())),
    );
    expected.insert(
        PathBuf::from("version/prefix/manifest.json"),
        CleanupExpectation::new(CleanupKind::Bytes(manifest_bytes.to_vec())),
    );
    expected.insert(
        PathBuf::from("current.json"),
        CleanupExpectation::new(CleanupKind::Bytes(ref_bytes.to_vec())),
    );
    expected.insert(
        PathBuf::from("version"),
        CleanupExpectation::new(CleanupKind::Directory),
    );
    expected.insert(
        PathBuf::from("version/prefix"),
        CleanupExpectation::new(CleanupKind::Directory),
    );
    for entry in &snapshot.entries {
        let relative = entry_path(entry);
        if relative == "manifest.json" {
            continue;
        }
        let path = PathBuf::from("version/prefix").join(relative);
        match entry {
            SnapshotEntry::File { size, digest, .. } => {
                expected.insert(
                    path,
                    CleanupExpectation::new(CleanupKind::Digest {
                        size: *size,
                        digest: digest.clone(),
                    }),
                );
            }
            SnapshotEntry::Directory { .. } => {
                expected.insert(path, CleanupExpectation::new(CleanupKind::Directory));
            }
            SnapshotEntry::Link { target, .. } => {
                expected.insert(
                    path,
                    CleanupExpectation::new(CleanupKind::Link {
                        target: target.clone(),
                        link_path: relative.to_owned(),
                    }),
                );
            }
        }
    }
    expected
}

fn bind_cleanup_expectation(
    transaction_root: &Path,
    relative: &Path,
    expected: &mut BTreeMap<PathBuf, CleanupExpectation>,
) -> Result<(), BottleMigrationError> {
    let Some(expectation) = expected.get_mut(relative) else {
        return Err(transaction_failed());
    };
    if expectation.identity.is_none() {
        let path = transaction_root.join(relative);
        expectation.identity = Some(cleanup_identity(&path).map_err(|_| transaction_failed())?);
    }
    Ok(())
}

fn bind_cleanup_ancestors(
    transaction_root: &Path,
    relative: &Path,
    expected: &mut BTreeMap<PathBuf, CleanupExpectation>,
) -> Result<(), BottleMigrationError> {
    let mut candidate = relative.to_owned();
    loop {
        if expected.contains_key(&candidate) {
            let path = transaction_root.join(&candidate);
            match fs::symlink_metadata(&path) {
                Ok(_) => bind_cleanup_expectation(transaction_root, &candidate, expected)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(transaction_failed()),
            }
        }
        if !candidate.pop() {
            break;
        }
    }
    Ok(())
}

fn cleanup_identity(path: &Path) -> io::Result<CleanupIdentity> {
    crate::platform::stable_path_identity(path)
}

fn materialized_link_target(link_path: &str, target: &str) -> Result<PathBuf, BottleMigrationError> {
    let parent = link_path
        .rsplit_once('/')
        .map_or_else(Vec::new, |(parent, _)| parent.split('/').collect::<Vec<_>>());
    let target = target.split('/').collect::<Vec<_>>();
    let common = parent
        .iter()
        .zip(&target)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in common..parent.len() {
        relative.push("..");
    }
    for component in &target[common..] {
        relative.push(component);
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Ok(relative)
}

fn normalize_link_target(link_path: &str, actual: &Path) -> Result<String, BottleMigrationError> {
    crate::path::normalize_link_target(link_path, actual).map_err(|_| target_collision())
}

#[derive(Debug, Clone)]
enum PrefixEntry {
    Bytes { bytes: Vec<u8> },
    File { size: u64, digest: String },
    Directory,
    Link { target: String },
}

impl PrefixEntry {
    fn from_snapshot(entry: &SnapshotEntry) -> Self {
        match entry {
            SnapshotEntry::File { path, .. } if path == "manifest.json" => Self::Bytes { bytes: Vec::new() },
            SnapshotEntry::File { size, digest, .. } => Self::File {
                size: *size,
                digest: digest.clone(),
            },
            SnapshotEntry::Directory { .. } => Self::Directory,
            SnapshotEntry::Link { target, .. } => Self::Link { target: target.clone() },
        }
    }
}

fn entry_path(entry: &SnapshotEntry) -> &str {
    match entry {
        SnapshotEntry::File { path, .. } | SnapshotEntry::Directory { path } | SnapshotEntry::Link { path, .. } => path,
    }
}

fn materialize_version(
    store: &BottleStore,
    destination: &Path,
    plan: &BottleMigrationPlan,
    snapshot: &BottleSnapshot,
    manifest_bytes: &[u8],
    migration_bytes: &[u8],
    cleanup_expectations: &mut BTreeMap<PathBuf, CleanupExpectation>,
) -> Result<(), BottleMigrationError> {
    ensure_dir(destination)?;
    let transaction_root = destination.parent().ok_or_else(transaction_failed)?;
    let directory_paths = snapshot
        .entries
        .iter()
        .filter_map(|entry| match entry {
            SnapshotEntry::Directory { path } => Some(path.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    bind_cleanup_expectation(transaction_root, Path::new("version"), cleanup_expectations)?;
    checkpoint()?;
    write_new_file(&destination.join("manifest.json"), manifest_bytes)?;
    bind_cleanup_expectation(
        transaction_root,
        Path::new("version/manifest.json"),
        cleanup_expectations,
    )?;
    checkpoint()?;
    write_new_file(&destination.join("migration.json"), migration_bytes)?;
    bind_cleanup_expectation(
        transaction_root,
        Path::new("version/migration.json"),
        cleanup_expectations,
    )?;
    checkpoint()?;
    let prefix = destination.join("prefix");
    ensure_dir(&prefix)?;
    bind_cleanup_expectation(transaction_root, Path::new("version/prefix"), cleanup_expectations)?;
    checkpoint()?;
    write_new_file(&prefix.join("manifest.json"), manifest_bytes)?;
    bind_cleanup_expectation(
        transaction_root,
        Path::new("version/prefix/manifest.json"),
        cleanup_expectations,
    )?;
    checkpoint()?;
    for entry in &snapshot.entries {
        let path = prefix.join(entry_path(entry));
        let relative = PathBuf::from("version/prefix").join(entry_path(entry));
        match entry {
            SnapshotEntry::Directory { .. } => ensure_dir(&path)?,
            SnapshotEntry::Link { target, .. } => {
                ensure_parent(&path)?;
                let target_is_directory = directory_paths.contains(target.as_str());
                let materialized_target = materialized_link_target(entry_path(entry), target)?;
                create_link(&materialized_target, &path, target_is_directory)?;
            }
            SnapshotEntry::File {
                path: relative,
                size,
                digest,
            } => {
                if relative == "manifest.json" {
                    continue;
                }
                let object = store
                    .root()
                    .join("objects")
                    .join("sha256")
                    .join(digest_hex(digest).ok_or_else(snapshot_corrupt)?);
                copy_object(&object, &path, *size, digest)?;
            }
        }
        bind_cleanup_expectation(transaction_root, &relative, cleanup_expectations)?;
        bind_cleanup_ancestors(transaction_root, &relative, cleanup_expectations)?;
        checkpoint()?;
    }
    let mut synced_entries = 0_usize;
    sync_tree(destination, 0, &mut synced_entries)?;
    let _ = plan;
    Ok(())
}

fn verify_staged_version(
    store: &BottleStore,
    version: &Path,
    plan: &BottleMigrationPlan,
    snapshot: &BottleSnapshot,
    manifest_bytes: &[u8],
    migration_bytes: &[u8],
) -> Result<(), BottleMigrationError> {
    verify_version_root(version)?;
    verify_file_bytes(&version.join("manifest.json"), manifest_bytes)?;
    verify_file_bytes(&version.join("migration.json"), migration_bytes)?;
    verify_prefix(store, &version.join("prefix"), snapshot, manifest_bytes)?;
    let _ = plan;
    Ok(())
}

fn version_matches(
    store: &BottleStore,
    version: &Path,
    plan: &BottleMigrationPlan,
    snapshot: &BottleSnapshot,
    manifest_bytes: &[u8],
    migration_bytes: &[u8],
) -> Result<bool, BottleMigrationError> {
    if !is_directory(version)? {
        return Ok(false);
    }
    if verify_staged_version(store, version, plan, snapshot, manifest_bytes, migration_bytes).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn verify_prefix(
    store: &BottleStore,
    prefix: &Path,
    snapshot: &BottleSnapshot,
    manifest_bytes: &[u8],
) -> Result<(), BottleMigrationError> {
    verify_directory_identity(prefix)?;
    let prefix_identity = cleanup_identity(prefix).map_err(|_| target_collision())?;
    let expected = expected_prefix_entries(snapshot, manifest_bytes)?;
    for (relative, entry) in &expected {
        let path = prefix.join(relative);
        match entry {
            PrefixEntry::Bytes { bytes } => verify_file_bytes(&path, bytes)?,
            PrefixEntry::File { size, digest } => verify_file_digest(&path, *size, digest)?,
            PrefixEntry::Directory => {
                verify_directory_identity(&path)?;
            }
            PrefixEntry::Link { target } => {
                let identity = cleanup_identity(&path).map_err(|_| target_collision())?;
                let actual = fs::read_link(&path).map_err(|_| target_collision())?;
                let normalized = normalize_link_target(relative, &actual)?;
                if normalized != *target || cleanup_identity(&path).map_err(|_| target_collision())? != identity {
                    return Err(target_collision());
                }
            }
        }
    }
    let actual = enumerate_tree(prefix)?;
    let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected_paths {
        return Err(target_collision());
    }
    if cleanup_identity(prefix).map_err(|_| target_collision())? != prefix_identity {
        return Err(target_collision());
    }
    let _ = store;
    Ok(())
}

fn verify_version_root(version: &Path) -> Result<(), BottleMigrationError> {
    verify_directory_identity(version)?;
    let version_identity = cleanup_identity(version).map_err(|_| target_collision())?;
    let expected = BTreeSet::from([
        "manifest.json".to_owned(),
        "migration.json".to_owned(),
        "prefix".to_owned(),
    ]);
    if enumerate_children(version)? != expected {
        return Err(target_collision());
    }
    if cleanup_identity(version).map_err(|_| target_collision())? != version_identity {
        return Err(target_collision());
    }
    Ok(())
}

fn verify_directory_identity(path: &Path) -> Result<(), BottleMigrationError> {
    if !is_directory(path)? {
        return Err(target_collision());
    }
    let identity = cleanup_identity(path).map_err(|_| target_collision())?;
    if !is_directory(path)? || cleanup_identity(path).map_err(|_| target_collision())? != identity {
        return Err(target_collision());
    }
    Ok(())
}

/// Bind every directory component of a store path without following a
/// symlink/reparse point.  The returned identity is checked again by callers
/// immediately before publication so a replaced transaction/ref parent is
/// rejected before any namespace switch.
fn verify_directory_chain(
    path: &Path,
    error: fn() -> BottleMigrationError,
) -> Result<CleanupIdentity, BottleMigrationError> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        let metadata = fs::symlink_metadata(candidate).map_err(|_| error())?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(error());
        }
        let parent = candidate.parent();
        current = parent.filter(|value| !value.as_os_str().is_empty() && *value != candidate);
    }
    let identity = cleanup_identity(path).map_err(|_| error())?;
    if cleanup_identity(path).map_err(|_| error())? != identity {
        return Err(error());
    }
    Ok(identity)
}

fn enumerate_children(root: &Path) -> Result<BTreeSet<String>, BottleMigrationError> {
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|_| target_collision())? {
        if paths.len() >= 100_000 {
            return Err(target_collision());
        }
        let name = entry
            .map_err(|_| target_collision())?
            .file_name()
            .to_str()
            .ok_or_else(target_collision)?
            .replace('\\', "/");
        paths.insert(name);
    }
    Ok(paths)
}

fn validate_active_version(store: &BottleStore, current: &BottleActiveRef) -> Result<(), BottleMigrationError> {
    let version = store.version_path(&current.bottle_id, &current.active_plan_digest)?;
    let migration_bytes = read_bounded(&version.join("migration.json"), MAX_VERSION_JSON_BYTES)?;
    let plan: BottleMigrationPlan = parse_closed(&migration_bytes)?;
    plan.validate()?;
    if plan.bottle.id != current.bottle_id || plan.plan_digest != current.active_plan_digest {
        return Err(snapshot_corrupt());
    }
    let snapshot = store.verify_snapshot(&plan.snapshot_digest)?;
    let manifest_bytes = canonical_json(&plan.bottle).map_err(|_| snapshot_corrupt())?;
    if !version_matches(
        store,
        &version,
        &plan,
        &snapshot,
        &manifest_bytes,
        &plan.canonical_json()?,
    )? {
        return Err(snapshot_corrupt());
    }
    Ok(())
}

fn next_active_ref(plan: &BottleMigrationPlan, current: Option<&BottleActiveRef>) -> BottleActiveRef {
    let mut history = current.map_or_else(Vec::new, |value| {
        let mut history = value.history.clone();
        if value.active_plan_digest != plan.plan_digest {
            history.push(value.active_plan_digest.clone());
        }
        history
    });
    history.retain(|digest| digest != &plan.plan_digest);
    if history.len() > MAX_VERSION_HISTORY {
        history.drain(..history.len() - MAX_VERSION_HISTORY);
    }
    BottleActiveRef {
        schema_version: SCHEMA_VERSION_V1.into(),
        bottle_id: plan.bottle.id.clone(),
        active_plan_digest: plan.plan_digest.clone(),
        history,
    }
}

fn ensure_store_layout(root: &Path, bottle_id: &str) -> Result<(), BottleMigrationError> {
    ensure_dir(root)?;
    ensure_dir(&root.join("versions"))?;
    ensure_dir(&root.join("versions").join(bottle_id))?;
    ensure_dir(&root.join("refs"))?;
    ensure_dir(&root.join("refs").join(bottle_id))?;
    ensure_dir(&root.join("transactions"))?;
    Ok(())
}

fn transaction_path(root: &Path, bottle_id: &str, digest: &str) -> Result<PathBuf, BottleMigrationError> {
    // One deterministic lock directory per Bottle prevents two processes
    // importing different plan digests from racing the single mutable ref.
    // The digest is still validated by the caller and remains the version
    // namespace; it is not used to create a second concurrent lock.
    let _ = digest_hex(digest).ok_or_else(invalid_manifest)?;
    Ok(root.join("transactions").join(bottle_id))
}

fn create_transaction(path: &Path) -> Result<CleanupIdentity, BottleMigrationError> {
    match fs::create_dir(path) {
        Ok(()) => {
            let marker = path.join(".owner");
            match write_new_file_with_identity(&marker, OWNER_MARKER) {
                Ok(marker_identity) => match cleanup_identity(path) {
                    Ok(identity) => Ok(identity),
                    Err(_) => {
                        let _ = remove_owned_file(&marker, Some(marker_identity), OWNER_MARKER);
                        let _ = fs::remove_dir(path);
                        Err(transaction_failed())
                    }
                },
                Err((error, marker_identity)) => {
                    let _ = remove_owned_file(&marker, marker_identity, OWNER_MARKER);
                    let _ = fs::remove_dir(path);
                    Err(error)
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(transaction_failed()),
        Err(_) => Err(transaction_failed()),
    }
}

fn remove_owned_file(path: &Path, expected: Option<CleanupIdentity>, expected_bytes: &[u8]) -> io::Result<bool> {
    let Some(expected) = expected else {
        return Ok(false);
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Ok(false);
    }
    if cleanup_identity(path)? != expected {
        return Ok(false);
    }
    if metadata.len() != u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) {
        return Ok(false);
    }
    if fs::read(path)? != expected_bytes {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn publish_version(source: &Path, target: &Path) -> Result<(), BottleMigrationError> {
    ensure_parent(target)?;
    if path_exists(target)? {
        return Err(target_collision());
    }
    rename_noreplace(source, target).map_err(|_| target_collision())
}

fn publish_ref(source: &Path, target: &Path) -> Result<(), BottleMigrationError> {
    ensure_parent(target)?;
    if let Ok(metadata) = fs::symlink_metadata(target) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(target_collision());
        }
    }
    #[cfg(windows)]
    {
        windows_move_file(source, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
            .map_err(|_| transaction_failed())
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, target).map_err(|_| transaction_failed())?;
        // The namespace replacement is the commit point.  Directory sync is
        // best effort after that point: reporting a failure would falsely
        // claim that the old ref is still active when the rename succeeded.
        #[cfg(unix)]
        if let Some(parent) = target.parent() {
            if let Ok(directory) = File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(())
    }
}

fn read_active_ref(path: &Path, bottle_id: &str) -> Result<Option<BottleActiveRef>, BottleMigrationError> {
    read_active_bytes(path, bottle_id).map(|value| value.map(|(active, _, _)| active))
}

fn read_active_bytes(
    path: &Path,
    bottle_id: &str,
) -> Result<Option<(BottleActiveRef, Vec<u8>, CleanupIdentity)>, BottleMigrationError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(snapshot_corrupt()),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(snapshot_corrupt());
    }
    let identity = cleanup_identity(path).map_err(|_| snapshot_corrupt())?;
    let bytes = read_bounded(path, MAX_VERSION_JSON_BYTES)?;
    if cleanup_identity(path).map_err(|_| snapshot_corrupt())? != identity {
        return Err(snapshot_corrupt());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| snapshot_corrupt())?;
    let value = BottleActiveRef::from_json(text).map_err(|_| snapshot_corrupt())?;
    if value.bottle_id != bottle_id {
        return Err(snapshot_corrupt());
    }
    if value.canonical_json().map_err(|_| snapshot_corrupt())? != bytes {
        return Err(snapshot_corrupt());
    }
    Ok(Some((value, bytes, identity)))
}

fn copy_object(
    source: &Path,
    target: &Path,
    expected_size: u64,
    expected_digest: &str,
) -> Result<(), BottleMigrationError> {
    ensure_parent(target)?;
    let mut input = open_regular(source).map_err(|_| snapshot_corrupt())?;
    let metadata = input.metadata().map_err(|_| snapshot_corrupt())?;
    if metadata.len() != expected_size || expected_size > MAX_FILE_BYTES {
        return Err(snapshot_corrupt());
    }
    let mut output = create_new_regular(target).map_err(|_| transaction_failed())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut copied = 0_u64;
    loop {
        let read = input.read(&mut buffer).map_err(|_| snapshot_corrupt())?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| transaction_failed())?)
            .ok_or_else(transaction_failed)?;
        if copied > expected_size || copied > MAX_FILE_BYTES {
            return Err(snapshot_corrupt());
        }
        output.write_all(&buffer[..read]).map_err(|_| transaction_failed())?;
        hasher.update(&buffer[..read]);
    }
    if copied != expected_size || format_digest(hasher.finalize()) != expected_digest {
        return Err(snapshot_corrupt());
    }
    output.sync_all().map_err(|_| transaction_failed())?;
    if input.metadata().map_err(|_| snapshot_corrupt())?.len() != expected_size {
        return Err(snapshot_corrupt());
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), BottleMigrationError> {
    bounded_bytes(bytes)?;
    ensure_parent(path)?;
    let mut file = create_new_regular(path).map_err(|_| transaction_failed())?;
    file.write_all(bytes).map_err(|_| transaction_failed())?;
    file.sync_all().map_err(|_| transaction_failed())?;
    verify_file_bytes(path, bytes)
}

fn write_new_file_with_identity(
    path: &Path,
    bytes: &[u8],
) -> Result<CleanupIdentity, (BottleMigrationError, Option<CleanupIdentity>)> {
    bounded_bytes(bytes).map_err(|error| (error, None))?;
    ensure_parent(path).map_err(|error| (error, None))?;
    let mut file = create_new_regular(path).map_err(|_| (transaction_failed(), None))?;
    let identity = cleanup_identity(path).map_err(|_| (transaction_failed(), None))?;
    file.write_all(bytes)
        .map_err(|_| (transaction_failed(), Some(identity)))?;
    #[cfg(test)]
    if take_write_failure(path) {
        return Err((transaction_failed(), Some(identity)));
    }
    file.sync_all().map_err(|_| (transaction_failed(), Some(identity)))?;
    verify_file_bytes(path, bytes).map_err(|error| (error, Some(identity)))?;
    Ok(identity)
}

fn verify_file_bytes(path: &Path, expected: &[u8]) -> Result<(), BottleMigrationError> {
    let bytes = read_bounded(path, MAX_VERSION_JSON_BYTES.max(expected.len()))?;
    if bytes == expected {
        Ok(())
    } else {
        Err(target_collision())
    }
}

fn verify_owned_bytes(
    path: &Path,
    expected_identity: CleanupIdentity,
    expected: &[u8],
) -> Result<(), BottleMigrationError> {
    if cleanup_identity(path).map_err(|_| transaction_failed())? != expected_identity {
        return Err(transaction_failed());
    }
    verify_file_bytes(path, expected)?;
    if cleanup_identity(path).map_err(|_| transaction_failed())? != expected_identity {
        return Err(transaction_failed());
    }
    Ok(())
}

fn verify_file_digest(path: &Path, expected_size: u64, expected_digest: &str) -> Result<(), BottleMigrationError> {
    let identity = cleanup_identity(path).map_err(|_| target_collision())?;
    let mut file = open_regular(path).map_err(|_| target_collision())?;
    let metadata = file.metadata().map_err(|_| target_collision())?;
    if metadata.len() != expected_size {
        return Err(target_collision());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| target_collision())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| target_collision())?)
            .ok_or_else(target_collision)?;
        if total > expected_size || total > MAX_FILE_BYTES {
            return Err(target_collision());
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size || format_digest(hasher.finalize()) != expected_digest {
        return Err(target_collision());
    }
    if file.metadata().map_err(|_| target_collision())?.len() != expected_size
        || cleanup_identity(path).map_err(|_| target_collision())? != identity
    {
        return Err(target_collision());
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, BottleMigrationError> {
    let before = fs::symlink_metadata(path).map_err(|_| snapshot_corrupt())?;
    if before.file_type().is_symlink() || !before.file_type().is_file() || before.len() > maximum as u64 {
        return Err(snapshot_corrupt());
    }
    let identity = cleanup_identity(path).map_err(|_| snapshot_corrupt())?;
    let mut file = open_regular(path).map_err(|_| snapshot_corrupt())?;
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(maximum).min(maximum));
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = file.read(&mut buffer).map_err(|_| snapshot_corrupt())?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > maximum {
            return Err(snapshot_corrupt());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let after = file.metadata().map_err(|_| snapshot_corrupt())?;
    if after.len() != before.len()
        || bytes.len() as u64 != before.len()
        || cleanup_identity(path).map_err(|_| snapshot_corrupt())? != identity
    {
        return Err(snapshot_corrupt());
    }
    Ok(bytes)
}

fn parse_closed<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BottleMigrationError> {
    bounded_bytes(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| snapshot_corrupt())
}

fn bounded_bytes(bytes: &[u8]) -> Result<(), BottleMigrationError> {
    if bytes.len() > MAX_VERSION_JSON_BYTES || std::str::from_utf8(bytes).is_err() {
        Err(invalid_manifest())
    } else {
        Ok(())
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&canonicalize(&value))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut sorted = serde_json::Map::new();
            for (key, item) in entries {
                sorted.insert(key.clone(), canonicalize(item));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        scalar => scalar.clone(),
    }
}

fn digest_hex(value: &str) -> Option<String> {
    if validate_digest("digest", value).is_err() {
        return None;
    }
    let hex = value.strip_prefix("sha256:")?;
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

fn format_digest(bytes: impl AsRef<[u8]>) -> String {
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing a String cannot fail");
    }
    value
}

fn path_exists(path: &Path) -> Result<bool, BottleMigrationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(transaction_failed()),
    }
}

fn is_directory(path: &Path) -> Result<bool, BottleMigrationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(snapshot_corrupt()),
    }
}

fn ensure_dir(path: &Path) -> Result<(), BottleMigrationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                Err(unsafe_entry())
            } else {
                Ok(())
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(transaction_failed)?;
            ensure_dir(parent)?;
            fs::create_dir(path).map_err(|_| transaction_failed())
        }
        Err(_) => Err(transaction_failed()),
    }
}

fn ensure_parent(path: &Path) -> Result<(), BottleMigrationError> {
    path.parent().ok_or_else(transaction_failed).and_then(ensure_dir)
}

fn create_new_regular(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0x0000_0001)
            .custom_flags(0x0020_0000)
            .open(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        OpenOptions::new().read(true).write(true).create_new(true).open(path)
    }
}

fn open_regular(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0007)
            .custom_flags(0x0020_0000)
            .open(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        File::open(path)
    }
}

struct SyncTreeFrame {
    path: PathBuf,
    depth: usize,
    children: Option<fs::ReadDir>,
}

fn sync_tree(path: &Path, depth: usize, entries_seen: &mut usize) -> Result<(), BottleMigrationError> {
    // Keep the post-order fsync walk on the heap.  Recursive sync over a
    // legal MAX_PATH_DEPTH tree can exhaust the Windows thread stack.
    let mut stack = vec![SyncTreeFrame {
        path: path.to_path_buf(),
        depth,
        children: None,
    }];
    while !stack.is_empty() {
        let index = stack.len().saturating_sub(1);
        if stack[index].children.is_none() {
            if stack[index].depth > MAX_TRANSACTION_PATH_DEPTH || *entries_seen >= MAX_TRANSACTION_ENTRIES {
                return Err(transaction_failed());
            }
            *entries_seen = entries_seen.saturating_add(1);
            let current = stack[index].path.clone();
            let metadata = fs::symlink_metadata(&current).map_err(|_| transaction_failed())?;
            if metadata.file_type().is_symlink() {
                // Snapshot links are already normalized and authenticated.
                // Syncing a link means persisting the directory entry itself;
                // never follow its target during the transaction.
                checkpoint()?;
                stack.pop();
                continue;
            }
            if metadata.file_type().is_dir() {
                stack[index].children = Some(fs::read_dir(&current).map_err(|_| transaction_failed())?);
                continue;
            }
            if metadata.file_type().is_file() {
                #[cfg(unix)]
                File::open(&current)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| transaction_failed())?;
                checkpoint()?;
            }
            stack.pop();
            continue;
        }

        let next = stack[index]
            .children
            .as_mut()
            .expect("directory frame has an iterator")
            .next()
            .transpose()
            .map_err(|_| transaction_failed())?;
        if let Some(entry) = next {
            stack.push(SyncTreeFrame {
                path: entry.path(),
                depth: stack[index].depth.saturating_add(1),
                children: None,
            });
            continue;
        }

        let _frame = stack.pop().expect("non-empty sync stack");
        #[cfg(unix)]
        File::open(&_frame.path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| transaction_failed())?;
        checkpoint()?;
    }
    Ok(())
}

fn enumerate_tree(root: &Path) -> Result<BTreeSet<String>, BottleMigrationError> {
    let mut paths = Vec::new();
    enumerate_tree_owned(root, Path::new(""), &mut paths)?;
    Ok(paths.into_iter().collect())
}

struct EnumerateTreeFrame {
    relative: PathBuf,
    children: fs::ReadDir,
}

fn enumerate_tree_owned(root: &Path, relative: &Path, paths: &mut Vec<String>) -> Result<(), BottleMigrationError> {
    if relative.components().count() > MAX_PATH_DEPTH {
        return Err(target_collision());
    }
    let mut stack = vec![EnumerateTreeFrame {
        relative: relative.to_path_buf(),
        children: fs::read_dir(root).map_err(|_| target_collision())?,
    }];
    while !stack.is_empty() {
        let index = stack.len().saturating_sub(1);
        let next = stack[index]
            .children
            .next()
            .transpose()
            .map_err(|_| target_collision())?;
        let Some(entry) = next else {
            stack.pop();
            continue;
        };
        if paths.len() >= 100_000 {
            return Err(target_collision());
        }
        let name = entry.file_name();
        let child_relative = if stack[index].relative.as_os_str().is_empty() {
            PathBuf::from(&name)
        } else {
            stack[index].relative.join(&name)
        };
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child).map_err(|_| target_collision())?;
        let relative_text = child_relative.to_str().ok_or_else(target_collision)?.replace('\\', "/");
        if child_relative.components().count() > MAX_PATH_DEPTH {
            return Err(target_collision());
        }
        paths.push(relative_text);
        if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            stack.push(EnumerateTreeFrame {
                relative: child_relative,
                children: fs::read_dir(&child).map_err(|_| target_collision())?,
            });
        }
    }
    Ok(())
}

fn create_link(target: &Path, path: &Path, target_is_directory: bool) -> Result<(), BottleMigrationError> {
    #[cfg(unix)]
    {
        let _ = target_is_directory;
        std::os::unix::fs::symlink(target, path).map_err(|_| transaction_failed())
    }
    #[cfg(windows)]
    {
        if target_is_directory {
            std::os::windows::fs::symlink_dir(target, path).map_err(|_| transaction_failed())
        } else {
            std::os::windows::fs::symlink_file(target, path).map_err(|_| transaction_failed())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, path, target_is_directory);
        Err(unsafe_entry())
    }
}

fn cleanup_transaction(
    path: &Path,
    transaction_identity: CleanupIdentity,
    expected: &BTreeMap<PathBuf, CleanupExpectation>,
) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transaction path is not an owned directory",
        ));
    }
    if cleanup_identity(path)? != transaction_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transaction directory identity changed",
        ));
    }
    let mut entries_seen = 0_usize;
    cleanup_transaction_directory(path, Path::new(""), expected, &mut entries_seen)?;
    fs::remove_dir(path)
}

struct CleanupDirectoryFrame {
    path: PathBuf,
    relative: PathBuf,
    identity: CleanupIdentity,
    children: fs::ReadDir,
    pending_child: Option<(PathBuf, CleanupIdentity)>,
}

fn cleanup_transaction_directory(
    root: &Path,
    relative: &Path,
    expected: &BTreeMap<PathBuf, CleanupExpectation>,
    entries_seen: &mut usize,
) -> io::Result<()> {
    if relative.components().count() > MAX_TRANSACTION_PATH_DEPTH || *entries_seen >= MAX_TRANSACTION_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transaction cleanup exceeds its bound",
        ));
    }
    // Keep directory identities on an explicit heap stack.  Recursive
    // cleanup can overflow a Windows thread stack before MAX_PATH_DEPTH is
    // reached; the same identity checks are retained at every descent and
    // before removing a completed child.
    let root_identity = cleanup_identity(root)?;
    let mut stack = vec![CleanupDirectoryFrame {
        path: root.to_path_buf(),
        relative: relative.to_path_buf(),
        identity: root_identity,
        children: fs::read_dir(root)?,
        pending_child: None,
    }];
    while !stack.is_empty() {
        let child = {
            let frame = stack.last_mut().expect("non-empty cleanup stack");
            frame.children.next().transpose()?
        };
        let Some(entry) = child else {
            let _frame = stack.pop().expect("non-empty cleanup stack");
            if let Some(parent) = stack.last_mut() {
                let (child, expected_identity) = parent
                    .pending_child
                    .take()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cleanup child state missing"))?;
                if cleanup_identity(&parent.path)? != parent.identity {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "transaction parent identity changed",
                    ));
                }
                if cleanup_identity(&child)? != expected_identity {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "transaction child identity changed",
                    ));
                }
                fs::remove_dir(child)?;
            }
            continue;
        };
        let frame = stack.last_mut().expect("non-empty cleanup stack");
        if *entries_seen >= MAX_TRANSACTION_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction cleanup exceeds its entry bound",
            ));
        }
        *entries_seen = entries_seen.saturating_add(1);
        let name = entry.file_name();
        let child_relative = if frame.relative.as_os_str().is_empty() {
            PathBuf::from(&name)
        } else {
            frame.relative.join(&name)
        };
        if child_relative.components().count() > MAX_TRANSACTION_PATH_DEPTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction cleanup exceeds its depth bound",
            ));
        }
        let child = entry.path();
        let Some(expectation) = expected.get(&child_relative) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction child is not owned",
            ));
        };
        let expected_identity = expectation
            .identity
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "transaction child identity was not bound"))?;
        if cleanup_identity(&child)? != expected_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction child identity changed",
            ));
        }
        run_cleanup_test_hook(&child_relative);
        // The hook models a concurrent replacement after the first binding.
        // Rebind the child immediately before observing its kind or opening
        // it; otherwise a same-byte foreign file could pass content checks
        // and be removed as if it were still owned.
        if cleanup_identity(&child)? != expected_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction child identity changed",
            ));
        }
        if cleanup_identity(&frame.path)? != frame.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction parent identity changed",
            ));
        }
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_dir() {
            if !matches!(expectation.kind, CleanupKind::Directory) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transaction directory kind changed",
                ));
            }
            frame.pending_child = Some((child.clone(), expected_identity));
            let child_identity = cleanup_identity(&child)?;
            let children = fs::read_dir(&child)?;
            stack.push(CleanupDirectoryFrame {
                path: child,
                relative: child_relative,
                identity: child_identity,
                children,
                pending_child: None,
            });
            continue;
        }
        let owned = match &expectation.kind {
            CleanupKind::Bytes(bytes) => read_bounded(&child, MAX_VERSION_JSON_BYTES)
                .map(|actual| actual == bytes.as_slice())
                .unwrap_or(false),
            CleanupKind::Digest { size, digest } => verify_file_digest(&child, *size, digest).is_ok(),
            CleanupKind::Link { target, link_path } => fs::read_link(&child)
                .and_then(|actual| {
                    normalize_link_target(link_path, &actual)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid transaction link"))
                })
                .map(|actual| actual == *target)
                .unwrap_or(false),
            CleanupKind::Directory => false,
        };
        if !owned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction child identity changed",
            ));
        }
        if cleanup_identity(&child)? != expected_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction child identity changed",
            ));
        }
        fs::remove_file(child)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, target: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    const RENAME_NOREPLACE: u32 = 1;
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: both paths are NUL-free C strings owned for the duration of the
    // syscall; renameat2 does not follow a final symlink in the source and
    // refuses to replace an existing target with RENAME_NOREPLACE.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_noreplace(source: &Path, target: &Path) -> io::Result<()> {
    // MoveFileExW without REPLACE_EXISTING is an atomic no-replace rename on
    // Windows, unlike a check-then-rename sequence that can race a creator.
    windows_move_file(source, target, MOVEFILE_WRITE_THROUGH)
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn rename_noreplace(_source: &Path, _target: &Path) -> io::Result<()> {
    // macOS snapshot creation is intentionally unsupported today; fail closed
    // for any future non-Linux backend until it has an atomic no-replace API.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace rename is unsupported on this platform",
    ))
}

#[cfg(windows)]
const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
#[cfg(windows)]
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

#[cfg(windows)]
fn windows_move_file(source: &Path, target: &Path, flags: u32) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    #[link(name = "Kernel32")]
    extern "system" {
        #[link_name = "MoveFileExW"]
        fn move_file_ex_w(source: *const u16, target: *const u16, flags: u32) -> i32;
    }

    let mut source = source.as_os_str().encode_wide().collect::<Vec<_>>();
    source.push(0);
    let mut target = target.as_os_str().encode_wide().collect::<Vec<_>>();
    target.push(0);
    // SAFETY: both UTF-16 buffers are NUL-terminated and remain alive for the
    // duration of the synchronous Win32 call.
    let result = unsafe { move_file_ex_w(source.as_ptr(), target.as_ptr(), flags) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn invalid_manifest() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::InvalidManifest)
}

fn snapshot_corrupt() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::SnapshotCorrupt)
}

fn unsafe_entry() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::UnsafeEntry)
}

fn runtime_mismatch() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::RuntimeMismatch)
}

fn target_collision() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::TargetCollision)
}

fn transaction_failed() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::TransactionFailed)
}

fn rollback_unavailable() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::RollbackUnavailable)
}

fn rollback_corrupt() -> BottleMigrationError {
    BottleMigrationError::new(DiagnosticCode::RollbackCorrupt)
}

fn map_rollback_error(error: BottleMigrationError) -> BottleMigrationError {
    match error.code() {
        DiagnosticCode::RollbackUnavailable | DiagnosticCode::RollbackCorrupt | DiagnosticCode::TransactionFailed => {
            error
        }
        DiagnosticCode::RuntimeMismatch => error,
        _ => rollback_corrupt(),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "macos"))]
    use super::super::{BottleMigrationPlan, BottleStore, RuntimeMap, RuntimeMapping};
    #[cfg(not(target_os = "macos"))]
    use compatforge_domain::{
        CpuArchitecture, HostOs, RuntimeChannel, RuntimeComponent, RuntimeHost, RuntimePackManifest, SCHEMA_VERSION_V1,
    };
    #[cfg(not(target_os = "macos"))]
    use compatforge_runtime::{sha256_digest_bytes, RejectAllSignatures, RuntimePackStore};
    #[cfg(not(target_os = "macos"))]
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "compatforge-bottle-import-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn setup_case() -> (TemporaryDirectory, BottleStore, RuntimePackStore, BottleMigrationPlan) {
        let temporary = TemporaryDirectory::new("case");
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("drive_c/Example")).unwrap();
        fs::create_dir_all(source.join("icons")).unwrap();
        fs::write(source.join("drive_c/Example/example.exe"), b"fixture executable").unwrap();
        fs::write(source.join("icons/example.png"), b"fixture icon").unwrap();
        let manifest = json!({
            "id": "bottle-fixture",
            "name": "Fixture Bottle",
            "windowsVersion": "win10",
            "arch": "win64",
            "engineId": "wine-9",
            "envOverrides": {"SHARED": "bottle"},
            "installedApps": [{
                "id": "launcher-z",
                "appId": "app-fixture",
                "bottleId": "bottle-fixture",
                "displayName": "Fixture",
                "exePath": "drive_c/Example/example.exe",
                "args": ["--safe"],
                "iconPath": "icons/example.png",
                "envOverrides": {"SHARED": "launcher"},
                "showInHome": true
            }],
            "createdAt": "2026-08-08T00:00:00Z",
            "updatedAt": "2026-08-08T00:00:01Z"
        });
        fs::write(
            source.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let store = BottleStore::new(temporary.path().join("store"));
        let snapshot = store.snapshot(&source).unwrap();

        let bundle = temporary.path().join("runtime-bundle");
        fs::create_dir_all(bundle.join("components")).unwrap();
        let artifact = b"fixture-runtime";
        fs::write(bundle.join("components/runtime.blob"), artifact).unwrap();
        let mut runtime_manifest = RuntimePackManifest {
            schema_version: SCHEMA_VERSION_V1.into(),
            id: "fixture-runtime".into(),
            version: "1.0.0".into(),
            channel: Some(RuntimeChannel::Preview),
            host: RuntimeHost {
                os: HostOs::Linux,
                architecture: CpuArchitecture::X86_64,
                minimum_version: None,
            },
            components: vec![RuntimeComponent {
                name: "runtime".into(),
                version: "1.0.0".into(),
                license: "MIT".into(),
                source: None,
                artifact: Some("components/runtime.blob".into()),
                digest: sha256_digest_bytes(artifact),
                entrypoints: BTreeMap::new(),
            }],
            capabilities: vec!["guest-x86_64".into()],
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            signature: None,
            sbom: None,
        };
        runtime_manifest.digest = sha256_digest_bytes(&runtime_manifest.canonical_unsigned_bytes().unwrap());
        let runtime_store = RuntimePackStore::new(temporary.path().join("runtime-store"));
        runtime_store
            .install(&bundle, &runtime_manifest, &RejectAllSignatures)
            .unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: "fixture-runtime".into(),
            runtime_pack_digest: runtime_manifest.digest,
        }]);
        let plan = store
            .plan(&snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        (temporary, store, runtime_store, plan)
    }

    #[test]
    fn relative_directory_chain_stops_at_the_lexical_root() {
        assert!(super::verify_directory_chain(Path::new("."), super::snapshot_corrupt).is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    fn set_import_hook(stage: super::ImportTestStage, hook: impl FnOnce() + 'static) {
        super::IMPORT_STAGE_HOOK.with(|slot| {
            assert!(slot
                .replace(Some(super::ImportTestHook {
                    stage,
                    hook: Box::new(hook),
                }))
                .is_none());
        });
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn import_publishes_an_immutable_version_and_active_ref() {
        let (_temporary, store, runtime_store, plan) = setup_case();
        let receipt = store.import_with_runtime(&plan, &runtime_store).unwrap();
        assert_eq!(receipt.bottle_id, plan.bottle.id);
        assert_eq!(receipt.plan_digest, plan.plan_digest);
        assert_eq!(
            store.active_plan(&plan.bottle.id).unwrap(),
            Some(plan.plan_digest.clone())
        );
        store.verify_active(&plan.bottle.id).unwrap();

        let version = store
            .root()
            .join("versions")
            .join(&plan.bottle.id)
            .join(plan.plan_digest.trim_start_matches("sha256:"));
        assert!(version.join("manifest.json").is_file());
        assert!(version.join("migration.json").is_file());
        assert!(version.join("prefix/manifest.json").is_file());
        assert!(version.join("prefix/drive_c/Example/example.exe").is_file());
        assert!(!store.root().join("transactions").join("active").exists());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn repeated_identical_import_is_a_true_noop() {
        let (_temporary, store, _runtime_store, plan) = setup_case();
        let first = store.import(&plan).unwrap();
        let version = store
            .root()
            .join("versions")
            .join(&plan.bottle.id)
            .join(plan.plan_digest.trim_start_matches("sha256:"));
        let before = fs::read(version.join("migration.json")).unwrap();
        assert_eq!(
            store.active_plan(&plan.bottle.id).unwrap(),
            Some(plan.plan_digest.clone())
        );
        let second = store.import(&plan).unwrap();
        assert!(first.activated);
        assert!(!second.activated);
        assert_eq!(first.bottle_id, second.bottle_id);
        assert_eq!(first.plan_digest, second.plan_digest);
        assert_eq!(before, fs::read(version.join("migration.json")).unwrap());
        store.verify_active(&plan.bottle.id).unwrap();
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn unequal_preexisting_version_is_a_target_collision_without_ref_change() {
        let (_temporary, store, _runtime_store, plan) = setup_case();
        let version = store
            .root()
            .join("versions")
            .join(&plan.bottle.id)
            .join(plan.plan_digest.trim_start_matches("sha256:"));
        fs::create_dir_all(&version).unwrap();
        fs::write(version.join("manifest.json"), b"foreign").unwrap();

        let error = store.import(&plan).unwrap_err();
        assert_eq!(error.code(), super::super::DiagnosticCode::TargetCollision);
        assert_eq!(store.active_plan(&plan.bottle.id).unwrap(), None);
        assert!(!store.root().join("transactions").join("active").exists());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn adversarial_import_rejects_version_mutation_after_final_validation() {
        let (_temporary, store, _runtime_store, plan) = setup_case();
        let version = store
            .root()
            .join("versions")
            .join(&plan.bottle.id)
            .join(plan.plan_digest.trim_start_matches("sha256:"));
        let raced_version = version.clone();
        set_import_hook(super::ImportTestStage::AfterFinalValidation, move || {
            fs::write(raced_version.join("migration.json"), b"forged-version\n").unwrap();
        });

        let error = store.import(&plan).unwrap_err();

        assert_eq!(error.code(), super::super::DiagnosticCode::TransactionFailed);
        assert_eq!(store.active_plan(&plan.bottle.id).unwrap(), None);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn adversarial_import_rejects_same_bytes_active_ref_replacement_after_final_validation() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        store.import_with_runtime(&first_plan, &runtime_store).unwrap();

        let source_manifest = temporary.path().join("source/manifest.json");
        let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&source_manifest).unwrap()).unwrap();
        changed["updatedAt"] = json!("2026-08-08T00:00:02Z");
        fs::write(&source_manifest, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
        let second_snapshot = store.snapshot(&temporary.path().join("source")).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: "fixture-runtime".into(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let second_plan = store
            .plan(&second_snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        let active_path = store.active_path(&first_plan.bottle.id).unwrap();
        let active_bytes = fs::read(&active_path).unwrap();
        let moved = active_path.with_extension("foreign");
        let active_for_hook = active_path.clone();
        set_import_hook(super::ImportTestStage::AfterFinalValidation, move || {
            fs::rename(&active_for_hook, &moved).unwrap();
            fs::write(&active_for_hook, active_bytes).unwrap();
        });

        let error = store.import(&second_plan).unwrap_err();

        assert_eq!(error.code(), super::super::DiagnosticCode::TransactionFailed);
        assert_eq!(
            store.active_plan(&first_plan.bottle.id).unwrap(),
            Some(first_plan.plan_digest)
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn injected_precommit_failures_leave_source_and_active_ref_unchanged() {
        for ordinal in 1..=128 {
            let (temporary, store, _runtime_store, plan) = setup_case();
            let source_manifest = temporary.path().join("source/manifest.json");
            let before = fs::read(&source_manifest).unwrap();
            super::fail_import_at_ordinal(ordinal);
            let result = store.import(&plan);
            super::reset_import_failure();
            assert_eq!(fs::read(&source_manifest).unwrap(), before);
            match result {
                Ok(receipt) => {
                    assert!(receipt.activated);
                    break;
                }
                Err(error) => {
                    assert_eq!(error.code(), super::super::DiagnosticCode::TransactionFailed);
                    assert_eq!(store.active_plan(&plan.bottle.id).unwrap(), None);
                    let transaction_root = store.root().join("transactions");
                    if transaction_root.exists() {
                        assert_eq!(fs::read_dir(transaction_root).unwrap().count(), 0);
                    }
                }
            }
            if ordinal == 128 {
                panic!("failure injector did not reach a successful ordinal");
            }
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn importing_a_second_plan_preserves_the_previous_active_digest_in_history() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        store.import(&first_plan).unwrap();

        let source_manifest = temporary.path().join("source/manifest.json");
        let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&source_manifest).unwrap()).unwrap();
        changed["updatedAt"] = json!("2026-08-08T00:00:02Z");
        fs::write(&source_manifest, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
        let second_snapshot = store.snapshot(&temporary.path().join("source")).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: "fixture-runtime".into(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let second_plan = store
            .plan(&second_snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        assert_ne!(first_plan.plan_digest, second_plan.plan_digest);
        store.import(&second_plan).unwrap();
        assert_eq!(
            store.active_plan(&first_plan.bottle.id).unwrap(),
            Some(second_plan.plan_digest.clone())
        );
        let active = super::read_active_ref(
            &store.active_path(&first_plan.bottle.id).unwrap(),
            &first_plan.bottle.id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(active.history, vec![first_plan.plan_digest]);
        store.verify_active(&first_plan.bottle.id).unwrap();
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn rollback_reactivates_the_most_recent_verified_history_target() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        store.import_with_runtime(&first_plan, &runtime_store).unwrap();

        let source_manifest = temporary.path().join("source/manifest.json");
        let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&source_manifest).unwrap()).unwrap();
        changed["updatedAt"] = json!("2026-08-08T00:00:02Z");
        fs::write(&source_manifest, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
        let second_snapshot = store.snapshot(&temporary.path().join("source")).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: "fixture-runtime".into(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let second_plan = store
            .plan(&second_snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        store.import_with_runtime(&second_plan, &runtime_store).unwrap();
        assert_eq!(
            store.active_plan(&first_plan.bottle.id).unwrap(),
            Some(second_plan.plan_digest.clone())
        );

        let receipt = store.rollback(&first_plan.bottle.id).unwrap();
        assert_eq!(receipt.bottle_id, first_plan.bottle.id);
        assert_eq!(receipt.plan_digest, first_plan.plan_digest);
        assert_eq!(receipt.previous_plan_digest, Some(second_plan.plan_digest));
        assert!(receipt.activated);
        assert_eq!(
            store.active_plan(&first_plan.bottle.id).unwrap(),
            Some(first_plan.plan_digest)
        );
        store
            .verify_active_with_runtime(&first_plan.bottle.id, &runtime_store)
            .unwrap();
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn rollback_rejects_tampered_history_without_switching_active_ref() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        store.import_with_runtime(&first_plan, &runtime_store).unwrap();
        let source_manifest = temporary.path().join("source/manifest.json");
        let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&source_manifest).unwrap()).unwrap();
        changed["updatedAt"] = json!("2026-08-08T00:00:02Z");
        fs::write(&source_manifest, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
        let second_snapshot = store.snapshot(&temporary.path().join("source")).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: "fixture-runtime".into(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let second_plan = store
            .plan(&second_snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        store.import_with_runtime(&second_plan, &runtime_store).unwrap();

        let history_digest = first_plan.plan_digest.trim_start_matches("sha256:");
        let historical_manifest = store
            .root()
            .join("versions")
            .join(&first_plan.bottle.id)
            .join(history_digest)
            .join("manifest.json");
        fs::write(&historical_manifest, b"tampered").unwrap();
        let active_before = fs::read(store.active_path(&first_plan.bottle.id).unwrap()).unwrap();
        let error = store.rollback(&first_plan.bottle.id).unwrap_err();
        assert_eq!(error.code(), super::super::DiagnosticCode::RollbackCorrupt);
        assert_eq!(
            fs::read(store.active_path(&first_plan.bottle.id).unwrap()).unwrap(),
            active_before
        );
        assert_eq!(
            store.active_plan(&first_plan.bottle.id).unwrap(),
            Some(second_plan.plan_digest)
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn injected_rollback_failures_leave_the_second_active_ref_unchanged() {
        for ordinal in 1..=32 {
            let (temporary, store, runtime_store, first_plan) = setup_case();
            store.import_with_runtime(&first_plan, &runtime_store).unwrap();
            let source_manifest = temporary.path().join("source/manifest.json");
            let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&source_manifest).unwrap()).unwrap();
            changed["updatedAt"] = json!("2026-08-08T00:00:02Z");
            fs::write(&source_manifest, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
            let second_snapshot = store.snapshot(&temporary.path().join("source")).unwrap();
            let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
                legacy_engine_id: "wine-9".into(),
                runtime_pack_id: "fixture-runtime".into(),
                runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
            }]);
            let second_plan = store
                .plan(&second_snapshot.snapshot_digest, &runtime_store, &runtime_map)
                .unwrap();
            store.import_with_runtime(&second_plan, &runtime_store).unwrap();
            let active_path = store.active_path(&first_plan.bottle.id).unwrap();
            let active_before = fs::read(&active_path).unwrap();
            super::fail_rollback_at_ordinal(ordinal);
            let result = store.rollback_with_runtime(&first_plan.bottle.id, &runtime_store);
            super::reset_rollback_failure();
            match result {
                Ok(receipt) => {
                    assert_eq!(receipt.plan_digest, first_plan.plan_digest);
                    assert_eq!(
                        store.active_plan(&first_plan.bottle.id).unwrap(),
                        Some(first_plan.plan_digest)
                    );
                    break;
                }
                Err(error) => {
                    assert_eq!(error.code(), super::super::DiagnosticCode::TransactionFailed);
                    assert_eq!(fs::read(&active_path).unwrap(), active_before);
                    assert_eq!(
                        store.active_plan(&first_plan.bottle.id).unwrap(),
                        Some(second_plan.plan_digest)
                    );
                }
            }
            if ordinal == 32 {
                panic!("rollback failure injector did not reach a successful ordinal");
            }
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn postcommit_ref_readback_failure_does_not_report_a_false_rollback_error() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        store.import_with_runtime(&first_plan, &runtime_store).unwrap();
        let source_manifest = temporary.path().join("source/manifest.json");
        let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&source_manifest).unwrap()).unwrap();
        changed["updatedAt"] = json!("2026-08-08T00:00:02Z");
        fs::write(&source_manifest, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
        let second_snapshot = store.snapshot(&temporary.path().join("source")).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: "fixture-runtime".into(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let second_plan = store
            .plan(&second_snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        store.import_with_runtime(&second_plan, &runtime_store).unwrap();

        super::fail_rollback_postcommit_readback();
        let receipt = store.rollback(&first_plan.bottle.id).unwrap();
        assert_eq!(receipt.plan_digest, first_plan.plan_digest);
        assert_eq!(
            store.active_plan(&first_plan.bottle.id).unwrap(),
            Some(first_plan.plan_digest)
        );
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn safe_snapshot_links_are_materialized_and_verified() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        let source = temporary.path().join("source");
        std::os::unix::fs::symlink("example.exe", source.join("drive_c/Example/alias.exe")).unwrap();
        std::os::unix::fs::symlink(".", source.join("drive_c/Example/parent-link")).unwrap();
        let snapshot = store.snapshot(&source).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: "fixture-runtime".into(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let plan = store
            .plan(&snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();

        let receipt = store.import(&plan).unwrap();
        assert!(receipt.activated);
        let version = store
            .root()
            .join("versions")
            .join(&plan.bottle.id)
            .join(plan.plan_digest.trim_start_matches("sha256:"));
        assert_eq!(
            fs::read_link(version.join("prefix/drive_c/Example/alias.exe")).unwrap(),
            PathBuf::from("example.exe")
        );
        assert_eq!(
            fs::read_link(version.join("prefix/drive_c/Example/parent-link")).unwrap(),
            PathBuf::from(".")
        );
        store.verify_active(&plan.bottle.id).unwrap();
        assert!(!store.root().join("transactions").join("bottle-fixture").exists());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn extra_version_root_entry_is_rejected_instead_of_being_a_noop() {
        let (_temporary, store, _runtime_store, plan) = setup_case();
        store.import(&plan).unwrap();
        let version = store
            .root()
            .join("versions")
            .join(&plan.bottle.id)
            .join(plan.plan_digest.trim_start_matches("sha256:"));
        fs::write(version.join("foreign-extra"), b"foreign").unwrap();

        let verify_error = store.verify_active(&plan.bottle.id).unwrap_err();
        assert_eq!(verify_error.code(), super::super::DiagnosticCode::SnapshotCorrupt);

        fs::remove_file(store.active_path(&plan.bottle.id).unwrap()).unwrap();
        let import_error = store.import(&plan).unwrap_err();
        assert_eq!(import_error.code(), super::super::DiagnosticCode::TargetCollision);
        assert_eq!(fs::read(version.join("foreign-extra")).unwrap(), b"foreign");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn verify_active_rejects_a_legal_but_missing_history_target() {
        let (_temporary, store, _runtime_store, plan) = setup_case();
        store.import(&plan).unwrap();
        let active_path = store.active_path(&plan.bottle.id).unwrap();
        let mut active = super::read_active_ref(&active_path, &plan.bottle.id).unwrap().unwrap();
        // The ref itself remains canonical and contract-valid; only the
        // historical target is unavailable.
        active.history = vec!["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()];
        fs::write(&active_path, active.canonical_json().unwrap()).unwrap();
        let error = store.verify_active(&plan.bottle.id).unwrap_err();
        assert_eq!(error.code(), super::super::DiagnosticCode::SnapshotCorrupt);
    }

    #[test]
    #[cfg(unix)]
    fn cleanup_refuses_same_bytes_replacement_of_an_owned_file() {
        let temporary = TemporaryDirectory::new("cleanup-identity");
        let transaction = temporary.path().join("transaction");
        fs::create_dir_all(&transaction).unwrap();
        let owner = transaction.join(".owner");
        fs::write(&owner, super::OWNER_MARKER).unwrap();
        let transaction_identity = super::cleanup_identity(&transaction).unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(
            PathBuf::from(".owner"),
            super::CleanupExpectation::new(super::CleanupKind::Bytes(super::OWNER_MARKER.to_vec())),
        );
        super::bind_cleanup_expectation(&transaction, Path::new(".owner"), &mut expected).unwrap();

        let replacement = transaction.join("replacement");
        fs::write(&replacement, super::OWNER_MARKER).unwrap();
        fs::rename(&replacement, &owner).unwrap();
        assert!(super::cleanup_transaction(&transaction, transaction_identity, &expected).is_err());
        assert_eq!(fs::read(&owner).unwrap(), super::OWNER_MARKER);
    }

    #[test]
    fn cleanup_rejects_file_substitution_after_child_identity_check() {
        let temporary = TemporaryDirectory::new("cleanup-file-substitution");
        let transaction = temporary.path().join("transaction");
        let owned = transaction.join("owned");
        let moved = temporary.path().join("moved-owned");
        let foreign = temporary.path().join("foreign-owned");
        fs::create_dir_all(&transaction).unwrap();
        fs::write(&owned, b"same bytes").unwrap();
        fs::write(&foreign, b"same bytes").unwrap();
        let transaction_identity = super::cleanup_identity(&transaction).unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(
            PathBuf::from("owned"),
            super::CleanupExpectation::new(super::CleanupKind::Bytes(b"same bytes".to_vec())),
        );
        super::bind_cleanup_expectation(&transaction, Path::new("owned"), &mut expected).unwrap();
        let owned_for_hook = owned.clone();
        let moved_for_hook = moved.clone();
        let foreign_for_hook = foreign.clone();
        super::CLEANUP_STAGE_HOOK.with(|slot| {
            assert!(slot
                .replace(Some(super::CleanupTestHook {
                    relative: PathBuf::from("owned"),
                    hook: Box::new(move || {
                        fs::rename(&owned_for_hook, &moved_for_hook).unwrap();
                        fs::rename(&foreign_for_hook, &owned_for_hook).unwrap();
                    }),
                }))
                .is_none());
        });

        let result = super::cleanup_transaction(&transaction, transaction_identity, &expected);

        assert!(result.is_err(), "cleanup must reject a same-byte foreign replacement");
        assert!(owned.exists(), "the foreign replacement remains reachable");
        assert!(moved.exists(), "the originally owned file is not discarded");
        assert_eq!(fs::read(&owned).unwrap(), b"same bytes");
        assert_eq!(fs::read(&moved).unwrap(), b"same bytes");
    }

    #[test]
    fn adversarial_cleanup_rejects_directory_substitution_after_child_identity_check() {
        let temporary = TemporaryDirectory::new("cleanup-directory-substitution");
        let transaction = temporary.path().join("transaction");
        let version = transaction.join("version");
        let moved = temporary.path().join("moved-version");
        let foreign = temporary.path().join("foreign-version");
        fs::create_dir_all(&transaction).unwrap();
        fs::create_dir(&version).unwrap();
        fs::create_dir(&foreign).unwrap();
        let transaction_identity = super::cleanup_identity(&transaction).unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(
            PathBuf::from("version"),
            super::CleanupExpectation::new(super::CleanupKind::Directory),
        );
        super::bind_cleanup_expectation(&transaction, Path::new("version"), &mut expected).unwrap();
        let version_for_hook = version.clone();
        let moved_for_hook = moved.clone();
        let foreign_for_hook = foreign.clone();
        super::CLEANUP_STAGE_HOOK.with(|slot| {
            assert!(slot
                .replace(Some(super::CleanupTestHook {
                    relative: PathBuf::from("version"),
                    hook: Box::new(move || {
                        fs::rename(&version_for_hook, &moved_for_hook).unwrap();
                        fs::rename(&foreign_for_hook, &version_for_hook).unwrap();
                    }),
                }))
                .is_none());
        });

        let result = super::cleanup_transaction(&transaction, transaction_identity, &expected);

        assert!(result.is_err(), "cleanup must fail closed after parent substitution");
        assert!(version.exists(), "the foreign replacement remains reachable");
        assert!(moved.exists(), "the originally owned directory is not discarded");
    }

    #[test]
    fn cleanup_walks_a_deep_owned_tree_without_recursion_overflow() {
        let temporary = TemporaryDirectory::new("cleanup-deep-tree");
        let transaction = temporary.path().join("transaction");
        fs::create_dir(&transaction).unwrap();
        let mut expected = BTreeMap::new();
        let mut current = transaction.clone();
        let mut relative = PathBuf::new();
        for _ in 0..70 {
            current.push("d");
            relative.push("d");
            fs::create_dir(&current).unwrap();
            expected.insert(
                relative.clone(),
                super::CleanupExpectation::new(super::CleanupKind::Directory),
            );
        }
        for path in expected.keys().cloned().collect::<Vec<_>>() {
            super::bind_cleanup_expectation(&transaction, &path, &mut expected).unwrap();
        }

        let transaction_identity = super::cleanup_identity(&transaction).unwrap();
        super::cleanup_transaction(&transaction, transaction_identity, &expected).unwrap();

        assert!(!transaction.exists());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn import_walks_a_depth_127_tree_without_recursion_overflow() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        let source = temporary.path().join("source");
        let mut nested = source.join("deep");
        for _ in 0..(super::MAX_PATH_DEPTH - 1) {
            fs::create_dir(&nested).unwrap();
            nested.push("d");
        }

        let snapshot = store.snapshot(&source).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: first_plan.runtime_pack.id.clone(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let plan = store
            .plan(&snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        let receipt = store.import_with_runtime(&plan, &runtime_store).unwrap();

        assert!(receipt.activated);
        store.verify_active(&plan.bottle.id).unwrap();
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn import_accepts_the_exact_maximum_guest_depth_without_transaction_residue() {
        let (temporary, store, runtime_store, first_plan) = setup_case();
        let source = temporary.path().join("source");
        let mut nested = source.join("deep");
        for _ in 0..super::MAX_PATH_DEPTH {
            fs::create_dir(&nested).unwrap();
            nested.push("d");
        }

        let snapshot = store.snapshot(&source).unwrap();
        let runtime_map = RuntimeMap::new(vec![RuntimeMapping {
            legacy_engine_id: "wine-9".into(),
            runtime_pack_id: first_plan.runtime_pack.id.clone(),
            runtime_pack_digest: first_plan.runtime_pack.digest.clone(),
        }]);
        let plan = store
            .plan(&snapshot.snapshot_digest, &runtime_store, &runtime_map)
            .unwrap();
        let receipt = store.import_with_runtime(&plan, &runtime_store).unwrap();

        assert!(receipt.activated);
        store.verify_active(&plan.bottle.id).unwrap();
        let transactions = store.root().join("transactions");
        assert_eq!(fs::read_dir(transactions).unwrap().count(), 0);
    }

    #[test]
    fn create_transaction_cleans_a_partially_written_owner_marker() {
        let temporary = TemporaryDirectory::new("transaction-marker-failure");
        let transaction = temporary.path().join("transaction");
        super::fail_next_write();
        assert!(super::create_transaction(&transaction).is_err());
        assert!(!transaction.exists());
    }

    #[test]
    #[cfg(unix)]
    fn create_transaction_never_removes_a_replaced_owner_marker() {
        let temporary = TemporaryDirectory::new("transaction-marker-replacement");
        let transaction = temporary.path().join("transaction");
        super::fail_next_write_with_replacement();
        assert!(super::create_transaction(&transaction).is_err());
        assert!(transaction.exists());
        assert_eq!(fs::read(transaction.join(".owner")).unwrap(), b"foreign replacement");
    }

    #[test]
    fn owned_marker_cleanup_rejects_an_oversized_replacement_before_reading() {
        let temporary = TemporaryDirectory::new("transaction-marker-oversized");
        let marker = temporary.path().join(".owner");
        fs::write(&marker, super::OWNER_MARKER).unwrap();
        let identity = super::cleanup_identity(&marker).unwrap();
        fs::write(&marker, vec![b'x'; super::MAX_VERSION_JSON_BYTES.saturating_add(1)]).unwrap();
        assert!(!super::remove_owned_file(&marker, Some(identity), super::OWNER_MARKER).unwrap());
        assert_eq!(
            fs::metadata(marker).unwrap().len(),
            super::MAX_VERSION_JSON_BYTES as u64 + 1
        );
    }

    #[test]
    fn nested_link_targets_round_trip_from_root_to_parent_relative() {
        let cases = [
            (
                "drive_c/Example/alias.exe",
                "drive_c/Example/example.exe",
                "example.exe",
            ),
            (
                "drive_c/Example/alias.exe",
                "drive_c/Other/example.exe",
                "../Other/example.exe",
            ),
            ("drive_c/Example/alias.exe", "manifest.json", "../../manifest.json"),
            ("drive_c/Example/parent-link", "drive_c/Example", "."),
        ];
        for (link_path, target, expected_raw) in cases {
            let actual = super::materialized_link_target(link_path, target).unwrap();
            assert_eq!(actual, PathBuf::from(expected_raw));
            assert_eq!(super::normalize_link_target(link_path, &actual).unwrap(), target);
        }
    }
}
