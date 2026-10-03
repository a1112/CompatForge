//! Managed application generations. A generation owns a fresh physical Bottle;
//! the application selection and its operation lease commit in one JSON record.

use crate::model::{ApplicationDefinition, JobKind, JobRecord, JobStatus};
use crate::registry::{now_milliseconds, RegistryError};
use compatforge_domain::{
    validate_digest, validate_id, CoreConfig, RuntimeBinding, RuntimeSelection, SCHEMA_VERSION_V1,
};
use compatforge_storage::JsonStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

pub const MAX_GENERATIONS: usize = compatforge_bottle::MAX_VERSION_HISTORY;
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GenerationStatus {
    Staging,
    Ready,
    Failed,
    Cancelled,
    Quarantined,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstalledRuntime {
    pub selection: RuntimeSelection,
    pub binding: RuntimeBinding,
    pub version: String,
}

impl InstalledRuntime {
    pub(crate) fn from_config(config: &CoreConfig, selection: &RuntimeSelection) -> Result<Self, RegistryError> {
        let binding = config
            .runtime_bindings
            .iter()
            .find(|binding| binding.pack_id == selection.pack_id && binding.pack_digest == selection.pack_digest)
            .ok_or(RegistryError::Conflict("installed runtime binding is unavailable"))?;
        let provider = config
            .capabilities
            .runtime_providers
            .iter()
            .find(|provider| {
                provider.id == binding.provider_id && provider.available && provider.kind == selection.provider.as_str()
            })
            .ok_or(RegistryError::Conflict("installed runtime provider is unavailable"))?;
        Ok(Self {
            selection: selection.clone(),
            binding: binding.clone(),
            version: provider.version.clone(),
        })
    }

    pub(crate) fn check_config(&self, config: &CoreConfig) -> Result<(), RegistryError> {
        if Self::from_config(config, &self.selection)? != *self {
            return Err(RegistryError::Conflict(
                "runtime configuration differs from installed generation; restore the pinned runtime",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationGeneration {
    pub id: String,
    pub bottle_id: String,
    pub definition: ApplicationDefinition,
    pub definition_digest: String,
    pub status: GenerationStatus,
    pub created_at_milliseconds: u64,
    pub updated_at_milliseconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<InstalledRuntime>,
    pub launcher_digests: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationOperation {
    pub job_id: String,
    pub generation_id: String,
    pub kind: JobKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationGenerations {
    pub schema_version: String,
    pub application_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_generation: Option<String>,
    pub generations: Vec<ApplicationGeneration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<GenerationOperation>,
    pub recovery_capability: RecoveryCapability,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryCapability {
    KernelBootIdentity,
    Unavailable,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RollbackRequest {
    pub application_id: String,
    pub generation_id: String,
}

pub(crate) struct LifecycleStore {
    root: PathBuf,
    storage_root: PathBuf,
    uncertain: Mutex<BTreeSet<String>>,
}

impl LifecycleStore {
    pub(crate) fn new(root: PathBuf, storage_root: PathBuf) -> Result<Self, RegistryError> {
        ensure_directory(&root)?;
        Ok(Self {
            root,
            storage_root,
            uncertain: Mutex::new(BTreeSet::new()),
        })
    }

    pub(crate) fn state(&self, id: &str) -> Result<ApplicationGenerations, RegistryError> {
        checked_id(id)?;
        if self
            .uncertain
            .lock()
            .map_err(|_| RegistryError::Conflict("lifecycle lock is poisoned"))?
            .contains(id)
        {
            return Err(RegistryError::Conflict(
                "generation commit durability is uncertain; service recovery required",
            ));
        }
        let path = self.root.join(format!("{id}.json"));
        let mut state: ApplicationGenerations = match read_record(&path) {
            Ok(state) => state,
            Err(RegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => ApplicationGenerations {
                schema_version: SCHEMA_VERSION_V1.into(),
                application_id: id.into(),
                selected_generation: None,
                generations: Vec::new(),
                operation: None,
                recovery_capability: RecoveryCapability::Unavailable,
            },
            Err(error) => return Err(error),
        };
        self.validate(&state, id)?;
        state.recovery_capability = if kernel_boot_id().is_some() {
            RecoveryCapability::KernelBootIdentity
        } else {
            RecoveryCapability::Unavailable
        };
        Ok(state)
    }

    fn validate(&self, state: &ApplicationGenerations, id: &str) -> Result<(), RegistryError> {
        if state.schema_version != SCHEMA_VERSION_V1
            || state.application_id != id
            || state.generations.len() > MAX_GENERATIONS
        {
            return Err(RegistryError::Invalid("invalid or oversized generation state"));
        }
        let mut ids = BTreeSet::new();
        for generation in &state.generations {
            checked_id(&generation.id)?;
            if !generation.id.starts_with("gen-job-")
                || !ids.insert(&generation.id)
                || generation.bottle_id != generation.id
                || generation.definition.id != id
            {
                return Err(RegistryError::Invalid("invalid generation identity"));
            }
            // Preserve older terminal failure evidence without permitting that
            // definition to be registered, staged, selected or executed again.
            if matches!(
                generation.status,
                GenerationStatus::Failed | GenerationStatus::Cancelled
            ) {
                generation.definition.validate_retained_failure_metadata()
            } else {
                generation.definition.validate()
            }
            .map_err(RegistryError::Model)?;
            if definition_digest(&generation.definition)? != generation.definition_digest {
                return Err(RegistryError::Invalid("generation definition digest mismatch"));
            }
            if generation.error.as_ref().is_some_and(|error| error.len() > 4096) {
                return Err(RegistryError::Invalid("generation error exceeds bound"));
            }
            if let Some(runtime) = &generation.runtime {
                runtime
                    .binding
                    .validate()
                    .map_err(|error| RegistryError::InvalidOwned(error.to_string()))?;
                if runtime.selection.pack_id != runtime.binding.pack_id
                    || runtime.selection.pack_digest != runtime.binding.pack_digest
                    || runtime.version.is_empty()
                    || runtime.version.len() > 4096
                {
                    return Err(RegistryError::Invalid("invalid generation runtime"));
                }
            }
            if generation.status == GenerationStatus::Ready
                && (generation.runtime.is_none()
                    || generation.launcher_digests.len() != generation.definition.launchers.len())
            {
                return Err(RegistryError::Invalid("ready generation has incomplete evidence"));
            }
            if generation.launcher_digests.len() > crate::model::MAX_LAUNCHERS {
                return Err(RegistryError::Invalid("too many launcher digests"));
            }
            for (launcher, digest) in &generation.launcher_digests {
                if !generation.definition.launchers.iter().any(|item| &item.id == launcher) {
                    return Err(RegistryError::Invalid("unknown verified launcher"));
                }
                validate_digest("launcher.digest", digest)
                    .map_err(|error| RegistryError::InvalidOwned(error.to_string()))?;
            }
        }
        if let Some(selected) = &state.selected_generation {
            if !state
                .generations
                .iter()
                .any(|generation| &generation.id == selected && generation.status == GenerationStatus::Ready)
            {
                return Err(RegistryError::Invalid("selection is not a completed generation"));
            }
        }
        if let Some(operation) = &state.operation {
            checked_id(&operation.job_id)?;
            if !state
                .generations
                .iter()
                .any(|generation| generation.id == operation.generation_id)
                || operation.boot_id.as_ref().is_some_and(|boot| !valid_boot_id(boot))
            {
                return Err(RegistryError::Invalid("invalid generation operation"));
            }
        }
        Ok(())
    }

    fn write(&self, state: &ApplicationGenerations) -> Result<(), RegistryError> {
        self.validate(state, &state.application_id)?;
        let relative = format!("{}.json", state.application_id);
        let path = self.root.join(&relative);
        check_path(&path, true)?;
        if stored_record_size(state)? > MAX_STATE_BYTES {
            return Err(RegistryError::Invalid("generation state exceeds 4 MiB"));
        }
        let previous = self.state(&state.application_id)?;
        let store = JsonStore::new(&self.root);
        if let Err(error) = store.write(&relative, state) {
            // A directory fsync error can follow a visible replacement. Restore
            // the complete old selection and lease; never report activation.
            if matches!(error, compatforge_storage::StoreError::DurabilityUncertain(_))
                && store.write(&relative, &previous).is_err()
            {
                self.uncertain
                    .lock()
                    .map_err(|_| RegistryError::Conflict("lifecycle lock is poisoned"))?
                    .insert(state.application_id.clone());
            }
            return Err(RegistryError::Store(error.to_string()));
        }
        Ok(())
    }

    pub(crate) fn stage(
        &self,
        app: &ApplicationDefinition,
        job_id: &str,
    ) -> Result<ApplicationGeneration, RegistryError> {
        let mut state = self.state(&app.id)?;
        require_idle(&state)?;
        app.validate().map_err(RegistryError::Model)?;
        if app
            .installer
            .as_ref()
            .and_then(|installer| installer.sha256.as_ref())
            .is_none()
        {
            return Err(RegistryError::Invalid(
                "managed installation requires a reviewed installer SHA-256",
            ));
        }
        if state.generations.len() >= MAX_GENERATIONS {
            return Err(RegistryError::Conflict(
                "generation retention limit reached; no data was removed",
            ));
        }
        checked_id(job_id)?;
        let id = format!("gen-{job_id}");
        checked_id(&id)?;
        let root = self.storage_root.join("bottles").join(&id);
        check_path(&root, true)?;
        if root.exists() || state.generations.iter().any(|generation| generation.id == id) {
            return Err(RegistryError::Conflict("generation already exists"));
        }
        let now = now_milliseconds();
        let generation = ApplicationGeneration {
            id: id.clone(),
            bottle_id: id.clone(),
            definition: app.clone(),
            definition_digest: definition_digest(app)?,
            status: GenerationStatus::Staging,
            created_at_milliseconds: now,
            updated_at_milliseconds: now,
            runtime: None,
            launcher_digests: BTreeMap::new(),
            error: None,
        };
        state.generations.push(generation.clone());
        state.operation = Some(GenerationOperation {
            job_id: job_id.into(),
            generation_id: id,
            kind: JobKind::Install,
            boot_id: kernel_boot_id(),
            quarantined: false,
        });
        self.write(&state)?;
        // The durable lease precedes all runtime and prefix effects.
        Ok(generation)
    }

    pub(crate) fn bind_runtime(
        &self,
        app_id: &str,
        job_id: &str,
        runtime: InstalledRuntime,
    ) -> Result<(), RegistryError> {
        let mut state = self.state(app_id)?;
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.job_id == job_id && !operation.quarantined)
            .ok_or(RegistryError::Conflict("generation operation is not owned by this job"))?;
        let generation = state
            .generations
            .iter_mut()
            .find(|generation| generation.id == operation.generation_id)
            .ok_or(RegistryError::NotFound("generation"))?;
        generation.runtime = Some(runtime);
        self.write(&state)
    }

    pub(crate) fn selected(&self, app_id: &str) -> Result<ApplicationGeneration, RegistryError> {
        let state = self.state(app_id)?;
        let selected = state.selected_generation.as_ref().ok_or(RegistryError::Conflict(
            "application has no selected managed generation; install the reviewed recipe",
        ))?;
        state
            .generations
            .iter()
            .find(|generation| &generation.id == selected)
            .cloned()
            .ok_or(RegistryError::NotFound("generation"))
    }

    pub(crate) fn begin_launch(
        &self,
        app_id: &str,
        job_id: &str,
        kind: JobKind,
    ) -> Result<ApplicationGeneration, RegistryError> {
        let mut state = self.state(app_id)?;
        require_idle(&state)?;
        let generation = self.selected(app_id)?;
        self.verify_launchers(&generation)?;
        state.operation = Some(GenerationOperation {
            job_id: job_id.into(),
            generation_id: generation.id.clone(),
            kind,
            boot_id: kernel_boot_id(),
            quarantined: false,
        });
        self.write(&state)?;
        Ok(generation)
    }

    pub(crate) fn finish(&self, job: &JobRecord) -> Result<(), RegistryError> {
        let mut state = self.state(&job.application_id)?;
        let operation = match state.operation.as_ref() {
            Some(operation) if operation.job_id == job.id => operation.clone(),
            None if job.kind != JobKind::Install && job.generation_id.is_none() => return Ok(()), // legacy jobs
            _ => return Err(RegistryError::Conflict("job has no owned generation operation")),
        };
        let generation = state
            .generations
            .iter_mut()
            .find(|generation| generation.id == operation.generation_id)
            .ok_or(RegistryError::NotFound("generation"))?;
        let mut verification_error = None;
        if operation.kind == JobKind::Install {
            if job.status == JobStatus::Succeeded {
                match self.launcher_digests(generation) {
                    Ok(digests) if generation.runtime.is_some() => {
                        generation.launcher_digests = digests;
                        generation.status = GenerationStatus::Ready;
                        state.selected_generation = Some(generation.id.clone());
                    }
                    result => {
                        let error = result
                            .err()
                            .unwrap_or(RegistryError::Invalid("installer runtime binding is absent"));
                        generation.status = GenerationStatus::Failed;
                        generation.error = Some(bounded_error(&error.to_string()));
                        verification_error = Some(error);
                    }
                }
            } else {
                generation.status = if job.status == JobStatus::Cancelled {
                    GenerationStatus::Cancelled
                } else {
                    GenerationStatus::Failed
                };
                generation.error = Some(bounded_error(
                    job.error.as_deref().unwrap_or("installation did not complete"),
                ));
            }
            generation.updated_at_milliseconds = now_milliseconds();
        }
        state.operation = None;
        self.write(&state)?;
        verification_error.map_or(Ok(()), Err)
    }

    pub(crate) fn quarantine(&self, app_id: &str, message: &str) -> Result<(), RegistryError> {
        let mut state = self.state(app_id)?;
        if let Some(operation) = state.operation.as_mut() {
            operation.quarantined = true;
            if operation.kind == JobKind::Install {
                let generation = state
                    .generations
                    .iter_mut()
                    .find(|generation| generation.id == operation.generation_id)
                    .ok_or(RegistryError::NotFound("generation"))?;
                generation.status = GenerationStatus::Quarantined;
                generation.error = Some(bounded_error(message));
                generation.updated_at_milliseconds = now_milliseconds();
            }
            self.write(&state)?;
        }
        Ok(())
    }

    pub(crate) fn quarantine_legacy(
        &self,
        application: &ApplicationDefinition,
        job: &JobRecord,
    ) -> Result<String, RegistryError> {
        let mut state = self.state(&application.id)?;
        if let Some(operation) = &state.operation {
            // Several legacy jobs can have shared one mutable Bottle. One
            // application lease blocks that entire Bottle until the next boot.
            return Ok(operation.generation_id.clone());
        }
        if state.generations.len() >= MAX_GENERATIONS {
            return Err(RegistryError::Conflict(
                "generation retention limit prevents legacy recovery",
            ));
        }
        let id = format!("gen-job-legacy-{:x}", Sha256::digest(job.id.as_bytes()));
        let now = now_milliseconds();
        state.generations.push(ApplicationGeneration {
            id: id.clone(), bottle_id: id.clone(), definition: application.clone(), definition_digest: definition_digest(application)?,
            status: GenerationStatus::Quarantined, created_at_milliseconds: now, updated_at_milliseconds: now,
            runtime: None, launcher_digests: BTreeMap::new(),
            error: Some("legacy interrupted job; original Bottle files were preserved without certification; recovery requires a later host reboot".into()),
        });
        state.operation = Some(GenerationOperation {
            job_id: job.id.clone(),
            generation_id: id.clone(),
            kind: JobKind::Install,
            boot_id: kernel_boot_id(),
            quarantined: true,
        });
        self.write(&state)?;
        Ok(id)
    }

    pub(crate) fn recover(&self, app_id: &str) -> Result<ApplicationGenerations, RegistryError> {
        self.recover_with_boot(app_id, kernel_boot_id().as_deref())
    }

    fn recover_with_boot(&self, app_id: &str, boot: Option<&str>) -> Result<ApplicationGenerations, RegistryError> {
        let mut state = self.state(app_id)?;
        let operation = state
            .operation
            .as_ref()
            .ok_or(RegistryError::Conflict("application has no interrupted operation"))?;
        if !operation.quarantined {
            return Err(RegistryError::Conflict(
                "application operation is still owned by this service",
            ));
        }
        let previous_boot = operation.boot_id.as_deref().ok_or(RegistryError::Conflict(
            "verified crash recovery is unavailable: original kernel boot identity is absent",
        ))?;
        let current_boot = boot.filter(|boot| valid_boot_id(boot)).ok_or(RegistryError::Conflict(
            "verified crash recovery is unavailable on this host; kernel boot identity cannot be read",
        ))?;
        if current_boot == previous_boot {
            return Err(RegistryError::Conflict(
                "runtime exit is unconfirmed; reboot the host, then call applications.recover",
            ));
        }
        if operation.kind == JobKind::Install {
            let generation = state
                .generations
                .iter_mut()
                .find(|generation| generation.id == operation.generation_id)
                .ok_or(RegistryError::NotFound("generation"))?;
            generation.status = GenerationStatus::Failed;
            generation.error =
                Some("interrupted installation abandoned after verified host reboot; files retained".into());
        }
        state.operation = None;
        self.write(&state)?;
        Ok(state)
    }

    pub(crate) fn rollback(&self, request: &RollbackRequest) -> Result<ApplicationGenerations, RegistryError> {
        checked_id(&request.generation_id)?;
        let mut state = self.state(&request.application_id)?;
        require_idle(&state)?;
        let generation = state
            .generations
            .iter()
            .find(|generation| generation.id == request.generation_id && generation.status == GenerationStatus::Ready)
            .ok_or(RegistryError::Conflict(
                "rollback requires a previously completed generation",
            ))?;
        self.verify_launchers(generation)?;
        state.selected_generation = Some(generation.id.clone());
        self.write(&state)?;
        Ok(state)
    }

    pub(crate) fn uninstall(&self, app_id: &str) -> Result<ApplicationGenerations, RegistryError> {
        let mut state = self.state(app_id)?;
        require_idle(&state)?;
        state.selected_generation = None;
        self.write(&state)?;
        Ok(state)
    }

    pub(crate) fn launcher_path(&self, generation: &ApplicationGeneration, executable: &str) -> PathBuf {
        self.storage_root
            .join("bottles")
            .join(&generation.bottle_id)
            .join("prefix/drive_c")
            .join(executable)
    }

    fn launcher_digests(&self, generation: &ApplicationGeneration) -> Result<BTreeMap<String, String>, RegistryError> {
        let mut digests = BTreeMap::new();
        for launcher in &generation.definition.launchers {
            let path = self.launcher_path(generation, &launcher.executable);
            check_path(&path, false)?;
            let inspection = compatforge_inspect::inspect_path(&path).map_err(|error| {
                RegistryError::InvalidOwned(format!("installed launcher {} is invalid: {error}", launcher.id))
            })?;
            digests.insert(launcher.id.clone(), inspection.file_digest);
        }
        Ok(digests)
    }

    pub(crate) fn verify_launchers(&self, generation: &ApplicationGeneration) -> Result<(), RegistryError> {
        if generation.status != GenerationStatus::Ready
            || self.launcher_digests(generation)? != generation.launcher_digests
        {
            return Err(RegistryError::Conflict(
                "installed launcher content differs from verified generation",
            ));
        }
        Ok(())
    }

    pub(crate) fn all_states(&self) -> Result<Vec<ApplicationGenerations>, RegistryError> {
        let mut states = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(RegistryError::Io)? {
            let entry = entry.map_err(RegistryError::Io)?;
            if states.len() >= crate::model::MAX_APPLICATIONS {
                return Err(RegistryError::Invalid("too many lifecycle records"));
            }
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("json") {
                let id = path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .ok_or(RegistryError::Invalid("invalid lifecycle filename"))?;
                states.push(self.state(id)?);
            }
        }
        Ok(states)
    }
}

pub(crate) fn require_idle(state: &ApplicationGenerations) -> Result<(), RegistryError> {
    if state.operation.is_some() {
        Err(RegistryError::Conflict(
            "application has an active or quarantined operation; inspect applications.generations",
        ))
    } else {
        Ok(())
    }
}

fn definition_digest(app: &ApplicationDefinition) -> Result<String, RegistryError> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(app).map_err(RegistryError::Json)?)
    ))
}

pub(crate) fn checked_id(id: &str) -> Result<(), RegistryError> {
    validate_id("id", id).map_err(|error| RegistryError::InvalidOwned(error.to_string()))?;
    if id.len() > 128 || id.ends_with('.') {
        return Err(RegistryError::Invalid("identifier exceeds portable bounds"));
    }
    Ok(())
}

pub(crate) fn bounded_error(message: &str) -> String {
    message.chars().take(1000).collect()
}

pub(crate) fn stored_record_size<T: Serialize>(value: &T) -> Result<u64, RegistryError> {
    // JsonStore persists pretty JSON followed by one newline. Admission must
    // measure that exact encoding so every successful write stays readable.
    Ok(serde_json::to_vec_pretty(value).map_err(RegistryError::Json)?.len() as u64 + 1)
}

pub(crate) fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, RegistryError> {
    check_path(path, false)?;
    let metadata = fs::symlink_metadata(path).map_err(RegistryError::Io)?;
    if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES {
        return Err(RegistryError::Invalid("record is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(RegistryError::Io)?
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(RegistryError::Io)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(RegistryError::Invalid("record exceeds 4 MiB"));
    }
    serde_json::from_slice(&bytes).map_err(RegistryError::Json)
}

pub(crate) fn check_path(path: &Path, allow_missing: bool) -> Result<(), RegistryError> {
    if !path.is_absolute() {
        return Err(RegistryError::Invalid("owned paths must be absolute"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err(RegistryError::Invalid("path contains traversal"));
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                #[cfg(windows)]
                let linked = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & 0x400 != 0
                };
                #[cfg(not(windows))]
                let linked = metadata.file_type().is_symlink();
                if linked {
                    return Err(RegistryError::Conflict(
                        "owned path contains a symbolic link or reparse point",
                    ));
                }
                if current != path && !metadata.is_dir() {
                    return Err(RegistryError::Conflict("owned path ancestor is not a directory"));
                }
            }
            Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RegistryError::Io(error)),
        }
    }
    Ok(())
}

pub(crate) fn ensure_directory(path: &Path) -> Result<(), RegistryError> {
    check_path(path, true)?;
    fs::create_dir_all(path).map_err(RegistryError::Io)?;
    check_path(path, false)?;
    if !path.is_dir() {
        return Err(RegistryError::Conflict("owned directory is not a directory"));
    }
    Ok(())
}

pub(crate) fn acquire_root_lock(root: &Path) -> Result<File, RegistryError> {
    ensure_directory(root)?;
    let path = root.join(".compatforge-service.lock");
    check_path(&path, true)?;
    if path.exists() && !fs::symlink_metadata(&path).map_err(RegistryError::Io)?.is_file() {
        return Err(RegistryError::Conflict("service lock is not a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(RegistryError::Io)?;
    fs4::FileExt::try_lock_exclusive(&file)
        .map_err(|_| RegistryError::Conflict("service or storage root is already owned by another service"))?;
    Ok(file)
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn kernel_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let mut bytes = Vec::new();
        File::open("/proc/sys/kernel/random/boot_id")
            .ok()?
            .take(38)
            .read_to_end(&mut bytes)
            .ok()?;
        let boot = std::str::from_utf8(&bytes).ok()?.trim();
        if valid_boot_id(boot) {
            return Some(boot.into());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    const BOOT_A: &str = "11111111-1111-1111-1111-111111111111";
    const BOOT_B: &str = "22222222-2222-2222-2222-222222222222";

    fn fixture() -> (LifecycleStore, ApplicationDefinition, InstalledRuntime) {
        let root = std::env::temp_dir().join(format!(
            "compatforge-generation-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = LifecycleStore::new(root.join("service/generations"), root.join("storage")).unwrap();
        let config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let binding = config.runtime_bindings[0].clone();
        let runtime = InstalledRuntime::from_config(
            &config,
            &RuntimeSelection {
                provider: compatforge_domain::RuntimeKind::Wine,
                pack_id: binding.pack_id.clone(),
                pack_digest: binding.pack_digest.clone(),
            },
        )
        .unwrap();
        let app: ApplicationDefinition = serde_json::from_value(serde_json::json!({
            "schemaVersion":"1", "id":"example-app", "name":"Example", "version":"1.0", "publisher":"Example", "category":"utility", "bottleId":"example-bottle",
            "installer":{"fileName":"setup.exe","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},
            "launchers":[{"id":"main","name":"Main","executable":"Program Files/Example/main.exe"},{"id":"helper","name":"Helper","executable":"Program Files/Example/helper.exe"}]
        })).unwrap();
        (store, app, runtime)
    }

    fn job(app: &ApplicationDefinition, id: &str, status: JobStatus) -> JobRecord {
        serde_json::from_value(serde_json::json!({"schemaVersion":"1", "id":id,"applicationId":app.id,"generationId":format!("gen-{id}"), "kind":"install","status":status,"createdAtMilliseconds":1,"updatedAtMilliseconds":1})).unwrap()
    }

    fn stage(
        store: &LifecycleStore,
        app: &ApplicationDefinition,
        runtime: &InstalledRuntime,
        id: &str,
    ) -> ApplicationGeneration {
        let generation = store.stage(app, id).unwrap();
        store.bind_runtime(&app.id, id, runtime.clone()).unwrap();
        generation
    }

    fn launchers(store: &LifecycleStore, generation: &ApplicationGeneration, count: usize) {
        for launcher in generation.definition.launchers.iter().take(count) {
            let path = store.launcher_path(generation, &launcher.executable);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, include_bytes!("../../../tests/fixtures/hello-x86_64.exe")).unwrap();
        }
    }

    fn installed(
        store: &LifecycleStore,
        app: &ApplicationDefinition,
        runtime: &InstalledRuntime,
        id: &str,
    ) -> ApplicationGeneration {
        let generation = stage(store, app, runtime, id);
        launchers(store, &generation, 2);
        store.finish(&job(app, id, JobStatus::Succeeded)).unwrap();
        store.selected(&app.id).unwrap()
    }

    #[test]
    fn oversized_pretty_generation_preserves_previous_selection_and_metadata() {
        let (store, mut app, runtime) = fixture();
        app.launchers.truncate(1);
        app.launchers[0].arguments = vec!["x".repeat(500); crate::model::MAX_ARGUMENTS];
        app.validate().unwrap();
        let selected = installed(&store, &app, &runtime, "job-old");
        let mut previous = store.state(&app.id).unwrap();
        for index in 1..MAX_GENERATIONS - 1 {
            let mut generation = selected.clone();
            generation.id = format!("gen-job-retained-{index}");
            generation.bottle_id = generation.id.clone();
            previous.generations.push(generation);
        }
        store.write(&previous).unwrap();
        let path = store.root.join(format!("{}.json", app.id));
        let original = fs::read(&path).unwrap();
        let mut oversized = previous.clone();
        let mut generation = selected.clone();
        generation.id = "gen-job-next".into();
        generation.bottle_id = generation.id.clone();
        oversized.generations.push(generation);
        store.validate(&oversized, &app.id).unwrap();
        assert!(serde_json::to_vec(&oversized).unwrap().len() as u64 <= MAX_STATE_BYTES);
        assert!(serde_json::to_vec_pretty(&oversized).unwrap().len() as u64 + 1 > MAX_STATE_BYTES);
        assert!(store.stage(&app, "job-next").is_err());
        assert_eq!(fs::read(path).unwrap(), original);
        assert_eq!(store.selected(&app.id).unwrap(), selected);
        let reopened = LifecycleStore::new(store.root.clone(), store.storage_root.clone()).unwrap();
        assert_eq!(reopened.state(&app.id).unwrap(), previous);
        assert_eq!(reopened.all_states().unwrap(), vec![previous]);
    }

    #[test]
    fn retained_failed_msi_space_override_remains_readable_but_cannot_execute() {
        let (store, app, runtime) = fixture();
        let old = installed(&store, &app, &runtime, "job-old");
        let mut state = store.state(&app.id).unwrap();
        let mut failed = old.clone();
        failed.id = "gen-job-space-failure".into();
        failed.bottle_id = failed.id.clone();
        failed.status = GenerationStatus::Failed;
        failed.launcher_digests.clear();
        failed.definition.installer = Some(
            serde_json::from_value(serde_json::json!({
                "fileName":"canary.msi", "sha256":"a".repeat(64),
                "msi":{"architecture":"x86_64", "sizeBytes":100, "maximumRuntimeMilliseconds":120000,
                    "handler":{"kind":"msiexec", "action":"install", "ui":"none", "reboot":"suppress",
                        "properties":{"TARGETDIR":"C:\\Qalculate Canary"}}}
            }))
            .unwrap(),
        );
        failed.definition_digest = definition_digest(&failed.definition).unwrap();
        state.generations.push(failed.clone());
        let path = store.root.join(format!("{}.json", app.id));
        fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        let bytes = fs::read(&path).unwrap();
        let reopened = LifecycleStore::new(store.root.clone(), store.storage_root.clone()).unwrap();
        assert_eq!(reopened.state(&app.id).unwrap().generations, state.generations);
        assert_eq!(reopened.selected(&app.id).unwrap(), old);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(failed.definition.validate().is_err());
        assert!(reopened.stage(&failed.definition, "job-new").is_err());
        assert!(reopened
            .rollback(&RollbackRequest {
                application_id: app.id.clone(),
                generation_id: failed.id.clone()
            })
            .is_err());
        failed.status = GenerationStatus::Ready;
        state.generations[1] = failed;
        assert!(reopened.write(&state).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn missing_one_launcher_and_cancellation_retain_old_selection() {
        let (store, app, runtime) = fixture();
        let old = installed(&store, &app, &runtime, "job-old");
        let update = stage(&store, &app, &runtime, "job-update");
        launchers(&store, &update, 1);
        assert!(store.finish(&job(&app, "job-update", JobStatus::Succeeded)).is_err());
        assert_eq!(store.selected(&app.id).unwrap(), old);
        let cancelled = stage(&store, &app, &runtime, "job-cancel");
        launchers(&store, &cancelled, 2);
        store.finish(&job(&app, "job-cancel", JobStatus::Cancelled)).unwrap();
        assert_eq!(store.selected(&app.id).unwrap(), old);
        assert_eq!(
            store.state(&app.id).unwrap().generations[2].status,
            GenerationStatus::Cancelled
        );
    }

    #[test]
    fn rollback_uninstall_keep_generations_and_personal_files() {
        let (store, app, runtime) = fixture();
        let old = installed(&store, &app, &runtime, "job-old");
        let data = store.launcher_path(&old, "users/person/Documents/private.txt");
        fs::create_dir_all(data.parent().unwrap()).unwrap();
        fs::write(&data, b"personal data").unwrap();
        let mut update = app.clone();
        update.version = "2.0".into();
        let new = installed(&store, &update, &runtime, "job-new");
        store
            .rollback(&RollbackRequest {
                application_id: app.id.clone(),
                generation_id: old.id.clone(),
            })
            .unwrap();
        assert_eq!(store.selected(&app.id).unwrap().definition.version, "1.0");
        let state = store.uninstall(&app.id).unwrap();
        assert!(state.selected_generation.is_none());
        assert_eq!(state.generations.len(), 2);
        assert_eq!(fs::read(data).unwrap(), b"personal data");
        assert!(store
            .launcher_path(&new, &new.definition.launchers[0].executable)
            .is_file());
        store
            .rollback(&RollbackRequest {
                application_id: app.id.clone(),
                generation_id: old.id,
            })
            .unwrap();
        assert_eq!(store.selected(&app.id).unwrap().definition.version, "1.0");
    }

    #[test]
    fn interrupted_install_blocks_mutations_until_different_verified_boot() {
        let (store, app, runtime) = fixture();
        let old = installed(&store, &app, &runtime, "job-old");
        let new = stage(&store, &app, &runtime, "job-interrupted");
        launchers(&store, &new, 2);
        let mut state = store.state(&app.id).unwrap();
        state.operation.as_mut().unwrap().boot_id = Some(BOOT_A.into());
        store.write(&state).unwrap();
        store.quarantine(&app.id, "interrupted").unwrap();
        assert!(store.uninstall(&app.id).is_err());
        assert!(store.stage(&app, "job-next").is_err());
        assert!(store.recover_with_boot(&app.id, Some(BOOT_A)).is_err());
        assert!(store.recover_with_boot(&app.id, None).is_err());
        assert!(store.recover_with_boot(&app.id, Some("untrusted")).is_err());
        assert_eq!(store.selected(&app.id).unwrap(), old);
        let state = store.recover_with_boot(&app.id, Some(BOOT_B)).unwrap();
        assert!(state.operation.is_none());
        assert_eq!(state.generations[1].status, GenerationStatus::Failed);
        assert_eq!(store.selected(&app.id).unwrap(), old);
        stage(&store, &app, &runtime, "job-next");
    }

    #[test]
    fn generation_metadata_and_launcher_modification_fail_closed() {
        let (store, app, runtime) = fixture();
        let generation = installed(&store, &app, &runtime, "job-old");
        let path = store.launcher_path(&generation, &generation.definition.launchers[0].executable);
        fs::write(path, b"tampered").unwrap();
        assert!(store.begin_launch(&app.id, "job-launch", JobKind::Launch).is_err());
        let mut state = store.state(&app.id).unwrap();
        state.generations[0].bottle_id = "../escape".into();
        assert!(store.write(&state).is_err());
        assert!(store.state("../../escape").is_err());
        let path = store.root.join(format!("{}.json", app.id));
        fs::write(path, vec![b' '; MAX_STATE_BYTES as usize + 1]).unwrap();
        assert!(store.state(&app.id).is_err());
    }

    #[test]
    fn unreviewed_installer_and_changed_runtime_are_rejected() {
        let (store, mut app, runtime) = fixture();
        app.installer.as_mut().unwrap().sha256 = None;
        assert!(store.stage(&app, "job-unreviewed").is_err());
        let mut config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        config.runtime_bindings[0].executable.push_str("-changed");
        assert!(runtime.check_config(&config).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn launcher_symlink_and_linked_ancestor_cannot_activate() {
        use std::os::unix::fs::symlink;
        let (store, app, runtime) = fixture();
        let generation = stage(&store, &app, &runtime, "job-linked");
        let outside = store.root.join("outside.exe");
        fs::write(&outside, include_bytes!("../../../tests/fixtures/hello-x86_64.exe")).unwrap();
        let path = store.launcher_path(&generation, &generation.definition.launchers[0].executable);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(&outside, &path).unwrap();
        assert!(store.finish(&job(&app, "job-linked", JobStatus::Succeeded)).is_err());
        assert!(store.selected(&app.id).is_err());
        let alias = store.root.join("alias");
        symlink(&store.storage_root, &alias).unwrap();
        assert!(check_path(&alias.join("bottles/future"), true).is_err());
    }
}
