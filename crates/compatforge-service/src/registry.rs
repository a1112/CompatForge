use crate::lifecycle::{
    acquire_root_lock, check_path, ensure_directory, read_record, stored_record_size, ApplicationGeneration,
    GenerationStatus, LifecycleStore,
};
use crate::model::{
    ApplicationDefinition, ApplicationRecord, ApplicationStatus, ApplicationSummary, BottleArchive, BottleStatus,
    BottleSummary, CompatibilityRating, InstallerDefinition, JobKind, JobRecord, JobStatus, LauncherDefinition,
    ModelError, ServiceSettings, MAX_APPLICATIONS,
};
use compatforge_domain::SCHEMA_VERSION_V1;
use compatforge_storage::JsonStore;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const MAX_JOB_RECORDS: usize = 4096;
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
static ARCHIVE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Registry {
    service_root: PathBuf,
    storage_root: PathBuf,
    store: JsonStore,
    mutation: Mutex<()>,
    job_mutation: Mutex<()>,
    pub(crate) lifecycle: LifecycleStore,
    _owners: Vec<RootOwner>,
}

/// The logical service owns the lease, not a transient fork's inherited file
/// description. Unlock explicitly before close, including partial construction.
struct RootOwner(fs::File);

impl Drop for RootOwner {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.0);
    }
}

impl Registry {
    pub(crate) fn new(service_root: PathBuf, storage_root: PathBuf) -> Result<Self, RegistryError> {
        if !service_root.is_absolute() || !storage_root.is_absolute() {
            return Err(RegistryError::Invalid("service and storage roots must be absolute"));
        }
        let mut owners = vec![RootOwner(acquire_root_lock(&service_root)?)];
        if service_root != storage_root {
            owners.push(RootOwner(acquire_root_lock(&storage_root)?));
        }
        create_directory(&service_root)?;
        create_directory(&service_root.join("applications"))?;
        create_directory(&service_root.join("jobs"))?;
        create_directory(&service_root.join("archives"))?;
        create_directory(&storage_root)?;
        create_directory(&storage_root.join("bottles"))?;
        create_directory(&storage_root.join("archives"))?;
        let store = JsonStore::new(&service_root);
        let lifecycle = LifecycleStore::new(service_root.join("generations"), storage_root.clone())?;
        let registry = Self {
            lifecycle,
            _owners: owners,
            service_root,
            storage_root,
            store,
            mutation: Mutex::new(()),
            job_mutation: Mutex::new(()),
        };
        check_path(&registry.service_root.join("settings.json"), true)?;
        if !registry.store.exists("settings.json") {
            registry.write_settings(&ServiceSettings::default())?;
        }
        Ok(registry)
    }

    fn write_record<T: serde::Serialize>(&self, path: impl AsRef<Path>, value: &T) -> Result<(), RegistryError> {
        check_path(&self.service_root.join(path.as_ref()), true)?;
        if stored_record_size(value)? > MAX_RECORD_BYTES {
            return Err(RegistryError::Invalid("registry record exceeds 4 MiB"));
        }
        self.store
            .write(path, value)
            .map_err(|error| RegistryError::Store(error.to_string()))
    }

    pub(crate) fn seed_defaults(&self) -> Result<(), RegistryError> {
        for application in baseline_applications() {
            match self.get_application(&application.id) {
                Ok(_) => {}
                Err(RegistryError::NotFound(_)) => {
                    self.upsert_application(application)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn upsert_application(
        &self,
        application: ApplicationDefinition,
    ) -> Result<ApplicationRecord, RegistryError> {
        application.validate().map_err(RegistryError::Model)?;
        let _guard = self.lock_mutation()?;
        let records = self.list_application_records_unlocked()?;
        if records.len() >= MAX_APPLICATIONS && records.iter().all(|record| record.application.id != application.id) {
            return Err(RegistryError::Invalid("application registry is full"));
        }
        let now = now_milliseconds();
        let created = records
            .iter()
            .find(|record| record.application.id == application.id)
            .map_or(now, |record| record.created_at_milliseconds);
        let record = ApplicationRecord {
            application,
            created_at_milliseconds: created,
            updated_at_milliseconds: now,
        };
        self.write_record(application_relative_path(&record.application.id), &record)
            .map_err(|error| RegistryError::Store(error.to_string()))?;
        Ok(record)
    }

    pub(crate) fn remove_application(&self, id: &str) -> Result<ApplicationRecord, RegistryError> {
        validate_registry_id(id)?;
        let _guard = self.lock_mutation()?;
        let record = self.get_application_unlocked(id)?;
        remove_regular_file(&self.service_root.join(application_relative_path(id)))?;
        Ok(record)
    }

    pub(crate) fn get_application(&self, id: &str) -> Result<ApplicationRecord, RegistryError> {
        validate_registry_id(id)?;
        self.get_application_unlocked(id)
    }

    fn get_application_unlocked(&self, id: &str) -> Result<ApplicationRecord, RegistryError> {
        let record: ApplicationRecord =
            read_record(&self.service_root.join(application_relative_path(id))).map_err(|error| match error {
                RegistryError::Io(source) if source.kind() == io::ErrorKind::NotFound => {
                    RegistryError::NotFound("application")
                }
                other => other,
            })?;
        record.application.validate().map_err(RegistryError::Model)?;
        if record.application.id != id {
            return Err(RegistryError::Invalid("application record identity mismatch"));
        }
        Ok(record)
    }

    pub(crate) fn list_application_records(&self) -> Result<Vec<ApplicationRecord>, RegistryError> {
        self.list_application_records_unlocked()
    }

    fn list_application_records_unlocked(&self) -> Result<Vec<ApplicationRecord>, RegistryError> {
        let mut records: Vec<ApplicationRecord> =
            read_json_directory(&self.service_root.join("applications"), MAX_APPLICATIONS)?;
        records.sort_by(|left, right| left.application.name.cmp(&right.application.name));
        if records.len() > MAX_APPLICATIONS {
            return Err(RegistryError::Invalid("application registry exceeds maximum entries"));
        }
        for record in &records {
            record.application.validate().map_err(RegistryError::Model)?;
        }
        Ok(records)
    }

    pub(crate) fn application_summaries(&self, jobs: &[JobRecord]) -> Result<Vec<ApplicationSummary>, RegistryError> {
        let records = self.list_application_records()?;
        records
            .into_iter()
            .map(|record| {
                let mut related: Vec<&JobRecord> = jobs
                    .iter()
                    .filter(|job| job.application_id == record.application.id)
                    .collect();
                related.sort_by_key(|job| job.updated_at_milliseconds);
                let active: Vec<&JobRecord> = related
                    .iter()
                    .copied()
                    .filter(|job| !job.status.is_terminal())
                    .collect();
                let generations = self.lifecycle.state(&record.application.id)?;
                let installed = self.application_installed(&record.application);
                let status = if active.iter().any(|job| job.kind == JobKind::Install) {
                    ApplicationStatus::Installing
                } else if !active.is_empty() {
                    ApplicationStatus::Running
                } else if related.last().is_some_and(|job| job.status == JobStatus::Failed) && !installed {
                    ApplicationStatus::Failed
                } else if installed {
                    ApplicationStatus::Installed
                } else {
                    ApplicationStatus::Installable
                };
                Ok(ApplicationSummary {
                    generations,
                    application: record.application,
                    status,
                    installed,
                    active_job_ids: active.iter().map(|job| job.id.clone()).collect(),
                    last_job_id: related.last().map(|job| job.id.clone()),
                })
            })
            .collect()
    }

    pub(crate) fn application_installed(&self, application: &ApplicationDefinition) -> bool {
        self.lifecycle
            .selected(&application.id)
            .is_ok_and(|generation| self.lifecycle.verify_launchers(&generation).is_ok())
    }

    pub(crate) fn bottle_drive_c(&self, bottle_id: &str) -> PathBuf {
        self.storage_root
            .join("bottles")
            .join(bottle_id)
            .join("prefix")
            .join("drive_c")
    }

    pub(crate) fn read_settings(&self) -> Result<ServiceSettings, RegistryError> {
        let settings: ServiceSettings = read_record(&self.service_root.join("settings.json"))?;
        settings.validate().map_err(RegistryError::Model)?;
        Ok(settings)
    }

    pub(crate) fn write_settings(&self, settings: &ServiceSettings) -> Result<ServiceSettings, RegistryError> {
        settings.validate().map_err(RegistryError::Model)?;
        self.write_record("settings.json", settings)
            .map_err(|error| RegistryError::Store(error.to_string()))?;
        Ok(settings.clone())
    }

    pub(crate) fn create_bottle(&self, id: &str) -> Result<BottleSummary, RegistryError> {
        validate_registry_id(id)?;
        let _guard = self.lock_mutation()?;
        create_directory_chain(&self.storage_root.join("bottles").join(id), &["prefix", "drive_c"])?;
        self.get_bottle_unlocked(id)
    }

    pub(crate) fn list_bottles(&self) -> Result<Vec<BottleSummary>, RegistryError> {
        let ids = list_directories(&self.storage_root.join("bottles"))?;
        let mut summaries = self.bottle_summaries(&ids)?;
        summaries.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(summaries)
    }

    pub(crate) fn get_bottle(&self, id: &str) -> Result<BottleSummary, RegistryError> {
        validate_registry_id(id)?;
        self.get_bottle_unlocked(id)
    }

    fn get_bottle_unlocked(&self, id: &str) -> Result<BottleSummary, RegistryError> {
        let root = self.storage_root.join("bottles").join(id);
        if !is_directory(&root) {
            return Err(RegistryError::NotFound("bottle"));
        }
        self.bottle_summaries(&[id.into()])?
            .pop()
            .ok_or(RegistryError::NotFound("bottle"))
    }

    fn bottle_summaries(&self, ids: &[String]) -> Result<Vec<BottleSummary>, RegistryError> {
        // Load and index each registry once per request, including retained
        // definitions whose current application recipe was changed or removed.
        let records = self.list_application_records_unlocked()?;
        let states = self.lifecycle.all_states()?;
        let mut definitions: BTreeMap<&str, Vec<&ApplicationDefinition>> = BTreeMap::new();
        for record in &records {
            definitions
                .entry(&record.application.bottle_id)
                .or_default()
                .push(&record.application);
        }
        let generations: BTreeMap<&str, &ApplicationGeneration> = states
            .iter()
            .flat_map(|state| state.generations.iter())
            .map(|generation| (generation.bottle_id.as_str(), generation))
            .collect();
        ids.iter()
            .map(|id| {
                validate_registry_id(id)?;
                let generation = generations.get(id.as_str()).copied();
                let applications = match generation {
                    Some(generation) => vec![&generation.definition],
                    None => definitions.get(id.as_str()).cloned().unwrap_or_default(),
                };
                Ok(self.bottle_summary(id, &applications, generation))
            })
            .collect()
    }

    fn bottle_summary(
        &self,
        id: &str,
        applications: &[&ApplicationDefinition],
        generation: Option<&ApplicationGeneration>,
    ) -> BottleSummary {
        let installed_launcher_count = applications
            .iter()
            .flat_map(|application| application.launchers.iter())
            .filter(|launcher| {
                let path = self.bottle_drive_c(id).join(&launcher.executable);
                check_path(&path, false).is_ok() && is_regular_file(&path)
            })
            .count();
        let incomplete_generation = generation.is_some_and(|generation| {
            generation.status != GenerationStatus::Ready
                || installed_launcher_count != generation.definition.launchers.len()
        });
        BottleSummary {
            id: id.into(),
            managed: generation.is_some() || id.starts_with("gen-"),
            status: if installed_launcher_count == 0 || incomplete_generation {
                BottleStatus::Empty
            } else {
                BottleStatus::Ready
            },
            application_ids: applications.iter().map(|application| application.id.clone()).collect(),
            installed_launcher_count,
        }
    }

    pub(crate) fn archive_bottle(&self, id: &str) -> Result<BottleArchive, RegistryError> {
        validate_registry_id(id)?;
        let _guard = self.lock_mutation()?;
        let source = self.storage_root.join("bottles").join(id);
        require_directory(&source, "bottle")?;
        let now = now_milliseconds();
        let archive_id = format!("{id}-{now}-{}", ARCHIVE_COUNTER.fetch_add(1, Ordering::Relaxed));
        validate_registry_id(&archive_id)?;
        let destination = self.storage_root.join("archives").join(&archive_id);
        if destination.exists() {
            return Err(RegistryError::Conflict("archive already exists"));
        }
        fs::rename(&source, &destination).map_err(RegistryError::Io)?;
        let archive = BottleArchive {
            schema_version: SCHEMA_VERSION_V1.into(),
            archive_id: archive_id.clone(),
            bottle_id: id.into(),
            archived_at_milliseconds: now,
        };
        self.write_record(archive_relative_path(&archive_id), &archive)
            .map_err(|error| RegistryError::Store(error.to_string()))?;
        Ok(archive)
    }

    pub(crate) fn list_archives(&self) -> Result<Vec<BottleArchive>, RegistryError> {
        let mut records: Vec<BottleArchive> =
            read_json_directory(&self.service_root.join("archives"), MAX_APPLICATIONS)?;
        records.sort_by_key(|record| Reverse(record.archived_at_milliseconds));
        Ok(records)
    }

    pub(crate) fn restore_bottle(&self, archive_id: &str) -> Result<BottleSummary, RegistryError> {
        validate_registry_id(archive_id)?;
        let _guard = self.lock_mutation()?;
        let archive: BottleArchive = read_record(&self.service_root.join(archive_relative_path(archive_id)))?;
        validate_registry_id(&archive.bottle_id)?;
        validate_registry_id(&archive.archive_id)?;
        if archive.archive_id != archive_id {
            return Err(RegistryError::Invalid("archive identity mismatch"));
        }
        let source = self.storage_root.join("archives").join(archive_id);
        require_directory(&source, "bottle archive")?;
        let destination = self.storage_root.join("bottles").join(&archive.bottle_id);
        if destination.exists() {
            return Err(RegistryError::Conflict("bottle already exists"));
        }
        fs::rename(&source, &destination).map_err(RegistryError::Io)?;
        remove_regular_file(&self.service_root.join(archive_relative_path(archive_id)))?;
        self.get_bottle_unlocked(&archive.bottle_id)
    }

    pub(crate) fn write_job(&self, job: &JobRecord) -> Result<(), RegistryError> {
        job.validate().map_err(RegistryError::Model)?;
        let _guard = self
            .job_mutation
            .lock()
            .map_err(|_| RegistryError::Conflict("job persistence lock is poisoned"))?;
        let path = self.service_root.join(job_relative_path(&job.id));
        check_path(&path, true)?;
        if !path.exists() {
            // Reserve capacity before the first Preparing record, hence before
            // any generation lease, prefix, or runtime side effect. Existing
            // records must remain writable at the limit for cleanup/recovery.
            let mut records = 0;
            for entry in fs::read_dir(self.service_root.join("jobs")).map_err(RegistryError::Io)? {
                let entry = entry.map_err(RegistryError::Io)?;
                let file_type = entry.file_type().map_err(RegistryError::Io)?;
                if file_type.is_file()
                    && !file_type.is_symlink()
                    && entry.path().extension().and_then(|value| value.to_str()) == Some("json")
                {
                    records += 1;
                    if records >= MAX_JOB_RECORDS {
                        return Err(RegistryError::Conflict("job history capacity reached (4096); stop the service and archive completed job records before retrying"));
                    }
                }
            }
        }
        self.write_record(job_relative_path(&job.id), job)
            .map_err(|error| RegistryError::Store(error.to_string()))
    }

    fn reconcile_install_job(&self, mut job: JobRecord) -> Result<JobRecord, RegistryError> {
        // Generation state is the atomic installation commit. A standalone
        // installer-exit record cannot certify installation, including across
        // a crash or an error between the two JSON replacements.
        if job.kind == JobKind::Install {
            if let Some(generation_id) = &job.generation_id {
                let state = self.lifecycle.state(&job.application_id)?;
                if let Some(generation) = state
                    .generations
                    .iter()
                    .find(|generation| &generation.id == generation_id)
                {
                    match generation.status {
                        crate::GenerationStatus::Ready => {
                            job.status = JobStatus::Succeeded;
                            job.error = None;
                        }
                        crate::GenerationStatus::Failed | crate::GenerationStatus::Quarantined => {
                            job.status = JobStatus::Failed;
                            job.error = generation.error.clone();
                        }
                        crate::GenerationStatus::Cancelled => {
                            job.status = JobStatus::Cancelled;
                            job.error = generation.error.clone();
                        }
                        crate::GenerationStatus::Staging if job.status == JobStatus::Succeeded => {
                            job.status = JobStatus::Running;
                        }
                        crate::GenerationStatus::Staging => {}
                    }
                } else if job.status == JobStatus::Succeeded {
                    job.status = JobStatus::Failed;
                    job.error = Some("installation has no verified generation".into());
                }
            } else if job.status == JobStatus::Succeeded {
                job.status = JobStatus::Failed;
                job.error = Some("legacy installer exit does not certify a managed generation".into());
            }
        }
        Ok(job)
    }

    pub(crate) fn read_job(&self, id: &str) -> Result<JobRecord, RegistryError> {
        validate_registry_id(id)?;
        let job: JobRecord =
            read_record(&self.service_root.join(job_relative_path(id))).map_err(|error| match error {
                RegistryError::Io(source) if source.kind() == io::ErrorKind::NotFound => RegistryError::NotFound("job"),
                other => other,
            })?;
        job.validate().map_err(RegistryError::Model)?;
        if job.id != id {
            return Err(RegistryError::Invalid("job identity mismatch"));
        }
        self.reconcile_install_job(job)
    }

    pub(crate) fn list_jobs(&self) -> Result<Vec<JobRecord>, RegistryError> {
        let mut jobs: Vec<JobRecord> = read_json_directory(&self.service_root.join("jobs"), MAX_JOB_RECORDS)?;
        for job in &jobs {
            job.validate().map_err(RegistryError::Model)?;
        }
        jobs.sort_by_key(|job| Reverse(job.updated_at_milliseconds));
        jobs.into_iter().map(|job| self.reconcile_install_job(job)).collect()
    }

    pub(crate) fn recover_interrupted_jobs(&self) -> Result<(), RegistryError> {
        let _guard = self.lock_mutation()?;
        for state in self.lifecycle.all_states()? {
            if state.operation.is_some() {
                self.lifecycle.quarantine(&state.application_id, "service interrupted before supervisor cleanup was confirmed; inspect recoveryCapability and recover after host reboot")?;
            }
        }
        for mut job in self.list_jobs()? {
            let interrupted = self
                .lifecycle
                .state(&job.application_id)?
                .operation
                .is_some_and(|operation| operation.job_id == job.id);
            if job.status.is_terminal() && !interrupted {
                continue;
            }
            if job.generation_id.is_none() {
                let application = self.get_application(&job.application_id)?.application;
                job.generation_id = Some(self.lifecycle.quarantine_legacy(&application, &job)?);
            }
            job.status = JobStatus::Failed;
            job.updated_at_milliseconds = now_milliseconds();
            job.error = Some("service process ended before the job reached a terminal event".into());
            self.write_job(&job)?;
        }
        Ok(())
    }

    fn lock_mutation(&self) -> Result<MutexGuard<'_, ()>, RegistryError> {
        self.mutation
            .lock()
            .map_err(|_| RegistryError::Conflict("registry lock is poisoned"))
    }
}

fn baseline_applications() -> [ApplicationDefinition; 3] {
    [
        baseline_application(
            "7zip",
            "7-Zip",
            "26.01",
            "Igor Pavlov",
            "gui-7zip",
            "7z2601-x64.exe",
            "d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d",
            "/S",
            "7zFM.exe",
            "Program Files/7-Zip/7zFM.exe",
        ),
        baseline_application(
            "sumatrapdf",
            "SumatraPDF",
            "3.6.1",
            "Krzysztof Kowalczyk",
            "gui-sumatrapdf",
            "SumatraPDF-3.6.1-64-install.exe",
            "1eee71cccd2ea6e94d5bcea54ee2f759844da3e1a0ee2f6045035b1d17b94381",
            "-silent",
            "SumatraPDF.exe",
            "Program Files/SumatraPDF/SumatraPDF.exe",
        ),
        baseline_application(
            "notepad-plus-plus",
            "Notepad++",
            "8.9.6.2",
            "Notepad++ Team",
            "gui-notepad-plus-plus",
            "npp.8.9.6.2.Installer.x64.exe",
            "7c243203265ce8fdac76c839bf744ae35dcf620760eb97c2ea279af498560e45",
            "/S",
            "notepad++.exe",
            "Program Files/Notepad++/notepad++.exe",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn baseline_application(
    id: &str,
    name: &str,
    version: &str,
    publisher: &str,
    bottle_id: &str,
    installer_name: &str,
    installer_sha256: &str,
    installer_argument: &str,
    executable_name: &str,
    executable: &str,
) -> ApplicationDefinition {
    ApplicationDefinition {
        schema_version: SCHEMA_VERSION_V1.into(),
        id: id.into(),
        name: name.into(),
        version: version.into(),
        publisher: publisher.into(),
        category: "utilities".into(),
        bottle_id: bottle_id.into(),
        installer: Some(InstallerDefinition {
            file_name: installer_name.into(),
            sha256: Some(installer_sha256.into()),
            arguments: if id == "sumatrapdf" {
                vec![
                    "-install".into(),
                    "-silent".into(),
                    "-d".into(),
                    "C:\\Program Files\\SumatraPDF".into(),
                ]
            } else {
                vec![installer_argument.into()]
            },
        }),
        launchers: vec![LauncherDefinition {
            id: "main".into(),
            name: executable_name.into(),
            executable: executable.into(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
        }],
        compatibility_rating: CompatibilityRating::Unknown,
        tags: vec!["gui-baseline".into()],
        wine_appearance: None,
    }
}

fn application_relative_path(id: &str) -> PathBuf {
    PathBuf::from("applications").join(format!("{id}.json"))
}

fn job_relative_path(id: &str) -> PathBuf {
    PathBuf::from("jobs").join(format!("{id}.json"))
}

fn archive_relative_path(id: &str) -> PathBuf {
    PathBuf::from("archives").join(format!("{id}.json"))
}

fn validate_registry_id(id: &str) -> Result<(), RegistryError> {
    crate::lifecycle::checked_id(id)
}

fn read_json_directory<T: serde::de::DeserializeOwned>(
    directory: &Path,
    maximum: usize,
) -> Result<Vec<T>, RegistryError> {
    create_directory(directory)?;
    let mut values = Vec::new();
    for entry in fs::read_dir(directory).map_err(RegistryError::Io)? {
        let entry = entry.map_err(RegistryError::Io)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(RegistryError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        if metadata.len() > MAX_RECORD_BYTES {
            return Err(RegistryError::Invalid("registry record exceeds 4 MiB"));
        }
        if values.len() >= maximum {
            return Err(RegistryError::Invalid("registry directory exceeds entry bound"));
        }
        values.push(read_record(&path)?);
    }
    Ok(values)
}

fn list_directories(root: &Path) -> Result<Vec<String>, RegistryError> {
    create_directory(root)?;
    let mut values = Vec::new();
    for entry in fs::read_dir(root).map_err(RegistryError::Io)? {
        let entry = entry.map_err(RegistryError::Io)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(RegistryError::Io)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| RegistryError::Invalid("registry path is not UTF-8"))?;
            values.push(name);
        }
    }
    Ok(values)
}

fn create_directory(path: &Path) -> Result<(), RegistryError> {
    ensure_directory(path)
}

fn create_directory_chain(root: &Path, children: &[&str]) -> Result<(), RegistryError> {
    create_directory(root)?;
    let mut current = root.to_path_buf();
    for child in children {
        current.push(child);
        create_directory(&current)?;
    }
    Ok(())
}

fn require_directory(path: &Path, label: &'static str) -> Result<(), RegistryError> {
    if is_directory(path) {
        Ok(())
    } else {
        Err(RegistryError::NotFound(label))
    }
}

fn is_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

fn remove_regular_file(path: &Path) -> Result<(), RegistryError> {
    let metadata = fs::symlink_metadata(path).map_err(RegistryError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(RegistryError::Conflict("record path is not a regular file"));
    }
    fs::remove_file(path).map_err(RegistryError::Io)
}

pub(crate) fn now_milliseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug)]
pub enum RegistryError {
    Invalid(&'static str),
    InvalidOwned(String),
    NotFound(&'static str),
    Conflict(&'static str),
    Model(ModelError),
    Store(String),
    Io(io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::NotFound(message) | Self::Conflict(message) => formatter.write_str(message),
            Self::InvalidOwned(message) | Self::Store(message) => formatter.write_str(message),
            Self::Model(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "registry I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "registry JSON failed: {error}"),
        }
    }
}

impl std::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    #[cfg(unix)]
    #[test]
    fn logical_owner_drop_releases_flock_even_while_pre_exec_duplicate_survives() {
        let (service, storage) = roots("duplicated-owner-fd");
        let registry = Registry::new(service.clone(), storage.clone()).unwrap();
        let inherited = registry
            ._owners
            .iter()
            .map(|file| file.0.try_clone().unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            Registry::new(service.clone(), storage.clone()),
            Err(RegistryError::Conflict(_))
        ));
        drop(registry);
        let next = Registry::new(service, storage).expect("logical owner ended despite inherited pre-exec descriptors");
        drop(inherited);
        drop(next);
    }

    fn roots(label: &str) -> (PathBuf, PathBuf) {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("compatforge-service-{label}-{}-{id}", std::process::id()));
        (root.join("service"), root.join("storage"))
    }

    #[test]
    fn seeded_registry_is_dynamic_and_bottle_archive_is_recoverable() {
        let (service_root, storage_root) = roots("registry");
        let registry = Registry::new(service_root, storage_root).unwrap();
        registry.seed_defaults().unwrap();
        let applications = registry.list_application_records().unwrap();
        assert_eq!(applications.len(), 3);
        assert_eq!(applications[0].application.id, "7zip");

        let bottle = registry.create_bottle("gui-7zip").unwrap();
        assert_eq!(bottle.status, BottleStatus::Empty);
        let archive = registry.archive_bottle("gui-7zip").unwrap();
        assert_eq!(registry.list_archives().unwrap(), vec![archive.clone()]);
        let restored = registry.restore_bottle(&archive.archive_id).unwrap();
        assert_eq!(restored.id, "gui-7zip");
    }

    #[test]
    fn legacy_files_are_not_certified_as_managed_installation() {
        let (service_root, storage_root) = roots("legacy");
        let registry = Registry::new(service_root, storage_root).unwrap();
        let app = baseline_applications()[0].clone();
        let path = registry
            .bottle_drive_c(&app.bottle_id)
            .join(&app.launchers[0].executable);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"legacy executable").unwrap();
        assert!(!registry.application_installed(&app));
    }

    #[test]
    fn a_second_owner_cannot_recover_a_running_service_or_shared_storage() {
        let (service_root, storage_root) = roots("ownership");
        let _registry = Registry::new(service_root.clone(), storage_root.clone()).unwrap();
        assert!(Registry::new(service_root.clone(), storage_root.clone()).is_err());
        assert!(Registry::new(service_root.with_file_name("other-service"), storage_root).is_err());
    }

    #[test]
    fn service_root_lock_is_exclusive_across_processes_and_released_on_drop() {
        let (service_root, storage_root) = roots("ownership-process");
        let registry = Registry::new(service_root.clone(), storage_root.clone()).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "registry::tests::ownership_child", "--ignored"])
            .env("COMPATFORGE_OWNER_TEST_SERVICE", &service_root)
            .env("COMPATFORGE_OWNER_TEST_STORAGE", &storage_root)
            .status()
            .unwrap();
        assert!(status.success());
        drop(registry);
        assert!(Registry::new(service_root, storage_root).is_ok());
    }

    #[test]
    #[ignore = "spawned only as an isolated service ownership client"]
    fn ownership_child() {
        if let (Some(service), Some(storage)) = (
            std::env::var_os("COMPATFORGE_OWNER_TEST_SERVICE"),
            std::env::var_os("COMPATFORGE_OWNER_TEST_STORAGE"),
        ) {
            assert!(matches!(
                Registry::new(service.into(), storage.into()),
                Err(RegistryError::Conflict(_))
            ));
        }
    }

    #[test]
    fn sumatra_recipe_selects_the_declared_install_directory() {
        let app = baseline_applications()[1].clone();
        assert_eq!(
            app.installer.unwrap().arguments,
            ["-install", "-silent", "-d", "C:\\Program Files\\SumatraPDF"]
        );
    }

    #[test]
    fn legacy_interrupted_job_is_quarantined_without_certifying_old_files() {
        let (service_root, storage_root) = roots("legacy-interrupted");
        let registry = Registry::new(service_root, storage_root).unwrap();
        registry.seed_defaults().unwrap();
        let job: JobRecord = serde_json::from_value(serde_json::json!({"schemaVersion":"1","id":"job-old-service","applicationId":"7zip","kind":"install","status":"running","createdAtMilliseconds":1,"updatedAtMilliseconds":1})).unwrap();
        registry.write_job(&job).unwrap();
        registry.recover_interrupted_jobs().unwrap();
        assert!(registry.lifecycle.state("7zip").unwrap().operation.unwrap().quarantined);
        assert!(registry.lifecycle.selected("7zip").is_err());
    }

    #[test]
    fn oversized_pretty_job_preserves_the_previous_readable_record() {
        let (service_root, storage_root) = roots("pretty-job-bound");
        let registry = Registry::new(service_root.clone(), storage_root.clone()).unwrap();
        let previous: JobRecord = serde_json::from_value(serde_json::json!({
            "schemaVersion":"1", "id":"job-bound", "applicationId":"7zip", "kind":"launch",
            "status":"succeeded", "createdAtMilliseconds":1, "updatedAtMilliseconds":1
        }))
        .unwrap();
        registry.write_job(&previous).unwrap();
        let path = service_root.join("jobs/job-bound.json");
        let original = fs::read(&path).unwrap();

        let mut oversized = previous.clone();
        let event: compatforge_domain::RuntimeEvent = serde_json::from_value(serde_json::json!({
            "schemaVersion":"1", "sequence":1, "kind":"started", "requestId":"job-bound",
            "elapsedMilliseconds":0, "message":""
        }))
        .unwrap();
        oversized.events = vec![event; crate::model::MAX_JOB_EVENTS];
        for (index, event) in oversized.events.iter_mut().enumerate() {
            event.sequence = index as u64 + 1;
        }
        let padding =
            (MAX_RECORD_BYTES as usize - serde_json::to_vec(&oversized).unwrap().len()) / oversized.events.len();
        for event in &mut oversized.events {
            event.message = Some("x".repeat(padding));
        }
        oversized.validate().unwrap();
        assert!(serde_json::to_vec(&oversized).unwrap().len() as u64 <= MAX_RECORD_BYTES);
        assert!(serde_json::to_vec_pretty(&oversized).unwrap().len() as u64 + 1 > MAX_RECORD_BYTES);
        assert!(registry.write_job(&oversized).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(registry.read_job(&previous.id).unwrap(), previous);

        // The final newline is part of the persisted file limit too.
        let mut newline_overflow = previous.clone();
        newline_overflow.inspection = Some(serde_json::Value::String(String::new()));
        let padding = MAX_RECORD_BYTES as usize - serde_json::to_vec_pretty(&newline_overflow).unwrap().len();
        newline_overflow.inspection = Some(serde_json::Value::String("x".repeat(padding)));
        assert_eq!(
            serde_json::to_vec_pretty(&newline_overflow).unwrap().len() as u64,
            MAX_RECORD_BYTES
        );
        assert!(registry.write_job(&newline_overflow).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(registry);
        let reopened = Registry::new(service_root, storage_root).unwrap();
        reopened.recover_interrupted_jobs().unwrap();
        assert_eq!(reopened.read_job(&previous.id).unwrap(), previous);
    }

    #[test]
    fn settings_are_persistent_and_validated() {
        let (service_root, storage_root) = roots("settings");
        let registry = Registry::new(service_root, storage_root).unwrap();
        let mut settings = registry.read_settings().unwrap();
        settings.maximum_parallel_jobs = 4;
        registry.write_settings(&settings).unwrap();
        assert_eq!(registry.read_settings().unwrap().maximum_parallel_jobs, 4);
        settings.maximum_parallel_jobs = 0;
        assert!(registry.write_settings(&settings).is_err());
    }
}
