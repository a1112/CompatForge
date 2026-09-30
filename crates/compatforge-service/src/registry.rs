use crate::model::{
    ApplicationDefinition, ApplicationRecord, ApplicationStatus, ApplicationSummary, BottleArchive, BottleStatus,
    BottleSummary, CompatibilityRating, InstallerDefinition, JobKind, JobRecord, JobStatus, LauncherDefinition,
    ModelError, ServiceSettings, MAX_APPLICATIONS,
};
use compatforge_domain::{validate_id, SCHEMA_VERSION_V1};
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

const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
static ARCHIVE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Registry {
    service_root: PathBuf,
    storage_root: PathBuf,
    store: JsonStore,
    mutation: Mutex<()>,
}

impl Registry {
    pub(crate) fn new(service_root: PathBuf, storage_root: PathBuf) -> Result<Self, RegistryError> {
        if !service_root.is_absolute() || !storage_root.is_absolute() {
            return Err(RegistryError::Invalid("service and storage roots must be absolute"));
        }
        create_directory(&service_root)?;
        create_directory(&service_root.join("applications"))?;
        create_directory(&service_root.join("jobs"))?;
        create_directory(&service_root.join("archives"))?;
        create_directory(&storage_root)?;
        create_directory(&storage_root.join("bottles"))?;
        create_directory(&storage_root.join("archives"))?;
        let store = JsonStore::new(&service_root);
        let registry = Self {
            service_root,
            storage_root,
            store,
            mutation: Mutex::new(()),
        };
        if !registry.store.exists("settings.json") {
            registry.write_settings(&ServiceSettings::default())?;
        }
        Ok(registry)
    }

    pub(crate) fn seed_defaults(&self) -> Result<(), RegistryError> {
        for application in baseline_applications() {
            if self.get_application(&application.id).is_err() {
                self.upsert_application(application)?;
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
        self.store
            .write(application_relative_path(&record.application.id), &record)
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
        self.store
            .read(application_relative_path(id))
            .map_err(|error| match error {
                compatforge_storage::StoreError::Io(source) if source.kind() == io::ErrorKind::NotFound => {
                    RegistryError::NotFound("application")
                }
                other => RegistryError::Store(other.to_string()),
            })
    }

    pub(crate) fn list_application_records(&self) -> Result<Vec<ApplicationRecord>, RegistryError> {
        self.list_application_records_unlocked()
    }

    fn list_application_records_unlocked(&self) -> Result<Vec<ApplicationRecord>, RegistryError> {
        let mut records: Vec<ApplicationRecord> = read_json_directory(&self.service_root.join("applications"))?;
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
        Ok(records
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
                ApplicationSummary {
                    application: record.application,
                    status,
                    installed,
                    active_job_ids: active.iter().map(|job| job.id.clone()).collect(),
                    last_job_id: related.last().map(|job| job.id.clone()),
                }
            })
            .collect())
    }

    pub(crate) fn application_installed(&self, application: &ApplicationDefinition) -> bool {
        application
            .launchers
            .iter()
            .any(|launcher| is_regular_file(&self.launcher_path(application, launcher)))
    }

    pub(crate) fn launcher_path(&self, application: &ApplicationDefinition, launcher: &LauncherDefinition) -> PathBuf {
        self.bottle_drive_c(&application.bottle_id).join(&launcher.executable)
    }

    pub(crate) fn bottle_drive_c(&self, bottle_id: &str) -> PathBuf {
        self.storage_root
            .join("bottles")
            .join(bottle_id)
            .join("prefix")
            .join("drive_c")
    }

    pub(crate) fn read_settings(&self) -> Result<ServiceSettings, RegistryError> {
        let settings: ServiceSettings = self
            .store
            .read("settings.json")
            .map_err(|error| RegistryError::Store(error.to_string()))?;
        settings.validate().map_err(RegistryError::Model)?;
        Ok(settings)
    }

    pub(crate) fn write_settings(&self, settings: &ServiceSettings) -> Result<ServiceSettings, RegistryError> {
        settings.validate().map_err(RegistryError::Model)?;
        self.store
            .write("settings.json", settings)
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
        let records = self.list_application_records()?;
        let mut summaries = Vec::new();
        for id in list_directories(&self.storage_root.join("bottles"))? {
            validate_registry_id(&id)?;
            summaries.push(self.bottle_summary(&id, &records));
        }
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
        let records = self.list_application_records_unlocked()?;
        Ok(self.bottle_summary(id, &records))
    }

    fn bottle_summary(&self, id: &str, records: &[ApplicationRecord]) -> BottleSummary {
        let applications: Vec<&ApplicationDefinition> = records
            .iter()
            .filter(|record| record.application.bottle_id == id)
            .map(|record| &record.application)
            .collect();
        let installed_launcher_count = applications
            .iter()
            .flat_map(|application| {
                application
                    .launchers
                    .iter()
                    .map(move |launcher| (*application, launcher))
            })
            .filter(|(application, launcher)| is_regular_file(&self.launcher_path(application, launcher)))
            .count();
        BottleSummary {
            id: id.into(),
            status: if installed_launcher_count == 0 {
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
        self.store
            .write(archive_relative_path(&archive_id), &archive)
            .map_err(|error| RegistryError::Store(error.to_string()))?;
        Ok(archive)
    }

    pub(crate) fn list_archives(&self) -> Result<Vec<BottleArchive>, RegistryError> {
        let mut records: Vec<BottleArchive> = read_json_directory(&self.service_root.join("archives"))?;
        records.sort_by_key(|record| Reverse(record.archived_at_milliseconds));
        Ok(records)
    }

    pub(crate) fn restore_bottle(&self, archive_id: &str) -> Result<BottleSummary, RegistryError> {
        validate_registry_id(archive_id)?;
        let _guard = self.lock_mutation()?;
        let archive: BottleArchive = self
            .store
            .read(archive_relative_path(archive_id))
            .map_err(|_| RegistryError::NotFound("bottle archive"))?;
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
        validate_registry_id(&job.id)?;
        self.store
            .write(job_relative_path(&job.id), job)
            .map_err(|error| RegistryError::Store(error.to_string()))
    }

    pub(crate) fn read_job(&self, id: &str) -> Result<JobRecord, RegistryError> {
        validate_registry_id(id)?;
        self.store.read(job_relative_path(id)).map_err(|error| match error {
            compatforge_storage::StoreError::Io(source) if source.kind() == io::ErrorKind::NotFound => {
                RegistryError::NotFound("job")
            }
            other => RegistryError::Store(other.to_string()),
        })
    }

    pub(crate) fn list_jobs(&self) -> Result<Vec<JobRecord>, RegistryError> {
        let mut jobs: Vec<JobRecord> = read_json_directory(&self.service_root.join("jobs"))?;
        jobs.sort_by_key(|job| Reverse(job.updated_at_milliseconds));
        Ok(jobs)
    }

    pub(crate) fn recover_interrupted_jobs(&self) -> Result<(), RegistryError> {
        let _guard = self.lock_mutation()?;
        for mut job in self.list_jobs()? {
            if job.status.is_terminal() {
                continue;
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
            arguments: vec![installer_argument.into()],
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
    validate_id("id", id).map_err(|error| RegistryError::InvalidOwned(error.to_string()))
}

fn read_json_directory<T: serde::de::DeserializeOwned>(directory: &Path) -> Result<Vec<T>, RegistryError> {
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
        let bytes = fs::read(&path).map_err(RegistryError::Io)?;
        values.push(serde_json::from_slice(&bytes).map_err(RegistryError::Json)?);
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(RegistryError::Conflict("directory path is not a real directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path).map_err(RegistryError::Io),
        Err(error) => Err(RegistryError::Io(error)),
    }
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
