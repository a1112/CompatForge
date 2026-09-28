//! Persistent application, Bottle, settings and automation job service.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod daemon;
pub mod desktop;
pub mod desktop_lifecycle;
mod jobs;
mod lifecycle;
pub use lifecycle::{
    ApplicationGeneration, ApplicationGenerations, GenerationOperation, GenerationStatus, InstalledRuntime,
    RecoveryCapability, RollbackRequest,
};
mod model;
mod registry;
pub mod transport;

use compatforge_debug::{DebugRequest, DebugSupervisor, UnavailableBackend};
use jobs::{JobError, JobManager};
pub use jobs::{ShutdownError, ShutdownFailure, ShutdownPhase};
use model::{ApplicationPayload, ArchivePayload, AssessmentPayload, IdPayload, PollPayload};
use registry::{Registry, RegistryError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub use model::{
    ApplicationDefinition, ApplicationRecord, ApplicationStatus, ApplicationSummary, AssessmentCheck,
    AssessmentOutcome, BottleArchive, BottleStatus, BottleSummary, CheckOutcome, CompatibilityRating,
    GuestArchitecture, InstallerDefinition, JobAssessment, JobKind, JobPollResult, JobRecord, JobRequest, JobStatus,
    LauncherDefinition, ModelError, ServiceConfig, ServiceRequest, ServiceResponse, ServiceSettings, WindowsVersion,
};

use compatforge_domain::{CoreConfig, SCHEMA_VERSION_V1};

pub struct AutomationService {
    registry: Arc<Registry>,
    jobs: JobManager,
    debug: Mutex<DebugSupervisor<UnavailableBackend>>,
}

impl AutomationService {
    /// Call only after stopping and draining clients. Stops owned jobs and joins
    /// their supervisor workers; this is a blocking desktop/service-owner API.
    pub fn shutdown_and_wait(&self) -> Result<(), ShutdownError> {
        self.jobs.shutdown_and_wait()
    }

    pub fn new(core_config: CoreConfig, service_config: ServiceConfig) -> Result<Self, ServiceError> {
        core_config
            .validate()
            .map_err(|error| ServiceError::Invalid(error.to_string()))?;
        service_config.validate().map_err(ServiceError::Model)?;
        let registry = Arc::new(
            Registry::new(
                PathBuf::from(service_config.service_root),
                PathBuf::from(&core_config.storage_root),
            )
            .map_err(ServiceError::Registry)?,
        );
        registry.recover_interrupted_jobs().map_err(ServiceError::Registry)?;
        let jobs = JobManager::new(Arc::clone(&registry), core_config);
        Ok(Self {
            registry,
            jobs,
            debug: Mutex::new(DebugSupervisor::new(UnavailableBackend)),
        })
    }

    pub fn seed_default_applications(&self) -> Result<(), ServiceError> {
        self.registry.seed_defaults().map_err(ServiceError::Registry)
    }

    pub fn list_applications(&self) -> Result<Vec<ApplicationSummary>, ServiceError> {
        let jobs = self.registry.list_jobs().map_err(ServiceError::Registry)?;
        self.registry
            .application_summaries(&jobs)
            .map_err(ServiceError::Registry)
    }

    pub fn get_application(&self, id: &str) -> Result<ApplicationRecord, ServiceError> {
        self.registry.get_application(id).map_err(ServiceError::Registry)
    }

    pub fn upsert_application(&self, application: ApplicationDefinition) -> Result<ApplicationRecord, ServiceError> {
        let _operation = self.jobs.lock_operation().map_err(ServiceError::Job)?;
        self.jobs
            .ensure_idle(&application.id, &application.bottle_id)
            .map_err(ServiceError::Job)?;
        if let Ok(previous) = self.registry.get_application(&application.id) {
            self.jobs
                .ensure_idle(&application.id, &previous.application.bottle_id)
                .map_err(ServiceError::Job)?;
        }
        self.registry
            .upsert_application(application)
            .map_err(ServiceError::Registry)
    }

    pub fn remove_application(&self, id: &str) -> Result<ApplicationRecord, ServiceError> {
        let _operation = self.jobs.lock_operation().map_err(ServiceError::Job)?;
        let application = self
            .registry
            .get_application(id)
            .map_err(ServiceError::Registry)?
            .application;
        self.jobs
            .ensure_idle(id, &application.bottle_id)
            .map_err(ServiceError::Job)?;
        if !self
            .registry
            .lifecycle
            .state(id)
            .map_err(ServiceError::Registry)?
            .generations
            .is_empty()
        {
            return Err(ServiceError::Conflict(
                "managed generations are retained; use applications.uninstall",
            ));
        }
        self.registry.remove_application(id).map_err(ServiceError::Registry)
    }

    pub fn application_generations(&self, id: &str) -> Result<ApplicationGenerations, ServiceError> {
        self.registry.lifecycle.state(id).map_err(ServiceError::Registry)
    }

    pub fn rollback_application(&self, request: &RollbackRequest) -> Result<ApplicationGenerations, ServiceError> {
        self.jobs.rollback(request).map_err(ServiceError::Job)
    }

    pub fn uninstall_application(&self, id: &str) -> Result<ApplicationGenerations, ServiceError> {
        self.jobs.uninstall(id).map_err(ServiceError::Job)
    }

    pub fn recover_application(&self, id: &str) -> Result<ApplicationGenerations, ServiceError> {
        self.jobs.recover(id).map_err(ServiceError::Job)
    }

    fn reject_managed_bottle(&self, id: &str) -> Result<(), ServiceError> {
        if id.starts_with("gen-")
            || self
                .registry
                .lifecycle
                .all_states()
                .map_err(ServiceError::Registry)?
                .iter()
                .any(|state| state.generations.iter().any(|generation| generation.bottle_id == id))
        {
            return Err(ServiceError::Conflict(
                "managed generation bottles are retained; use application lifecycle operations",
            ));
        }
        Ok(())
    }

    pub fn get_settings(&self) -> Result<ServiceSettings, ServiceError> {
        self.registry.read_settings().map_err(ServiceError::Registry)
    }

    pub fn update_settings(&self, settings: &ServiceSettings) -> Result<ServiceSettings, ServiceError> {
        self.registry.write_settings(settings).map_err(ServiceError::Registry)
    }

    pub fn list_bottles(&self) -> Result<Vec<BottleSummary>, ServiceError> {
        self.registry.list_bottles().map_err(ServiceError::Registry)
    }

    pub fn get_bottle(&self, id: &str) -> Result<BottleSummary, ServiceError> {
        self.registry.get_bottle(id).map_err(ServiceError::Registry)
    }

    pub fn create_bottle(&self, id: &str) -> Result<BottleSummary, ServiceError> {
        let _operation = self.jobs.lock_operation().map_err(ServiceError::Job)?;
        self.jobs
            .ensure_idle("create-operation", id)
            .map_err(ServiceError::Job)?;
        self.reject_managed_bottle(id)?;
        self.registry.create_bottle(id).map_err(ServiceError::Registry)
    }

    pub fn archive_bottle(&self, id: &str) -> Result<BottleArchive, ServiceError> {
        let _operation = self.jobs.lock_operation().map_err(ServiceError::Job)?;
        self.jobs
            .ensure_idle("archive-operation", id)
            .map_err(ServiceError::Job)?;
        self.reject_managed_bottle(id)?;
        let bound_applications: Vec<String> = self
            .registry
            .list_application_records()
            .map_err(ServiceError::Registry)?
            .into_iter()
            .filter(|record| record.application.bottle_id == id)
            .map(|record| record.application.id)
            .collect();
        if self
            .registry
            .list_jobs()
            .map_err(ServiceError::Registry)?
            .iter()
            .any(|job| !job.status.is_terminal() && bound_applications.contains(&job.application_id))
        {
            return Err(ServiceError::Conflict("bottle has an active job"));
        }
        self.registry.archive_bottle(id).map_err(ServiceError::Registry)
    }

    pub fn list_bottle_archives(&self) -> Result<Vec<BottleArchive>, ServiceError> {
        self.registry.list_archives().map_err(ServiceError::Registry)
    }

    pub fn restore_bottle(&self, archive_id: &str) -> Result<BottleSummary, ServiceError> {
        let _operation = self.jobs.lock_operation().map_err(ServiceError::Job)?;
        let archive = self
            .registry
            .list_archives()
            .map_err(ServiceError::Registry)?
            .into_iter()
            .find(|archive| archive.archive_id == archive_id)
            .ok_or(ServiceError::NotFound("bottle archive"))?;
        self.jobs
            .ensure_idle("restore-operation", &archive.bottle_id)
            .map_err(ServiceError::Job)?;
        self.reject_managed_bottle(&archive.bottle_id)?;
        self.registry.restore_bottle(archive_id).map_err(ServiceError::Registry)
    }

    pub fn submit_job(&self, request: JobRequest) -> Result<JobRecord, ServiceError> {
        self.jobs.submit(request).map_err(ServiceError::Job)
    }

    pub fn list_jobs(&self) -> Result<Vec<JobRecord>, ServiceError> {
        self.registry.list_jobs().map_err(ServiceError::Registry)
    }

    pub fn desktop_launchers(&self) -> Result<Vec<desktop::DesktopLauncher>, ServiceError> {
        self.jobs.desktop_launchers()
    }

    /// Advance supervised jobs even when no desktop client is connected.
    pub fn poll_active_jobs(&self) -> Result<(), ServiceError> {
        self.jobs.poll_active_jobs().map_err(ServiceError::Job)
    }

    pub fn get_job(&self, id: &str) -> Result<JobRecord, ServiceError> {
        self.registry.read_job(id).map_err(ServiceError::Registry)
    }

    pub fn poll_job(&self, id: &str, timeout_milliseconds: u64) -> Result<JobPollResult, ServiceError> {
        self.jobs.poll(id, timeout_milliseconds).map_err(ServiceError::Job)
    }

    pub fn cancel_job(&self, id: &str) -> Result<JobRecord, ServiceError> {
        self.jobs.cancel(id).map_err(ServiceError::Job)
    }

    pub fn assess_job(&self, id: &str, assessment: JobAssessment) -> Result<JobRecord, ServiceError> {
        self.jobs.assess(id, assessment).map_err(ServiceError::Job)
    }

    pub fn call(&self, request: ServiceRequest) -> Result<ServiceResponse, ServiceError> {
        request.validate().map_err(ServiceError::Model)?;
        let result = match request.operation.as_str() {
            "debug.session" => {
                let bytes = serde_json::to_vec(&request.payload).map_err(ServiceError::Json)?;
                let command = compatforge_debug::decode_request(&bytes).map_err(ServiceError::Debug)?;
                to_value(self.debug_session(command)?)?
            }
            "applications.seed-defaults" => {
                self.seed_default_applications()?;
                json!({ "seeded": true })
            }
            "applications.list" => to_value(self.list_applications()?)?,
            "desktop.launchers" => {
                if request.payload != json!({}) {
                    return Err(ServiceError::Invalid(
                        "desktop.launchers requires an empty object".into(),
                    ));
                }
                to_value(self.desktop_launchers()?)?
            }
            "applications.get" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.get_application(&payload.id)?)?
            }
            "applications.upsert" => {
                let payload: ApplicationPayload = parse_payload(request.payload)?;
                to_value(self.upsert_application(payload.application)?)?
            }
            "applications.remove" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.remove_application(&payload.id)?)?
            }
            "applications.generations" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.application_generations(&payload.id)?)?
            }
            "applications.rollback" => {
                let payload: RollbackRequest = parse_payload(request.payload)?;
                to_value(self.rollback_application(&payload)?)?
            }
            "applications.uninstall" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.uninstall_application(&payload.id)?)?
            }
            "applications.recover" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.recover_application(&payload.id)?)?
            }
            "bottles.list" => to_value(self.list_bottles()?)?,
            "bottles.get" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.get_bottle(&payload.id)?)?
            }
            "bottles.create" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.create_bottle(&payload.id)?)?
            }
            "bottles.archive" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.archive_bottle(&payload.id)?)?
            }
            "bottles.archives.list" => to_value(self.list_bottle_archives()?)?,
            "bottles.restore" => {
                let payload: ArchivePayload = parse_payload(request.payload)?;
                to_value(self.restore_bottle(&payload.archive_id)?)?
            }
            "settings.get" => to_value(self.get_settings()?)?,
            "settings.update" => {
                let settings: ServiceSettings = parse_payload(request.payload)?;
                to_value(self.update_settings(&settings)?)?
            }
            "jobs.submit" => {
                let job: JobRequest = parse_payload(request.payload)?;
                to_value(self.submit_job(job)?)?
            }
            "jobs.list" => to_value(self.list_jobs()?)?,
            "jobs.get" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.get_job(&payload.id)?)?
            }
            "jobs.poll" => {
                let payload: PollPayload = parse_payload(request.payload)?;
                to_value(self.poll_job(&payload.id, payload.timeout_milliseconds)?)?
            }
            "jobs.cancel" => {
                let payload: IdPayload = parse_payload(request.payload)?;
                to_value(self.cancel_job(&payload.id)?)?
            }
            "jobs.assess" => {
                let payload: AssessmentPayload = parse_payload(request.payload)?;
                to_value(self.assess_job(&payload.id, payload.assessment)?)?
            }
            _ => return Err(ServiceError::NotFound("service operation")),
        };
        Ok(ServiceResponse {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: request.request_id,
            operation: request.operation,
            result,
        })
    }
}

impl AutomationService {
    fn debug_session(&self, command: DebugRequest) -> Result<Value, ServiceError> {
        let uid = debug_owner_uid();
        let mut sessions = self
            .debug
            .lock()
            .map_err(|_| ServiceError::Conflict("debug supervisor lock is poisoned"))?;
        match command {
            DebugRequest::Launch { target } => {
                // Reuse the desktop launch trust chain: only a selected Ready
                // generation whose frozen runtime and launcher digests still
                // match can become a debug target.
                let eligible = self.desktop_launchers()?.iter().any(|entry| {
                    entry.application_id == target.application_id
                        && entry.generation_id == target.generation_id
                        && entry.launcher_id == target.launcher_id
                });
                if !eligible {
                    return Err(ServiceError::Debug(compatforge_debug::DebugError::Unauthorized));
                }
                let handle = sessions.launch(target, uid).map_err(ServiceError::Debug)?;
                to_value(handle)
            }
            DebugRequest::Status { handle } => to_value(sessions.state(&handle, uid).map_err(ServiceError::Debug)?),
            DebugRequest::Terminate { handle } => {
                sessions.terminate(&handle, uid).map_err(ServiceError::Debug)?;
                Ok(json!({"terminated":true}))
            }
            DebugRequest::Disconnect { handle } => {
                sessions.disconnect(&handle, uid).map_err(ServiceError::Debug)?;
                Ok(json!({"disconnected":true}))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn debug_owner_uid() -> u32 {
    rustix::process::getuid().as_raw()
}
#[cfg(not(target_os = "linux"))]
fn debug_owner_uid() -> u32 {
    0
}

fn parse_payload<T: DeserializeOwned>(payload: Value) -> Result<T, ServiceError> {
    serde_json::from_value(payload).map_err(ServiceError::Json)
}

fn to_value<T: Serialize>(value: T) -> Result<Value, ServiceError> {
    serde_json::to_value(value).map_err(ServiceError::Json)
}

#[derive(Debug)]
pub enum ServiceError {
    Invalid(String),
    NotFound(&'static str),
    Conflict(&'static str),
    Model(ModelError),
    Registry(RegistryError),
    Job(JobError),
    Json(serde_json::Error),
    Debug(compatforge_debug::DebugError),
}

impl ServiceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::Model(_) | Self::Json(_) => "invalid-request",
            Self::Debug(
                compatforge_debug::DebugError::InvalidRequest | compatforge_debug::DebugError::InvalidTarget,
            ) => "invalid-request",
            Self::Debug(compatforge_debug::DebugError::Unauthorized) => "unauthorized",
            Self::Debug(compatforge_debug::DebugError::Unavailable) => "unavailable",
            Self::Debug(
                compatforge_debug::DebugError::DigestMismatch | compatforge_debug::DebugError::BackendFailed,
            ) => "service-failed",
            Self::Debug(compatforge_debug::DebugError::Capacity | compatforge_debug::DebugError::InvalidTransition) => {
                "conflict"
            }
            Self::NotFound(_) => "not-found",
            Self::Conflict(_) => "conflict",
            Self::Registry(RegistryError::NotFound(_)) | Self::Job(JobError::NotFound(_)) => "not-found",
            Self::Registry(RegistryError::Conflict(_))
            | Self::Job(JobError::Conflict(_) | JobError::Registry(RegistryError::Conflict(_))) => "conflict",
            Self::Registry(_) | Self::Job(_) => "service-failed",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::NotFound(message) => write!(formatter, "{message} not found"),
            Self::Conflict(message) => formatter.write_str(message),
            Self::Model(error) => write!(formatter, "{error}"),
            Self::Registry(error) => write!(formatter, "{error}"),
            Self::Job(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "invalid service payload: {error}"),
            Self::Debug(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ServiceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::CoreConfig;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn service() -> AutomationService {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("compatforge-service-dispatch-{}-{id}", std::process::id()));
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/context-config.linux-arm64.json");
        let mut config: CoreConfig = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        config.storage_root = root.join("storage").to_string_lossy().into_owned();
        AutomationService::new(
            config,
            ServiceConfig {
                schema_version: SCHEMA_VERSION_V1.into(),
                service_root: root.join("service").to_string_lossy().into_owned(),
            },
        )
        .unwrap()
    }

    #[test]
    fn desktop_exports_only_verified_selected_frozen_generations() {
        let service = service();
        service.seed_default_applications().unwrap();
        assert!(service.desktop_launchers().unwrap().is_empty());
        let app = service.get_application("7zip").unwrap().application;
        let staged = service.registry.lifecycle.stage(&app, "job-desktop-1").unwrap();
        let config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let binding = &config.runtime_bindings[0];
        let runtime = InstalledRuntime::from_config(
            &config,
            &compatforge_domain::RuntimeSelection {
                provider: compatforge_domain::RuntimeKind::Wine,
                pack_id: binding.pack_id.clone(),
                pack_digest: binding.pack_digest.clone(),
            },
        )
        .unwrap();
        service
            .registry
            .lifecycle
            .bind_runtime(&app.id, "job-desktop-1", runtime)
            .unwrap();
        let path = service
            .registry
            .lifecycle
            .launcher_path(&staged, &app.launchers[0].executable);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, include_bytes!("../../../tests/fixtures/hello-x86_64.exe")).unwrap();
        let job: JobRecord = serde_json::from_value(json!({"schemaVersion":"1","id":"job-desktop-1","applicationId":"7zip","generationId":staged.id,"kind":"install","status":"succeeded","createdAtMilliseconds":1,"updatedAtMilliseconds":1})).unwrap();
        service.registry.lifecycle.finish(&job).unwrap();
        let mut changed = app;
        changed.name = "Different pending recipe".into();
        service.upsert_application(changed).unwrap();
        let entries = service.desktop_launchers().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "7-Zip");
        fs::write(&path, b"tampered").unwrap();
        assert!(service.desktop_launchers().is_err());
        service.uninstall_application("7zip").unwrap();
        assert!(service.desktop_launchers().unwrap().is_empty());
    }

    #[test]
    fn debug_session_refuses_unmanaged_or_tampered_target_and_unavailable_provider() {
        let service = service();
        service.seed_default_applications().unwrap();
        let request = |generation: &str| ServiceRequest {
            schema_version: "1".into(),
            request_id: "debug-contract".into(),
            operation: "debug.session".into(),
            payload: json!({"schemaVersion":"1","command":"launch","target":{"applicationId":"7zip","generationId":generation,"launcherId":"main"}}),
        };
        assert!(service.call(request("gen-foreign")).is_err());
        let app = service.get_application("7zip").unwrap().application;
        let staged = service.registry.lifecycle.stage(&app, "job-debug-1").unwrap();
        let config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let binding = &config.runtime_bindings[0];
        let runtime = InstalledRuntime::from_config(
            &config,
            &compatforge_domain::RuntimeSelection {
                provider: compatforge_domain::RuntimeKind::Wine,
                pack_id: binding.pack_id.clone(),
                pack_digest: binding.pack_digest.clone(),
            },
        )
        .unwrap();
        service
            .registry
            .lifecycle
            .bind_runtime(&app.id, "job-debug-1", runtime)
            .unwrap();
        let path = service
            .registry
            .lifecycle
            .launcher_path(&staged, &app.launchers[0].executable);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, include_bytes!("../../../tests/fixtures/hello-x86_64.exe")).unwrap();
        let job: JobRecord = serde_json::from_value(json!({"schemaVersion":"1","id":"job-debug-1","applicationId":"7zip","generationId":staged.id,"kind":"install","status":"succeeded","createdAtMilliseconds":1,"updatedAtMilliseconds":1})).unwrap();
        service.registry.lifecycle.finish(&job).unwrap();
        let error = service.call(request(&staged.id)).unwrap_err();
        assert_eq!(
            error.code(),
            "unavailable",
            "Task 5 must not claim an uninstalled debugger can launch"
        );
        fs::write(&path, b"tampered").unwrap();
        assert_ne!(service.call(request(&staged.id)).unwrap_err().code(), "unavailable");
        let invalid = ServiceRequest {
            payload: json!({"schemaVersion":"1","command":"attachPid","pid":7}),
            ..request(&staged.id)
        };
        assert_eq!(service.call(invalid).unwrap_err().code(), "invalid-request");
    }

    #[test]
    fn lifecycle_dispatcher_is_typed_and_never_deletes_user_files() {
        let service = service();
        service.seed_default_applications().unwrap();
        let response = service
            .call(ServiceRequest {
                schema_version: "1".into(),
                request_id: "lifecycle-list".into(),
                operation: "applications.generations".into(),
                payload: json!({"id":"7zip"}),
            })
            .unwrap();
        assert_eq!(response.result["schemaVersion"], "1");
        assert!(response.result["generations"].as_array().unwrap().is_empty());
        let response = service
            .call(ServiceRequest {
                schema_version: "1".into(),
                request_id: "lifecycle-uninstall".into(),
                operation: "applications.uninstall".into(),
                payload: json!({"id":"7zip"}),
            })
            .unwrap();
        assert!(response.result.get("selectedGeneration").is_none());
        for operation in [
            "applications.uninstall",
            "applications.generations",
            "applications.recover",
        ] {
            let error = service
                .call(ServiceRequest {
                    schema_version: "1".into(),
                    request_id: "reject-extra".into(),
                    operation: operation.into(),
                    payload: json!({"id":"7zip","deleteUserData":true}),
                })
                .unwrap_err();
            assert_eq!(error.code(), "invalid-request");
        }
        let error = service
            .call(ServiceRequest {
                schema_version: "1".into(),
                request_id: "reject-executor".into(),
                operation: "applications.rollback".into(),
                payload: json!({"applicationId":"7zip","generationId":"gen-job-missing","executor":"shell"}),
            })
            .unwrap_err();
        assert_eq!(error.code(), "invalid-request");
        assert!(service.create_bottle("gen-job-foreign").is_err());
    }

    #[test]
    fn managed_bottle_summary_uses_retained_definition_and_disables_archive() {
        let service = service();
        service.seed_default_applications().unwrap();
        let app = service.registry.get_application("7zip").unwrap().application;
        let generation = service.registry.lifecycle.stage(&app, "job-summary").unwrap();
        let config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let binding = &config.runtime_bindings[0];
        let runtime = lifecycle::InstalledRuntime::from_config(
            &config,
            &compatforge_domain::RuntimeSelection {
                provider: compatforge_domain::RuntimeKind::Wine,
                pack_id: binding.pack_id.clone(),
                pack_digest: binding.pack_digest.clone(),
            },
        )
        .unwrap();
        service
            .registry
            .lifecycle
            .bind_runtime(&app.id, "job-summary", runtime)
            .unwrap();
        let path = service
            .registry
            .lifecycle
            .launcher_path(&generation, &app.launchers[0].executable);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, include_bytes!("../../../tests/fixtures/hello-x86_64.exe")).unwrap();
        let job: JobRecord = serde_json::from_value(json!({"schemaVersion":"1", "id":"job-summary", "applicationId":app.id,
            "generationId":generation.id, "kind":"install", "status":"succeeded", "createdAtMilliseconds":1, "updatedAtMilliseconds":1})).unwrap();
        service.registry.lifecycle.finish(&job).unwrap();
        let mut replacement = app.clone();
        replacement.bottle_id = "another-logical-bottle".into();
        replacement.launchers[0].executable = "missing-new-launcher.exe".into();
        service.registry.upsert_application(replacement).unwrap();
        let summary = service.get_bottle(&generation.bottle_id).unwrap();
        assert_eq!(summary.application_ids, std::slice::from_ref(&app.id));
        assert_eq!(summary.installed_launcher_count, 1);
        assert_eq!(summary.status, BottleStatus::Ready);
        assert_eq!(serde_json::to_value(&summary).unwrap()["managed"], true);
        assert_eq!(
            service.archive_bottle(&generation.bottle_id).unwrap_err().code(),
            "conflict"
        );
        // Retained generations keep their identity even after recipe removal.
        service.registry.remove_application(&app.id).unwrap();
        assert_eq!(service.list_bottles().unwrap(), [summary]);
        let legacy = service.create_bottle("manual-bottle").unwrap();
        assert_eq!(serde_json::to_value(legacy).unwrap()["managed"], false);
        assert!(service.archive_bottle("manual-bottle").is_ok());
    }

    #[test]
    fn generic_dispatcher_covers_applications_settings_and_bottles() {
        let service = service();
        service
            .call(ServiceRequest {
                schema_version: SCHEMA_VERSION_V1.into(),
                request_id: "request-01".into(),
                operation: "applications.seed-defaults".into(),
                payload: json!({}),
            })
            .unwrap();
        let response = service
            .call(ServiceRequest {
                schema_version: SCHEMA_VERSION_V1.into(),
                request_id: "request-02".into(),
                operation: "applications.list".into(),
                payload: json!({}),
            })
            .unwrap();
        assert_eq!(response.result.as_array().unwrap().len(), 3);
        let bottle = service
            .call(ServiceRequest {
                schema_version: SCHEMA_VERSION_V1.into(),
                request_id: "request-03".into(),
                operation: "bottles.create".into(),
                payload: json!({ "id": "custom-bottle" }),
            })
            .unwrap();
        assert_eq!(bottle.result["id"], "custom-bottle");
    }
}
