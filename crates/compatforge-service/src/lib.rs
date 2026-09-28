//! Persistent application, Bottle, settings and automation job service.

#![forbid(unsafe_code)]

pub mod bootstrap;
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

use jobs::{JobError, JobManager};
pub use jobs::{ShutdownError, ShutdownFailure, ShutdownPhase};
use model::{ApplicationPayload, ArchivePayload, AssessmentPayload, IdPayload, PollPayload};
use registry::{Registry, RegistryError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

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
        Ok(Self { registry, jobs })
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
            "applications.seed-defaults" => {
                self.seed_default_applications()?;
                json!({ "seeded": true })
            }
            "applications.list" => to_value(self.list_applications()?)?,
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
}

impl ServiceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::Model(_) | Self::Json(_) => "invalid-request",
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
