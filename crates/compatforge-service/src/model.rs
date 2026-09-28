use compatforge_domain::{validate_id, ContractError, RuntimeEvent, SCHEMA_VERSION_V1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};

pub const MAX_APPLICATIONS: usize = 4096;
pub const MAX_LAUNCHERS: usize = 64;
pub const MAX_ARGUMENTS: usize = 256;
pub const MAX_ENVIRONMENT: usize = 256;
pub const MAX_JOB_EVENTS: usize = 4096;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_POLL_MILLISECONDS: u64 = 30_000;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub schema_version: String,
    pub service_root: String,
}

impl ServiceConfig {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_schema(&self.schema_version)?;
        let root = Path::new(&self.service_root);
        if !root.is_absolute() {
            return Err(ModelError::Invalid("serviceRoot must be absolute"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallerDefinition {
    pub file_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LauncherDefinition {
    pub id: String,
    pub name: String,
    pub executable: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationDefinition {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub category: String,
    pub bottle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installer: Option<InstallerDefinition>,
    pub launchers: Vec<LauncherDefinition>,
    #[serde(default)]
    pub compatibility_rating: CompatibilityRating,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl ApplicationDefinition {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_schema(&self.schema_version)?;
        validate_domain_id("application.id", &self.id)?;
        validate_domain_id("application.bottleId", &self.bottle_id)?;
        validate_text("application.name", &self.name)?;
        validate_text("application.version", &self.version)?;
        validate_text("application.publisher", &self.publisher)?;
        validate_text("application.category", &self.category)?;
        if self.launchers.is_empty() || self.launchers.len() > MAX_LAUNCHERS {
            return Err(ModelError::Invalid("application launchers must contain 1..64 entries"));
        }
        if let Some(installer) = &self.installer {
            validate_file_name("installer.fileName", &installer.file_name)?;
            validate_arguments(&installer.arguments)?;
            if let Some(digest) = &installer.sha256 {
                validate_sha256(digest)?;
            }
        }
        let mut launcher_ids = BTreeSet::new();
        for launcher in &self.launchers {
            validate_domain_id("launcher.id", &launcher.id)?;
            if !launcher_ids.insert(launcher.id.as_str()) {
                return Err(ModelError::Invalid("launcher ids must be unique"));
            }
            validate_text("launcher.name", &launcher.name)?;
            validate_relative_path("launcher.executable", &launcher.executable)?;
            validate_arguments(&launcher.arguments)?;
            validate_environment(&launcher.environment)?;
        }
        if self.tags.len() > 256 {
            return Err(ModelError::Invalid("too many application tags"));
        }
        for tag in &self.tags {
            validate_text("application.tags", tag)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CompatibilityRating {
    Excellent,
    Good,
    Limited,
    Experimental,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationRecord {
    pub application: ApplicationDefinition,
    pub created_at_milliseconds: u64,
    pub updated_at_milliseconds: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationStatus {
    Installable,
    Installed,
    Installing,
    Running,
    Failed,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationSummary {
    pub generations: crate::lifecycle::ApplicationGenerations,
    pub application: ApplicationDefinition,
    pub status: ApplicationStatus,
    pub installed: bool,
    pub active_job_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_job_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceSettings {
    pub schema_version: String,
    pub automatic_runtime_discovery: bool,
    pub launch_at_login: bool,
    pub close_to_background: bool,
    pub default_windows_version: WindowsVersion,
    pub default_guest_architecture: GuestArchitecture,
    pub capture_screenshots: bool,
    pub retain_diagnostics_days: u16,
    pub maximum_parallel_jobs: u8,
    pub automatic_rollback: bool,
    pub reduced_motion: bool,
    pub compact_application_grid: bool,
}

impl Default for ServiceSettings {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1.into(),
            automatic_runtime_discovery: true,
            launch_at_login: false,
            close_to_background: false,
            default_windows_version: WindowsVersion::Windows11,
            default_guest_architecture: GuestArchitecture::X86_64,
            capture_screenshots: true,
            retain_diagnostics_days: 30,
            maximum_parallel_jobs: 1,
            automatic_rollback: true,
            reduced_motion: false,
            compact_application_grid: true,
        }
    }
}

impl ServiceSettings {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_schema(&self.schema_version)?;
        if self.retain_diagnostics_days > 3650 {
            return Err(ModelError::Invalid("retainDiagnosticsDays exceeds 3650"));
        }
        if !(1..=16).contains(&self.maximum_parallel_jobs) {
            return Err(ModelError::Invalid("maximumParallelJobs must be between 1 and 16"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowsVersion {
    Windows7,
    Windows10,
    Windows11,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
pub enum GuestArchitecture {
    #[serde(rename = "i386")]
    I386,
    #[serde(rename = "x86_64")]
    X86_64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BottleStatus {
    Ready,
    Empty,
    Archived,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BottleSummary {
    pub id: String,
    pub status: BottleStatus,
    pub application_ids: Vec<String>,
    pub installed_launcher_count: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BottleArchive {
    pub schema_version: String,
    pub archive_id: String,
    pub bottle_id: String,
    pub archived_at_milliseconds: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobKind {
    Install,
    Launch,
    CompatibilityTest,
    AdaptationTrial,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobStatus {
    Preparing,
    Running,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobRequest {
    pub schema_version: String,
    pub application_id: String,
    pub kind: JobKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launcher_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argument_overrides: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment_overrides: BTreeMap<String, String>,
}

impl JobRequest {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_schema(&self.schema_version)?;
        validate_domain_id("job.applicationId", &self.application_id)?;
        if let Some(launcher_id) = &self.launcher_id {
            validate_domain_id("job.launcherId", launcher_id)?;
        }
        validate_arguments(&self.argument_overrides)?;
        validate_environment(&self.environment_overrides)?;
        match self.kind {
            JobKind::Install => {
                if !self.argument_overrides.is_empty() || self.launcher_id.is_some() {
                    return Err(ModelError::Invalid(
                        "managed install jobs cannot override the reviewed recipe",
                    ));
                }
                for (key, value) in &self.environment_overrides {
                    let allowed = match key.as_str() {
                        "DISPLAY" => value.strip_prefix(':').is_some_and(|display| {
                            let parts: Vec<&str> = display.split('.').collect();
                            (1..=2).contains(&parts.len())
                                && parts.iter().all(|part| {
                                    !part.is_empty()
                                        && part.len() <= 5
                                        && part.bytes().all(|byte| byte.is_ascii_digit())
                                })
                        }),
                        "XAUTHORITY" => Path::new(value).is_absolute() && !value.as_bytes().contains(&0),
                        _ => false,
                    };
                    if !allowed {
                        return Err(ModelError::Invalid(
                            "installer environment accepts only local DISPLAY and absolute XAUTHORITY session values",
                        ));
                    }
                }
                let path = self
                    .executable_path
                    .as_deref()
                    .ok_or(ModelError::Invalid("install jobs require executablePath"))?;
                if !Path::new(path).is_absolute() || path.len() > MAX_TEXT_BYTES || path.as_bytes().contains(&0) {
                    return Err(ModelError::Invalid("job executablePath must be absolute"));
                }
            }
            JobKind::Launch | JobKind::CompatibilityTest | JobKind::AdaptationTrial => {
                if self.executable_path.is_some() {
                    return Err(ModelError::Invalid("only install jobs accept executablePath"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_id: Option<String>,
    pub schema_version: String,
    pub id: String,
    pub application_id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub created_at_milliseconds: u64,
    pub updated_at_milliseconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inspection: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_plan: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<RuntimeEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment: Option<JobAssessment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl JobRecord {
    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        validate_schema(&self.schema_version)?;
        validate_domain_id("job.id", &self.id)?;
        validate_domain_id("job.applicationId", &self.application_id)?;
        if let Some(id) = &self.generation_id {
            validate_domain_id("job.generationId", id)?;
        }
        if self.events.len() > MAX_JOB_EVENTS {
            return Err(ModelError::Invalid("too many job events"));
        }
        if let Some(error) = &self.error {
            validate_text("job.error", error)?;
        }
        if let Some(assessment) = &self.assessment {
            assessment.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AssessmentOutcome {
    Accepted,
    Failed,
    Unverified,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckOutcome {
    Passed,
    Failed,
    Blocked,
    Skipped,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCheck {
    pub id: String,
    pub outcome: CheckOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobAssessment {
    pub schema_version: String,
    pub outcome: AssessmentOutcome,
    pub summary: String,
    pub checks: Vec<AssessmentCheck>,
    pub assessed_at_milliseconds: u64,
}

impl JobAssessment {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_schema(&self.schema_version)?;
        validate_text("assessment.summary", &self.summary)?;
        if self.checks.len() > 256 {
            return Err(ModelError::Invalid("assessment checks exceed 256 entries"));
        }
        for check in &self.checks {
            validate_domain_id("assessment.check.id", &check.id)?;
            if let Some(message) = &check.message {
                validate_text("assessment.check.message", message)?;
            }
            if check.evidence.len() > 64 {
                return Err(ModelError::Invalid("assessment evidence exceeds 64 entries per check"));
            }
            for evidence in &check.evidence {
                validate_text("assessment.check.evidence", evidence)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobPollResult {
    pub job: JobRecord,
    pub events: Vec<RuntimeEvent>,
    pub stream_ended: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRequest {
    pub schema_version: String,
    pub request_id: String,
    pub operation: String,
    #[serde(default)]
    pub payload: Value,
}

impl ServiceRequest {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_schema(&self.schema_version)?;
        if serde_json::to_vec(self)
            .map_err(|_| ModelError::Invalid("invalid service request"))?
            .len()
            > crate::transport::MAX_REQUEST_BYTES
        {
            return Err(ModelError::Invalid("service request exceeds 1 MiB"));
        }
        validate_text("requestId", &self.request_id)?;
        validate_domain_id("operation", &self.operation.replace('.', "-"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceResponse {
    pub schema_version: String,
    pub request_id: String,
    pub operation: String,
    pub result: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IdPayload {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ArchivePayload {
    pub archive_id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PollPayload {
    pub id: String,
    #[serde(default)]
    pub timeout_milliseconds: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AssessmentPayload {
    pub id: String,
    pub assessment: JobAssessment,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApplicationPayload {
    pub application: ApplicationDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    Invalid(&'static str),
    Contract(String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Contract(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ModelError {}

fn validate_schema(value: &str) -> Result<(), ModelError> {
    if value == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(ModelError::Invalid("unsupported schemaVersion"))
    }
}

fn validate_domain_id(field: &'static str, value: &str) -> Result<(), ModelError> {
    if value.len() > 128 || value.ends_with('.') {
        return Err(ModelError::Invalid("identifier exceeds portable bounds"));
    }
    validate_id(field, value).map_err(contract_error)
}

fn contract_error(error: ContractError) -> ModelError {
    ModelError::Contract(error.to_string())
}

fn validate_text(_field: &'static str, value: &str) -> Result<(), ModelError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        Err(ModelError::Invalid("text value must contain 1..4096 bytes"))
    } else {
        Ok(())
    }
}

fn validate_file_name(_field: &'static str, value: &str) -> Result<(), ModelError> {
    let path = Path::new(value);
    if value.contains('\\') || value.contains(':') || value.as_bytes().contains(&0) {
        return Err(ModelError::Invalid("path is not portable"));
    }
    if value.is_empty()
        || value.len() > 255
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        Err(ModelError::Invalid("file name must be one portable component"))
    } else {
        Ok(())
    }
}

fn validate_relative_path(_field: &'static str, value: &str) -> Result<(), ModelError> {
    let path = Path::new(value);
    if value.contains('\\') || value.contains(':') || value.as_bytes().contains(&0) {
        return Err(ModelError::Invalid("path is not portable"));
    }
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(ModelError::Invalid(
            "launcher executable must be a bounded relative path",
        ))
    } else {
        Ok(())
    }
}

fn validate_arguments(arguments: &[String]) -> Result<(), ModelError> {
    if arguments.len() > MAX_ARGUMENTS || arguments.iter().any(|value| value.len() > MAX_TEXT_BYTES) {
        Err(ModelError::Invalid("argument list exceeds limits"))
    } else {
        Ok(())
    }
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), ModelError> {
    if environment.len() > MAX_ENVIRONMENT
        || environment
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 256 || value.len() > MAX_TEXT_BYTES)
    {
        Err(ModelError::Invalid("environment overrides exceed limits"))
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str) -> Result<(), ModelError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ModelError::Invalid("installer sha256 must contain 64 hex characters"))
    }
}
