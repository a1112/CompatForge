use crate::model::{
    JobAssessment, JobKind, JobPollResult, JobRecord, JobRequest, JobStatus, MAX_JOB_EVENTS, MAX_POLL_MILLISECONDS,
};
use crate::registry::{now_milliseconds, Registry, RegistryError};
use compatforge_domain::{
    CoreConfig, CpuArchitecture, ExecutableMode, ExecutableRequest, LaunchConstraints, LaunchRequest, NetworkPolicy,
    RuntimeEvent, RuntimeEventKind, SCHEMA_VERSION_V1,
};
use compatforge_inspect::{inspect_path, PeArchitecture};
use compatforge_orchestrator::PreparedLaunch;
use compatforge_process::{EventPoll, LaunchHandle, PreparingLaunch, ProcessSupervisor};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) struct JobManager {
    registry: Arc<Registry>,
    config: CoreConfig,
    active: Mutex<HashMap<String, ActiveJob>>,
    operation: Mutex<()>,
    closing: AtomicBool,
}

struct ActiveJob {
    handle: Arc<JobHandle>,
    record: JobRecord,
    cancel_requested: bool,
}

enum JobHandle {
    Running(LaunchHandle),
    Preparing(PreparingLaunch),
}
impl JobHandle {
    fn start(plan: &compatforge_domain::LaunchPlan) -> Result<Self, compatforge_process::ProcessError> {
        if plan.wine_appearance.is_some() {
            ProcessSupervisor::prepare(plan).map(Self::Preparing)
        } else {
            ProcessSupervisor::start(plan).map(Self::Running)
        }
    }
    fn activate(&self) {
        if let Self::Preparing(handle) = self {
            handle.activate();
        }
    }
    fn next_event(&self, timeout: Duration) -> EventPoll {
        match self {
            Self::Running(handle) => handle.next_event(timeout),
            Self::Preparing(handle) => handle.next_event(timeout),
        }
    }
    fn terminate(&self) -> Result<(), compatforge_process::ProcessError> {
        match self {
            Self::Running(handle) => handle.terminate(),
            Self::Preparing(handle) => handle.terminate(),
        }
    }
}

impl JobManager {
    pub(crate) fn new(registry: Arc<Registry>, config: CoreConfig) -> Self {
        Self {
            registry,
            config,
            active: Mutex::new(HashMap::new()),
            operation: Mutex::new(()),
            closing: AtomicBool::new(false),
        }
    }

    pub(crate) fn submit(&self, request: JobRequest) -> Result<JobRecord, JobError> {
        request.validate().map_err(JobError::Model)?;
        let _operation = self
            .operation
            .lock()
            .map_err(|_| JobError::Conflict("service operation lock is poisoned"))?;
        if self.closing.load(Ordering::Acquire) {
            return Err(JobError::Conflict("service is shutting down"));
        }
        let settings = self.registry.read_settings().map_err(JobError::Registry)?;
        let active_count = self
            .lock_active()?
            .values()
            .filter(|active| !active.record.status.is_terminal())
            .count();
        if active_count >= usize::from(settings.maximum_parallel_jobs) {
            return Err(JobError::Conflict("maximum parallel jobs reached"));
        }

        let application = self
            .registry
            .get_application(&request.application_id)
            .map_err(JobError::Registry)?
            .application;
        if let Some(expected) = request.expected_wine_appearance {
            let matches = match expected {
                crate::model::WineAppearanceExpectation::Default => application.wine_appearance.is_none(),
                crate::model::WineAppearanceExpectation::Classic => {
                    application.wine_appearance == Some(compatforge_domain::WineAppearance::Classic)
                }
            };
            if !matches {
                return Err(JobError::Conflict(
                    "reviewed Wine appearance differs from install expectation",
                ));
            }
        }
        self.registry
            .create_bottle(&application.bottle_id)
            .map_err(JobError::Registry)?;

        let job_id = next_job_id();
        let now = now_milliseconds();
        let mut record = JobRecord {
            schema_version: SCHEMA_VERSION_V1.into(),
            id: job_id.clone(),
            application_id: application.id.clone(),
            kind: request.kind,
            status: JobStatus::Preparing,
            created_at_milliseconds: now,
            updated_at_milliseconds: now,
            inspection: None,
            launch_plan: None,
            events: Vec::new(),
            assessment: None,
            error: None,
        };
        self.registry.write_job(&record).map_err(JobError::Registry)?;

        let start_result = (|| {
            let resolved = self.resolve_launch(&application, &request)?;
            let inspection = inspect_path(&resolved.source).map_err(|error| JobError::Inspection(error.to_string()))?;
            let architecture = map_architecture(inspection.architecture)?;
            let launch_request = LaunchRequest {
                wine_appearance: if request.kind == JobKind::Install {
                    application.wine_appearance
                } else {
                    None
                },
                schema_version: SCHEMA_VERSION_V1.into(),
                request_id: job_id.clone(),
                bottle_id: application.bottle_id.clone(),
                recipe_id: Some(application.id.clone()),
                executable: ExecutableRequest {
                    path: resolved.source.to_string_lossy().into_owned(),
                    architecture,
                    mode: resolved.executable.mode,
                    sha256: resolved.executable.sha256,
                },
                arguments: resolved.arguments,
                environment: resolved.environment,
                constraints: LaunchConstraints {
                    allow_virtual_machine: false,
                    allow_remote: false,
                    requires_kernel_driver: false,
                    requires_direct_x12: false,
                    network_policy: NetworkPolicy::Deny,
                    required_capabilities: Vec::new(),
                },
            };
            let prepared = PreparedLaunch::prepare(&self.config, &resolved.source, &launch_request)
                .map_err(|error| JobError::Preparation(error.to_string()))?;
            record.inspection = Some(serde_json::to_value(prepared.inspection()).map_err(JobError::Serialization)?);
            record.launch_plan = Some(serde_json::to_value(prepared.plan()).map_err(JobError::Serialization)?);
            record.updated_at_milliseconds = now_milliseconds();
            self.registry.write_job(&record).map_err(JobError::Registry)?;
            let plan = prepared
                .authorize(&self.config)
                .map_err(|error| JobError::Preparation(error.to_string()))?;
            JobHandle::start(plan).map_err(|error| JobError::Process(error.to_string()))
        })();

        match start_result {
            Ok(handle) => {
                record.status = if matches!(handle, JobHandle::Preparing(_)) {
                    JobStatus::Preparing
                } else {
                    JobStatus::Running
                };
                record.updated_at_milliseconds = now_milliseconds();
                let handle = Arc::new(handle);
                self.lock_active()?.insert(
                    job_id,
                    ActiveJob {
                        handle: Arc::clone(&handle),
                        record: record.clone(),
                        cancel_requested: false,
                    },
                );
                if let Err(error) = self.registry.write_job(&record) {
                    if matches!(handle.as_ref(), JobHandle::Preparing(_)) {
                        if let Some(state) = self
                            .active
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .get_mut(&record.id)
                        {
                            state.cancel_requested = true;
                            state.record.status = JobStatus::Cancelling;
                            state.record.error = Some("preparing job persistence failed before activation".into());
                        }
                        let _ = handle.terminate();
                    }
                    return Err(JobError::Registry(error));
                }
                handle.activate();
                Ok(record)
            }
            Err(error) => {
                record.status = JobStatus::Failed;
                record.error = Some(error.to_string());
                record.updated_at_milliseconds = now_milliseconds();
                self.registry.write_job(&record).map_err(JobError::Registry)?;
                Err(error)
            }
        }
    }

    pub(crate) fn poll(&self, id: &str, timeout_milliseconds: u64) -> Result<JobPollResult, JobError> {
        if timeout_milliseconds > MAX_POLL_MILLISECONDS {
            return Err(JobError::Invalid("poll timeout exceeds 30000 milliseconds"));
        }
        let handle = {
            let active = self.lock_active()?;
            match active.get(id) {
                Some(job) => Arc::clone(&job.handle),
                None => {
                    let job = self.registry.read_job(id).map_err(JobError::Registry)?;
                    let stream_ended = job.status.is_terminal();
                    return Ok(JobPollResult {
                        job,
                        events: Vec::new(),
                        stream_ended,
                    });
                }
            }
        };

        let mut new_events = Vec::new();
        match handle.next_event(Duration::from_millis(timeout_milliseconds)) {
            EventPoll::Event(event) => new_events.push(event),
            EventPoll::Timeout => {}
            EventPoll::Closed => {}
        }
        while new_events.len() < 64 {
            match handle.next_event(Duration::ZERO) {
                EventPoll::Event(event) => new_events.push(event),
                EventPoll::Timeout | EventPoll::Closed => break,
            }
        }

        let mut active = self.lock_active()?;
        let state = active
            .get_mut(id)
            .ok_or(JobError::Conflict("job changed while polling"))?;
        for event in &new_events {
            apply_event(state, event);
        }
        if state.record.events.len() > MAX_JOB_EVENTS {
            let excess = state.record.events.len() - MAX_JOB_EVENTS;
            state.record.events.drain(..excess);
        }
        state.record.updated_at_milliseconds = now_milliseconds();
        self.registry.write_job(&state.record).map_err(JobError::Registry)?;
        let job = state.record.clone();
        let stream_ended = job.status.is_terminal();
        if stream_ended {
            active.remove(id);
        }
        Ok(JobPollResult {
            job,
            events: new_events,
            stream_ended,
        })
    }

    pub(crate) fn cancel(&self, id: &str) -> Result<JobRecord, JobError> {
        let handle = {
            let mut active = self.lock_active()?;
            let state = active.get_mut(id).ok_or_else(|| match self.registry.read_job(id) {
                Ok(job) if job.status.is_terminal() => JobError::Conflict("job is already terminal"),
                Ok(_) => JobError::Conflict("job is not active in this service process"),
                Err(error) => JobError::Registry(error),
            })?;
            state.cancel_requested = true;
            state.record.status = JobStatus::Cancelling;
            state.record.updated_at_milliseconds = now_milliseconds();
            self.registry.write_job(&state.record).map_err(JobError::Registry)?;
            Arc::clone(&state.handle)
        };
        handle
            .terminate()
            .map_err(|error| JobError::Process(error.to_string()))?;
        self.registry.read_job(id).map_err(JobError::Registry)
    }

    pub(crate) fn assess(&self, id: &str, mut assessment: JobAssessment) -> Result<JobRecord, JobError> {
        assessment.validate().map_err(JobError::Model)?;
        assessment.assessed_at_milliseconds = now_milliseconds();
        let mut active = self.lock_active()?;
        if let Some(state) = active.get_mut(id) {
            state.record.assessment = Some(assessment);
            state.record.updated_at_milliseconds = now_milliseconds();
            self.registry.write_job(&state.record).map_err(JobError::Registry)?;
            return Ok(state.record.clone());
        }
        drop(active);
        let mut record = self.registry.read_job(id).map_err(JobError::Registry)?;
        record.assessment = Some(assessment);
        record.updated_at_milliseconds = now_milliseconds();
        self.registry.write_job(&record).map_err(JobError::Registry)?;
        Ok(record)
    }

    pub(crate) fn shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        let _operation = self.operation.lock().unwrap_or_else(|error| error.into_inner());
        let handles = self
            .lock_active()
            .map(|active| active.values().map(|job| Arc::clone(&job.handle)).collect::<Vec<_>>())
            .unwrap_or_default();
        for handle in handles {
            let _ = handle.terminate();
        }
    }

    fn resolve_launch(
        &self,
        application: &crate::model::ApplicationDefinition,
        request: &JobRequest,
    ) -> Result<ResolvedLaunch, JobError> {
        match request.kind {
            JobKind::Install => {
                let installer = application
                    .installer
                    .as_ref()
                    .ok_or(JobError::Conflict("application has no installer definition"))?;
                let source = PathBuf::from(
                    request
                        .executable_path
                        .as_deref()
                        .ok_or(JobError::Invalid("install job has no executable path"))?,
                );
                let actual_name = source.file_name().and_then(|value| value.to_str());
                if !actual_name.is_some_and(|name| name.eq_ignore_ascii_case(&installer.file_name)) {
                    return Err(JobError::Invalid(
                        "installer file name does not match application definition",
                    ));
                }
                let mut arguments = installer.arguments.clone();
                arguments.extend(request.argument_overrides.clone());
                Ok(ResolvedLaunch {
                    source,
                    executable: ResolvedExecutable {
                        mode: ExecutableMode::ImmutableArtifact,
                        sha256: installer.sha256.clone(),
                    },
                    arguments,
                    environment: request.environment_overrides.clone(),
                })
            }
            JobKind::Launch | JobKind::CompatibilityTest | JobKind::AdaptationTrial => {
                let launcher = match request.launcher_id.as_deref() {
                    Some(id) => application.launchers.iter().find(|launcher| launcher.id == id),
                    None => application.launchers.first(),
                }
                .ok_or(JobError::NotFound("launcher"))?;
                let source = self.registry.launcher_path(application, launcher);
                let mut arguments = launcher.arguments.clone();
                arguments.extend(request.argument_overrides.clone());
                let mut environment = launcher.environment.clone();
                environment.extend(request.environment_overrides.clone());
                Ok(ResolvedLaunch {
                    source,
                    executable: ResolvedExecutable {
                        mode: ExecutableMode::BottleInPlace,
                        sha256: None,
                    },
                    arguments,
                    environment,
                })
            }
        }
    }

    fn lock_active(&self) -> Result<MutexGuard<'_, HashMap<String, ActiveJob>>, JobError> {
        self.active
            .lock()
            .map_err(|_| JobError::Conflict("job registry lock is poisoned"))
    }
}

impl Drop for JobManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ResolvedExecutable {
    mode: ExecutableMode,
    sha256: Option<String>,
}

struct ResolvedLaunch {
    source: PathBuf,
    executable: ResolvedExecutable,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
}

fn apply_event(state: &mut ActiveJob, event: &RuntimeEvent) {
    state.record.events.push(event.clone());
    match event.kind {
        RuntimeEventKind::Exited => {
            let success = event.exit.as_ref().is_some_and(|exit| exit.success);
            state.record.status = if state.record.error.is_some() {
                JobStatus::Failed
            } else if state.cancel_requested {
                JobStatus::Cancelled
            } else if success {
                JobStatus::Succeeded
            } else {
                JobStatus::Failed
            };
            if !success && !state.cancel_requested {
                state.record.error = Some("process exited unsuccessfully".into());
            }
        }
        RuntimeEventKind::Failed => {
            if state.record.error.is_none() {
                state.record.error = event.message.clone().or_else(|| Some("runtime failed".into()));
            }
        }
        RuntimeEventKind::Started => {
            if state.record.status == JobStatus::Preparing {
                state.record.status = JobStatus::Running;
            }
        }
        RuntimeEventKind::Output
        | RuntimeEventKind::TerminateRequested
        | RuntimeEventKind::TimedOut
        | RuntimeEventKind::GracePeriodExpired
        | RuntimeEventKind::WineServerStopRequested => {}
    }
}

fn map_architecture(architecture: PeArchitecture) -> Result<CpuArchitecture, JobError> {
    match architecture {
        PeArchitecture::X86 => Ok(CpuArchitecture::I386),
        PeArchitecture::X86_64 => Ok(CpuArchitecture::X86_64),
        PeArchitecture::Arm | PeArchitecture::Arm64 => Err(JobError::Invalid("ARM PE executables are unsupported")),
    }
}

fn next_job_id() -> String {
    let now = now_milliseconds();
    let counter = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("job-{now}-{counter}")
}

#[derive(Debug)]
pub enum JobError {
    Invalid(&'static str),
    NotFound(&'static str),
    Conflict(&'static str),
    Model(crate::model::ModelError),
    Registry(RegistryError),
    Inspection(String),
    Preparation(String),
    Process(String),
    Serialization(serde_json::Error),
}

impl fmt::Display for JobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::NotFound(message) | Self::Conflict(message) => formatter.write_str(message),
            Self::Model(error) => write!(formatter, "{error}"),
            Self::Registry(error) => write!(formatter, "{error}"),
            Self::Inspection(message) => write!(formatter, "executable inspection failed: {message}"),
            Self::Preparation(message) => write!(formatter, "launch preparation failed: {message}"),
            Self::Process(message) => write!(formatter, "process supervision failed: {message}"),
            Self::Serialization(error) => write!(formatter, "job evidence serialization failed: {error}"),
        }
    }
}

impl std::error::Error for JobError {}
