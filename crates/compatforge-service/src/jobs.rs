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
use compatforge_process::{EventPoll, LaunchHandle, ProcessSupervisor};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) struct JobManager {
    registry: Arc<Registry>,
    config: CoreConfig,
    active: Mutex<HashMap<String, ActiveJob>>,
}

struct ActiveJob {
    handle: Arc<dyn JobProcess>,
    record: JobRecord,
    cancel_requested: bool,
    cleanup_join_failed: bool,
}

trait JobProcess: ShutdownTarget + Send + Sync {
    fn next_event(&self, timeout: Duration) -> EventPoll;
}

impl JobProcess for LaunchHandle {
    fn next_event(&self, timeout: Duration) -> EventPoll {
        LaunchHandle::next_event(self, timeout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownFailure {
    pub job_id: Option<String>,
    pub phase: ShutdownPhase,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    Snapshot,
    Terminate,
    Join,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownError {
    pub failures: Vec<ShutdownFailure>,
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} process cleanup operation(s) failed", self.failures.len())
    }
}

impl std::error::Error for ShutdownError {}

trait ShutdownTarget {
    fn request_stop(&self) -> Result<(), String>;
    fn wait_for_stop(&self, grace: Duration) -> Result<(), String>;
}

impl ShutdownTarget for LaunchHandle {
    fn request_stop(&self) -> Result<(), String> {
        self.terminate().map_err(|error| error.to_string())
    }
    fn wait_for_stop(&self, grace: Duration) -> Result<(), String> {
        self.terminate_and_wait(grace).map_err(|error| error.to_string())
    }
}

impl<T: ShutdownTarget + ?Sized> ShutdownTarget for Arc<T> {
    fn request_stop(&self) -> Result<(), String> {
        self.as_ref().request_stop()
    }
    fn wait_for_stop(&self, grace: Duration) -> Result<(), String> {
        self.as_ref().wait_for_stop(grace)
    }
}

fn shutdown_handles(handles: &[(String, impl ShutdownTarget)], grace: Duration) -> Result<(), ShutdownError> {
    let mut failures = Vec::new();
    // Request every stop before waiting for any one process. An error from one
    // supervisor must not prevent stopping or joining the remaining jobs.
    for (job_id, handle) in handles {
        if let Err(message) = handle.request_stop() {
            failures.push(ShutdownFailure {
                job_id: Some(job_id.clone()),
                phase: ShutdownPhase::Terminate,
                message,
            });
        }
    }
    for (job_id, handle) in handles {
        if let Err(message) = handle.wait_for_stop(grace) {
            failures.push(ShutdownFailure {
                job_id: Some(job_id.clone()),
                phase: ShutdownPhase::Join,
                message,
            });
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ShutdownError { failures })
    }
}

impl JobManager {
    pub(crate) fn new(registry: Arc<Registry>, config: CoreConfig) -> Self {
        Self {
            registry,
            config,
            active: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn submit(&self, request: JobRequest) -> Result<JobRecord, JobError> {
        request.validate().map_err(JobError::Model)?;
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
            ProcessSupervisor::start(plan).map_err(|error| JobError::Process(error.to_string()))
        })();

        match start_result {
            Ok(handle) => self.adopt_started_job(record, Arc::new(handle)),
            Err(error) => {
                record.status = JobStatus::Failed;
                record.error = Some(error.to_string());
                record.updated_at_milliseconds = now_milliseconds();
                self.registry.write_job(&record).map_err(JobError::Registry)?;
                Err(error)
            }
        }
    }

    fn adopt_started_job(&self, mut record: JobRecord, handle: Arc<dyn JobProcess>) -> Result<JobRecord, JobError> {
        record.status = JobStatus::Running;
        record.updated_at_milliseconds = now_milliseconds();
        // A started process must acquire a cleanup owner before any fallible
        // post-start persistence. Recover solely to retain ownership if the map
        // was poisoned; ordinary operations still fail closed through lock_active.
        self.active.lock().unwrap_or_else(|error| error.into_inner()).insert(
            record.id.clone(),
            ActiveJob {
                handle,
                record: record.clone(),
                cancel_requested: false,
                cleanup_join_failed: false,
            },
        );
        self.registry.write_job(&record).map_err(JobError::Registry)?;
        Ok(record)
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
        let mut job = state.record.clone();
        let stream_ended = job.status.is_terminal();
        let needs_join = stream_ended && !state.cleanup_join_failed;
        drop(active);
        if needs_join {
            // Exited describes the guest, not the supervisor's cleanup result.
            // This terminal-only acknowledgement has the existing supervisor's
            // 16-second forced-completion bound, separate from the event timeout.
            // Do not hold the job map while waiting or hide a failed join.
            let cleanup = handle.wait_for_stop(Duration::ZERO);
            let mut active = self.lock_active()?;
            if let Some(state) = active.get_mut(id) {
                match cleanup {
                    Ok(()) => {
                        job = state.record.clone();
                        active.remove(id);
                    }
                    Err(message) => {
                        state.cleanup_join_failed = true;
                        state.record.status = JobStatus::Failed;
                        let detail = format!("process cleanup not confirmed: {message}");
                        state.record.error = Some(match state.record.error.take() {
                            Some(previous) => format!("{previous}; {detail}"),
                            None => detail,
                        });
                        state.record.updated_at_milliseconds = now_milliseconds();
                        self.registry.write_job(&state.record).map_err(JobError::Registry)?;
                        job = state.record.clone();
                    }
                }
            }
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
            if state.record.status.is_terminal() {
                return Err(JobError::Conflict("job is already terminal"));
            }
            state.cancel_requested = true;
            state.record.status = JobStatus::Cancelling;
            state.record.updated_at_milliseconds = now_milliseconds();
            self.registry.write_job(&state.record).map_err(JobError::Registry)?;
            Arc::clone(&state.handle)
        };
        handle.request_stop().map_err(JobError::Process)?;
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
        for (_, handle) in self.owned_cleanup_handles() {
            let _ = handle.request_stop();
        }
    }

    pub(crate) fn shutdown_and_wait(&self) -> Result<(), ShutdownError> {
        let handles = self.owned_cleanup_handles();
        shutdown_handles(
            &handles,
            Duration::from_millis(self.config.supervisor.termination_grace_milliseconds),
        )
    }

    fn owned_cleanup_handles(&self) -> Vec<(String, Arc<dyn JobProcess>)> {
        // Poison must not make already owned processes disappear from shutdown.
        // This only snapshots handles for cleanup; it does not resume mutations.
        self.active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .map(|(id, job)| (id.clone(), Arc::clone(&job.handle)))
            .collect()
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
        RuntimeEventKind::Started
        | RuntimeEventKind::Output
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

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use compatforge_domain::{LaunchPlan, NativeCommand, ProcessLifecycle};

    struct CompletedProcess {
        events: Mutex<std::collections::VecDeque<RuntimeEvent>>,
        cleanup_failed: bool,
        joins: AtomicU64,
    }

    impl ShutdownTarget for CompletedProcess {
        fn request_stop(&self) -> Result<(), String> {
            Ok(())
        }
        fn wait_for_stop(&self, grace: Duration) -> Result<(), String> {
            assert!(grace <= Duration::from_millis(20));
            self.joins.fetch_add(1, Ordering::SeqCst);
            if self.cleanup_failed {
                Err("supervisor cleanup failed".into())
            } else {
                Ok(())
            }
        }
    }

    impl JobProcess for CompletedProcess {
        fn next_event(&self, _: Duration) -> EventPoll {
            self.events
                .lock()
                .unwrap()
                .pop_front()
                .map_or(EventPoll::Closed, EventPoll::Event)
        }
    }

    fn terminal_poll_fixture(cleanup_failed: bool) -> (JobManager, Arc<CompletedProcess>, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "compatforge-terminal-poll-{}-{}",
            std::process::id(),
            JOB_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let mut config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        config.storage_root = root.join("storage").to_string_lossy().into_owned();
        config.supervisor.termination_grace_milliseconds = 20;
        let registry = Arc::new(Registry::new(root.join("service"), root.join("storage")).unwrap());
        let manager = JobManager::new(registry, config);
        let mut events = std::collections::VecDeque::new();
        if cleanup_failed {
            events.push_back(serde_json::from_value(serde_json::json!({
                "schemaVersion":"1", "sequence":1, "kind":"failed", "requestId":"cleanup-job", "elapsedMilliseconds":1,
                "message":"supervisor cleanup failed"
            })).unwrap());
        }
        events.push_back(
            serde_json::from_value(serde_json::json!({
                "schemaVersion":"1", "sequence":2, "kind":"exited", "requestId":"cleanup-job", "elapsedMilliseconds":2,
                "exit":{"code":0,"success":true}
            }))
            .unwrap(),
        );
        let handle = Arc::new(CompletedProcess {
            events: Mutex::new(events),
            cleanup_failed,
            joins: AtomicU64::new(0),
        });
        let record = JobRecord {
            schema_version: SCHEMA_VERSION_V1.into(),
            id: "cleanup-job".into(),
            application_id: "cleanup-test".into(),
            kind: JobKind::Launch,
            status: JobStatus::Running,
            created_at_milliseconds: 1,
            updated_at_milliseconds: 1,
            inspection: None,
            launch_plan: None,
            events: Vec::new(),
            assessment: None,
            error: None,
        };
        manager.active.lock().unwrap().insert(
            record.id.clone(),
            ActiveJob {
                handle: handle.clone(),
                record,
                cancel_requested: false,
                cleanup_join_failed: false,
            },
        );
        (manager, handle, root)
    }

    #[test]
    fn post_start_persistence_failure_retains_real_handle_for_error_exit_cleanup() {
        let (manager, _, root) = terminal_poll_fixture(false);
        let mut record = manager.active.lock().unwrap().remove("cleanup-job").unwrap().record;
        record.status = JobStatus::Preparing;
        manager.registry.write_job(&record).unwrap();
        let mut plan: LaunchPlan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
        plan.process = NativeCommand {
            executable: std::env::current_exe().unwrap().to_string_lossy().into_owned(),
            arguments: vec![
                "--exact".into(),
                "jobs::shutdown_tests::sleeping_child_helper".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            environment: BTreeMap::from([("COMPATFORGE_SERVICE_SHUTDOWN_HELPER".into(), "sleep".into())]),
            working_directory: std::env::current_dir().unwrap().to_string_lossy().into_owned(),
        };
        plan.mounts.clear();
        plan.graphics.backend = compatforge_domain::GraphicsBackendKind::WineD3d;
        plan.graphics.version = None;
        plan.translator.provider = compatforge_domain::TranslatorKind::Native;
        plan.translator.version = None;
        plan.lifecycle = ProcessLifecycle::default();
        plan.lifecycle.maximum_runtime_milliseconds = Some(10_000);
        let handle = Arc::new(ProcessSupervisor::start(&plan).unwrap());
        assert!(
            matches!(handle.next_event(Duration::from_secs(5)), EventPoll::Event(event) if event.kind == RuntimeEventKind::Started)
        );
        // Model a destination/rename failure after the process has really
        // started, without making the pre-start Preparing write fail.
        let job_path = root.join("service/jobs/cleanup-job.json");
        std::fs::remove_file(&job_path).unwrap();
        std::fs::create_dir(&job_path).unwrap();
        assert!(matches!(
            manager.adopt_started_job(record, handle.clone()),
            Err(JobError::Registry(_))
        ));
        assert!(
            manager.active.lock().unwrap().contains_key("cleanup-job"),
            "live handle was lost after post-start persistence failure"
        );
        manager.shutdown_and_wait().unwrap();
        assert!(handle.is_finished());
        handle.terminate_and_wait(Duration::ZERO).unwrap();
        drop(manager);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_does_not_lose_owned_handles_when_the_job_map_is_poisoned() {
        let (manager, handle, root) = terminal_poll_fixture(false);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _active = manager.active.lock().unwrap();
            panic!("injected job-map failure");
        }))
        .is_err());
        assert!(
            manager.lock_active().is_err(),
            "ordinary mutations must remain fail closed"
        );
        manager.shutdown_and_wait().unwrap();
        assert_eq!(handle.joins.load(Ordering::SeqCst), 1);
        drop(manager);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn poll_preserves_failed_cleanup_for_close_and_failure_is_not_overwritten_by_successful_exit() {
        let (manager, handle, root) = terminal_poll_fixture(true);
        let polled = manager.poll("cleanup-job", 0).unwrap();
        assert_eq!(polled.job.status, JobStatus::Failed);
        assert!(polled.stream_ended);
        assert!(manager.active.lock().unwrap().contains_key("cleanup-job"));
        assert_eq!(manager.poll("cleanup-job", 0).unwrap().job.status, JobStatus::Failed);
        assert_eq!(
            handle.joins.load(Ordering::SeqCst),
            1,
            "ordinary repeat poll must not repeat failed cleanup waits"
        );
        let failure = manager.shutdown_and_wait().unwrap_err();
        assert!(failure
            .failures
            .iter()
            .any(|failure| failure.job_id.as_deref() == Some("cleanup-job") && failure.phase == ShutdownPhase::Join));
        assert!(handle.joins.load(Ordering::SeqCst) >= 2);
        drop(manager);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn poll_reclaims_successful_terminal_handle_only_after_join_acknowledgement() {
        let (manager, handle, root) = terminal_poll_fixture(false);
        let polled = manager.poll("cleanup-job", 0).unwrap();
        assert_eq!(polled.job.status, JobStatus::Succeeded);
        assert!(polled.stream_ended);
        assert_eq!(handle.joins.load(Ordering::SeqCst), 1);
        assert!(!manager.active.lock().unwrap().contains_key("cleanup-job"));
        manager.shutdown_and_wait().unwrap();
        drop(manager);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_cleanup_failure_cannot_be_changed_back_to_cancelling() {
        let (manager, _, root) = terminal_poll_fixture(true);
        manager.poll("cleanup-job", 0).unwrap();
        assert!(matches!(
            manager.cancel("cleanup-job"),
            Err(JobError::Conflict("job is already terminal"))
        ));
        assert_eq!(
            manager.registry.read_job("cleanup-job").unwrap().status,
            JobStatus::Failed
        );
        drop(manager);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_runtime_event_is_sticky_even_when_cleanup_join_succeeds() {
        let (manager, handle, root) = terminal_poll_fixture(false);
        handle.events.lock().unwrap().push_front(
            serde_json::from_value(serde_json::json!({
                "schemaVersion":"1", "sequence":1, "kind":"failed", "requestId":"cleanup-job", "elapsedMilliseconds":1,
                "message":"runtime reported failure"
            }))
            .unwrap(),
        );
        let polled = manager.poll("cleanup-job", 0).unwrap();
        assert_eq!(polled.job.status, JobStatus::Failed);
        assert_eq!(polled.job.error.as_deref(), Some("runtime reported failure"));
        assert_eq!(handle.joins.load(Ordering::SeqCst), 1);
        assert!(!manager.active.lock().unwrap().contains_key("cleanup-job"));
        manager.shutdown_and_wait().unwrap();
        drop(manager);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shutdown_attempts_all_handles_and_preserves_every_failure() {
        struct Target {
            id: &'static str,
            events: Arc<Mutex<Vec<String>>>,
        }
        impl ShutdownTarget for Target {
            fn request_stop(&self) -> Result<(), String> {
                self.events.lock().unwrap().push(format!("stop-{}", self.id));
                if self.id == "first" {
                    Err("stop failure".into())
                } else {
                    Ok(())
                }
            }
            fn wait_for_stop(&self, _: Duration) -> Result<(), String> {
                self.events.lock().unwrap().push(format!("join-{}", self.id));
                if self.id == "first" {
                    Err("join failure".into())
                } else {
                    Ok(())
                }
            }
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let handles = ["first", "second"].map(|id| {
            (
                id.to_owned(),
                Target {
                    id,
                    events: events.clone(),
                },
            )
        });
        let error = shutdown_handles(&handles, Duration::ZERO).unwrap_err();
        assert_eq!(
            *events.lock().unwrap(),
            ["stop-first", "stop-second", "join-first", "join-second"]
        );
        assert_eq!(error.failures.len(), 2);
        assert_eq!(error.failures[0].phase, ShutdownPhase::Terminate);
        assert_eq!(error.failures[1].phase, ShutdownPhase::Join);
        assert!(error
            .failures
            .iter()
            .all(|failure| failure.job_id.as_deref() == Some("first")));
    }

    #[test]
    fn active_job_shutdown_waits_for_real_supervisor_completion() {
        let root = std::env::temp_dir().join(format!(
            "compatforge-shutdown-{}-{}",
            std::process::id(),
            now_milliseconds()
        ));
        let mut config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        config.storage_root = root.join("storage").to_string_lossy().into_owned();
        config.supervisor.termination_grace_milliseconds = 20;
        let registry = Arc::new(Registry::new(root.join("service"), root.join("storage")).unwrap());
        let manager = JobManager::new(registry, config);
        let mut plan: LaunchPlan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
        plan.process = NativeCommand {
            executable: std::env::current_exe().unwrap().to_string_lossy().into_owned(),
            arguments: vec![
                "--exact".into(),
                "jobs::shutdown_tests::sleeping_child_helper".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            environment: BTreeMap::from([("COMPATFORGE_SERVICE_SHUTDOWN_HELPER".into(), "sleep".into())]),
            working_directory: std::env::current_dir().unwrap().to_string_lossy().into_owned(),
        };
        plan.mounts.clear();
        plan.graphics.backend = compatforge_domain::GraphicsBackendKind::WineD3d;
        plan.graphics.version = None;
        plan.translator.provider = compatforge_domain::TranslatorKind::Native;
        plan.translator.version = None;
        plan.lifecycle = ProcessLifecycle::default();
        plan.lifecycle.maximum_runtime_milliseconds = Some(10_000);
        let handle = Arc::new(ProcessSupervisor::start(&plan).unwrap());
        let event = handle.next_event(Duration::from_secs(5));
        assert!(matches!(event, EventPoll::Event(event) if event.kind == RuntimeEventKind::Started));
        let record = JobRecord {
            schema_version: SCHEMA_VERSION_V1.into(),
            id: "cleanup-job".into(),
            application_id: "cleanup-test".into(),
            kind: JobKind::Launch,
            status: JobStatus::Running,
            created_at_milliseconds: 1,
            updated_at_milliseconds: 1,
            inspection: None,
            launch_plan: None,
            events: Vec::new(),
            assessment: None,
            error: None,
        };
        manager.active.lock().unwrap().insert(
            record.id.clone(),
            ActiveJob {
                handle: handle.clone(),
                record,
                cancel_requested: false,
                cleanup_join_failed: false,
            },
        );
        assert!(!handle.is_finished());
        let lifecycle = Arc::new(crate::desktop_lifecycle::DesktopLifecycle::default());
        let in_flight = lifecycle.admit().unwrap();
        assert!(lifecycle.begin_close());
        let closing = lifecycle.clone();
        let caller = std::thread::current().id();
        let cleanup = std::thread::spawn(move || {
            closing.wait_for_workers();
            manager.shutdown_and_wait().unwrap();
            drop(manager);
            closing.complete_cleanup();
            std::thread::current().id()
        });
        assert!(!lifecycle.cleanup_complete());
        drop(in_flight);
        assert_ne!(cleanup.join().unwrap(), caller);
        assert!(lifecycle.cleanup_complete());
        assert!(handle.is_finished(), "shutdown returned before supervisor completion");
        // Repeated cleanup must acknowledge completed worker joins, not merely
        // observe the guest's exit or a requested termination.
        handle.terminate_and_wait(Duration::ZERO).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "spawned only as the bounded supervisor child"]
    fn sleeping_child_helper() {
        if std::env::var("COMPATFORGE_SERVICE_SHUTDOWN_HELPER").as_deref() == Ok("sleep") {
            std::thread::sleep(Duration::from_secs(10));
        }
    }
}
