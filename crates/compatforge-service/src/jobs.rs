use crate::lifecycle::{ApplicationGenerations, InstalledRuntime, RollbackRequest};
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
    active_debug: Mutex<HashMap<String, DebugLease>>,
    operation: Mutex<()>,
}

pub(crate) struct SelectedDebugTarget {
    pub executable: PathBuf,
}

struct ActiveJob {
    handle: Arc<dyn JobProcess>,
    record: JobRecord,
    cancel_requested: bool,
    cleanup_join_failed: bool,
    polling: Arc<Mutex<()>>,
}

struct DebugLease {
    application_id: String,
    bottle_id: String,
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
    Persist,
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
    /// Keep the lifecycle operation gate held until the provider has started.
    /// Rollback and uninstall acquire the same gate, so a selected generation
    /// cannot change between validation and process creation.
    pub(crate) fn launch_selected_debug_session(
        &self,
        target: &compatforge_debug::DebugTarget,
        launch: impl FnOnce(SelectedDebugTarget) -> Result<compatforge_debug::DebugSessionHandle, crate::ServiceError>,
    ) -> Result<compatforge_debug::DebugSessionHandle, crate::ServiceError> {
        let _operation = self.lock_operation().map_err(crate::ServiceError::Job)?;
        let mut active_debug = self
            .active_debug
            .lock()
            .map_err(|_| crate::ServiceError::Conflict("debug lease lock is poisoned"))?;
        let generation = self
            .registry
            .lifecycle
            .selected(&target.application_id)
            .map_err(crate::ServiceError::Registry)?;
        if generation.id != target.generation_id {
            return Err(crate::ServiceError::Debug(compatforge_debug::DebugError::Unauthorized));
        }
        generation
            .runtime
            .as_ref()
            .ok_or(crate::ServiceError::Conflict("selected generation has no runtime"))?
            .check_config(&self.config)
            .map_err(crate::ServiceError::Registry)?;
        self.registry
            .lifecycle
            .verify_launchers(&generation)
            .map_err(crate::ServiceError::Registry)?;
        let launcher = generation
            .definition
            .launchers
            .iter()
            .find(|launcher| launcher.id == target.launcher_id)
            .ok_or(crate::ServiceError::Debug(compatforge_debug::DebugError::Unauthorized))?;
        let selected = SelectedDebugTarget {
            executable: self.registry.lifecycle.launcher_path(&generation, &launcher.executable),
        };
        let handle = launch(selected)?;
        active_debug.insert(
            handle.session_id.clone(),
            DebugLease {
                application_id: target.application_id.clone(),
                bottle_id: generation.definition.bottle_id,
            },
        );
        Ok(handle)
    }

    /// Call only after the debug provider confirms that its owned process tree
    /// has stopped. Failed cleanup retains the lease and blocks lifecycle edits.
    pub(crate) fn end_debug_session(&self, session_id: &str) -> Result<(), JobError> {
        let _operation = self.lock_operation()?;
        self.active_debug
            .lock()
            .map_err(|_| JobError::Conflict("debug lease lock is poisoned"))?
            .remove(session_id);
        Ok(())
    }

    pub(crate) fn clear_debug_sessions(&self) -> Result<(), JobError> {
        let _operation = self.lock_operation()?;
        self.active_debug
            .lock()
            .map_err(|_| JobError::Conflict("debug lease lock is poisoned"))?
            .clear();
        Ok(())
    }

    pub(crate) fn poll_active_jobs(&self) -> Result<(), JobError> {
        let ids: Vec<String> = self.lock_active()?.keys().cloned().collect();
        for id in ids {
            match self.poll(&id, 0) {
                Ok(_) | Err(JobError::Conflict("job is already being polled")) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn desktop_launchers(&self) -> Result<Vec<crate::desktop::DesktopLauncher>, crate::ServiceError> {
        let _operation = self.lock_operation().map_err(crate::ServiceError::Job)?;
        let mut entries = Vec::new();
        for state in self
            .registry
            .lifecycle
            .all_states()
            .map_err(crate::ServiceError::Registry)?
        {
            if state.selected_generation.is_none() {
                continue;
            }
            let generation = self
                .registry
                .lifecycle
                .selected(&state.application_id)
                .map_err(crate::ServiceError::Registry)?;
            generation
                .runtime
                .as_ref()
                .ok_or(crate::ServiceError::Conflict("selected generation has no runtime"))?
                .check_config(&self.config)
                .map_err(crate::ServiceError::Registry)?;
            self.registry
                .lifecycle
                .verify_launchers(&generation)
                .map_err(crate::ServiceError::Registry)?;
            entries.extend(crate::desktop::from_generation(&generation)?);
        }
        Ok(entries)
    }

    pub(crate) fn new(registry: Arc<Registry>, config: CoreConfig) -> Self {
        Self {
            registry,
            config,
            active: Mutex::new(HashMap::new()),
            active_debug: Mutex::new(HashMap::new()),
            operation: Mutex::new(()),
        }
    }

    pub(crate) fn submit(&self, request: JobRequest) -> Result<JobRecord, JobError> {
        request.validate().map_err(JobError::Model)?;
        let _operation = self.lock_operation()?;
        let settings = self.registry.read_settings().map_err(JobError::Registry)?;
        let active_count = self.lock_active()?.len();
        if active_count >= usize::from(settings.maximum_parallel_jobs) {
            return Err(JobError::Conflict("maximum parallel jobs reached"));
        }

        let application = self
            .registry
            .get_application(&request.application_id)
            .map_err(JobError::Registry)?
            .application;
        self.ensure_idle(&application.id, &application.bottle_id)?;

        let job_id = next_job_id();
        let now = now_milliseconds();
        let mut record = JobRecord {
            generation_id: None,
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
            let generation = if request.kind == JobKind::Install {
                self.registry.lifecycle.stage(&application, &job_id)
            } else {
                let selected = self
                    .registry
                    .lifecycle
                    .selected(&application.id)
                    .map_err(JobError::Registry)?;
                self.ensure_idle(&application.id, &selected.definition.bottle_id)?;
                self.registry
                    .lifecycle
                    .begin_launch(&application.id, &job_id, request.kind)
            }
            .map_err(JobError::Registry)?;
            record.generation_id = Some(generation.id.clone());
            self.registry.write_job(&record).map_err(JobError::Registry)?;
            if let Some(runtime) = &generation.runtime {
                runtime.check_config(&self.config).map_err(JobError::Registry)?;
            }
            let resolved = self.resolve_launch(&generation, &request)?;
            let inspection = inspect_path(&resolved.source).map_err(|error| JobError::Inspection(error.to_string()))?;
            let architecture = map_architecture(inspection.architecture)?;
            let launch_request = LaunchRequest {
                schema_version: SCHEMA_VERSION_V1.into(),
                request_id: job_id.clone(),
                bottle_id: generation.bottle_id.clone(),
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
            let runtime =
                InstalledRuntime::from_config(&self.config, &prepared.plan().runtime).map_err(JobError::Registry)?;
            if request.kind == JobKind::Install {
                self.registry
                    .lifecycle
                    .bind_runtime(&application.id, &job_id, runtime)
                    .map_err(JobError::Registry)?;
            } else if generation.runtime.as_ref() != Some(&runtime) {
                return Err(JobError::Conflict(
                    "prepared runtime differs from the installed generation",
                ));
            }
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
                record.error = Some(crate::lifecycle::bounded_error(&error.to_string()));
                record.updated_at_milliseconds = now_milliseconds();
                self.registry.write_job(&record).map_err(JobError::Registry)?;
                if record.generation_id.is_some() {
                    if matches!(error, JobError::Process(_)) {
                        self.registry
                            .lifecycle
                            .quarantine(
                                &record.application_id,
                                "runtime startup failed; cleanup is not independently confirmed",
                            )
                            .map_err(JobError::Registry)?;
                    } else {
                        self.registry.lifecycle.finish(&record).map_err(JobError::Registry)?;
                    }
                }
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
                polling: Arc::new(Mutex::new(())),
            },
        );
        self.registry.write_job(&record).map_err(JobError::Registry)?;
        Ok(record)
    }

    pub(crate) fn poll(&self, id: &str, timeout_milliseconds: u64) -> Result<JobPollResult, JobError> {
        if timeout_milliseconds > MAX_POLL_MILLISECONDS {
            return Err(JobError::Invalid("poll timeout exceeds 30000 milliseconds"));
        }
        let (handle, polling) = {
            let active = self.lock_active()?;
            match active.get(id) {
                Some(job) => (Arc::clone(&job.handle), Arc::clone(&job.polling)),
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

        // One consumer owns receive -> apply -> cleanup acknowledgement ->
        // generation commit. A second poll must not take an exit past an adverse
        // event already consumed by the first. Reject contention promptly, and
        // never hold the job map or service operation lock while receiving.
        let _poll = polling.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => JobError::Conflict("job is already being polled"),
            std::sync::TryLockError::Poisoned(_) => JobError::Conflict("job poll lock is poisoned"),
        })?;
        if !self.lock_active()?.contains_key(id) {
            let job = self.registry.read_job(id).map_err(JobError::Registry)?;
            let stream_ended = job.status.is_terminal();
            return Ok(JobPollResult {
                job,
                events: Vec::new(),
                stream_ended,
            });
        }

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
        if new_events.is_empty() && !state.record.status.is_terminal() {
            return Ok(JobPollResult {
                job: state.record.clone(),
                events: Vec::new(),
                stream_ended: false,
            });
        }
        for event in &new_events {
            apply_event(state, event);
        }
        if state.record.events.len() > MAX_JOB_EVENTS {
            let excess = state.record.events.len() - MAX_JOB_EVENTS;
            state.record.events.drain(..excess);
        }
        state.record.updated_at_milliseconds = now_milliseconds();
        let mut observed = state.record.clone();
        if observed.status == JobStatus::Succeeded {
            observed.status = JobStatus::Running;
        }
        self.registry.write_job(&observed).map_err(JobError::Registry)?;
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
            let _operation = self.lock_operation()?;
            let mut active = self.lock_active()?;
            if let Some(state) = active.get_mut(id) {
                match cleanup {
                    Ok(()) => {
                        // Shutdown may have requested cancellation while this
                        // terminal poll was acknowledging supervisor completion.
                        if state.record.status == JobStatus::Cancelling {
                            state.record.status = JobStatus::Cancelled;
                        }
                        // Persist terminal evidence before the one atomic generation
                        // selection. A crash in between leaves the lease quarantined.
                        self.registry.write_job(&state.record).map_err(JobError::Registry)?;
                        if let Err(error) = self.registry.lifecycle.finish(&state.record) {
                            state.record.status = JobStatus::Failed;
                            state.record.error = Some(crate::lifecycle::bounded_error(&error.to_string()));
                            self.registry.write_job(&state.record).map_err(JobError::Registry)?;
                        }
                        job = state.record.clone();
                        active.remove(id);
                    }
                    Err(message) => {
                        state.cleanup_join_failed = true;
                        self.registry
                            .lifecycle
                            .quarantine(
                                &state.record.application_id,
                                "supervisor cleanup failed; recovery required",
                            )
                            .map_err(JobError::Registry)?;
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
        {
            let mut active = self.active.lock().unwrap_or_else(|error| error.into_inner());
            for (id, _) in &handles {
                if let Some(state) = active.get_mut(id) {
                    // A poll already receiving must see cancellation before its
                    // successful exit can become an activation during shutdown.
                    state.cancel_requested = true;
                    if !state.record.status.is_terminal() || state.record.status == JobStatus::Succeeded {
                        state.record.status = JobStatus::Cancelling;
                    }
                }
            }
        }
        shutdown_handles(
            &handles,
            Duration::from_millis(self.config.supervisor.termination_grace_milliseconds),
        )?;
        let mut failures = Vec::new();
        for (id, _) in &handles {
            let polling = {
                let active = self.active.lock().unwrap_or_else(|error| error.into_inner());
                active.get(id).map(|state| Arc::clone(&state.polling))
            };
            let Some(polling) = polling else {
                continue;
            };
            // Match poll's lock order: per-job gate -> operation -> job map.
            // Cleanup recovers poisoned gates only to retain process ownership.
            let _poll = polling.lock().unwrap_or_else(|error| error.into_inner());
            let _operation = self.operation.lock().unwrap_or_else(|error| error.into_inner());
            let mut active = self.active.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(state) = active.get_mut(id) {
                // Closing never activates an installer based on an unconsumed exit.
                if !state.record.status.is_terminal() || state.record.status == JobStatus::Succeeded {
                    state.record.status = JobStatus::Cancelled;
                    state.record.error = Some("service closed after confirmed supervisor cleanup".into());
                }
                state.record.updated_at_milliseconds = now_milliseconds();
                let result = self
                    .registry
                    .write_job(&state.record)
                    .and_then(|()| self.registry.lifecycle.finish(&state.record));
                if let Err(error) = result {
                    failures.push(ShutdownFailure {
                        job_id: Some(id.clone()),
                        phase: ShutdownPhase::Persist,
                        message: error.to_string(),
                    });
                } else {
                    active.remove(id);
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ShutdownError { failures })
        }
    }

    pub(crate) fn lock_operation(&self) -> Result<MutexGuard<'_, ()>, JobError> {
        self.operation
            .lock()
            .map_err(|_| JobError::Conflict("service operation lock is poisoned"))
    }

    pub(crate) fn ensure_idle(&self, app_id: &str, bottle_id: &str) -> Result<(), JobError> {
        if self
            .active_debug
            .lock()
            .map_err(|_| JobError::Conflict("debug lease lock is poisoned"))?
            .values()
            .any(|lease| lease.application_id == app_id || lease.bottle_id == bottle_id)
        {
            return Err(JobError::Conflict("application or bottle has an active debug session"));
        }
        for active in self.lock_active()?.values() {
            if active.record.application_id == app_id {
                return Err(JobError::Conflict("application has a live or uncleared cleanup handle"));
            }
            if self
                .registry
                .get_application(&active.record.application_id)
                .is_ok_and(|record| record.application.bottle_id == bottle_id)
            {
                return Err(JobError::Conflict("bottle has a live or uncleared cleanup handle"));
            }
        }
        for state in self.registry.lifecycle.all_states().map_err(JobError::Registry)? {
            if let Some(operation) = &state.operation {
                if state.application_id == app_id
                    || state.generations.iter().any(|generation| {
                        generation.id == operation.generation_id && generation.definition.bottle_id == bottle_id
                    })
                {
                    return Err(JobError::Conflict("application or bottle has an active or quarantined operation; inspect applications.generations"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn rollback(&self, request: &RollbackRequest) -> Result<ApplicationGenerations, JobError> {
        let _operation = self.lock_operation()?;
        let application = self
            .registry
            .get_application(&request.application_id)
            .map_err(JobError::Registry)?
            .application;
        self.ensure_idle(&application.id, &application.bottle_id)?;
        let state = self
            .registry
            .lifecycle
            .state(&application.id)
            .map_err(JobError::Registry)?;
        let generation = state
            .generations
            .iter()
            .find(|generation| generation.id == request.generation_id)
            .ok_or(JobError::NotFound("generation"))?;
        self.ensure_idle(&application.id, &generation.definition.bottle_id)?;
        generation
            .runtime
            .as_ref()
            .ok_or(JobError::Conflict("generation has no completed runtime binding"))?
            .check_config(&self.config)
            .map_err(JobError::Registry)?;
        self.registry.lifecycle.rollback(request).map_err(JobError::Registry)
    }

    pub(crate) fn uninstall(&self, app_id: &str) -> Result<ApplicationGenerations, JobError> {
        let _operation = self.lock_operation()?;
        let application = self
            .registry
            .get_application(app_id)
            .map_err(JobError::Registry)?
            .application;
        self.ensure_idle(app_id, &application.bottle_id)?;
        self.registry.lifecycle.uninstall(app_id).map_err(JobError::Registry)
    }

    pub(crate) fn recover(&self, app_id: &str) -> Result<ApplicationGenerations, JobError> {
        let _operation = self.lock_operation()?;
        if self
            .lock_active()?
            .values()
            .any(|active| active.record.application_id == app_id)
        {
            return Err(JobError::Conflict(
                "supervisor is still owned by this service; cleanup must complete before recovery",
            ));
        }
        self.registry.lifecycle.recover(app_id).map_err(JobError::Registry)
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
        generation: &crate::lifecycle::ApplicationGeneration,
        request: &JobRequest,
    ) -> Result<ResolvedLaunch, JobError> {
        let application = &generation.definition;
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
                if installer.sha256.is_none() {
                    return Err(JobError::Invalid("managed installation requires a reviewed SHA-256"));
                }
                let arguments = installer.arguments.clone();
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
                let source = self.registry.lifecycle.launcher_path(generation, &launcher.executable);
                // Carry the installed digest through prepare/authorize/start.
                // A prior filesystem check alone must not authorize a replacement
                // read by PreparedLaunch after that check.
                let digest = generation
                    .launcher_digests
                    .get(&launcher.id)
                    .and_then(|digest| digest.strip_prefix("sha256:"))
                    .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .ok_or(JobError::Conflict("selected launcher has no verified digest"))?;
                let mut arguments = launcher.arguments.clone();
                arguments.extend(request.argument_overrides.clone());
                let mut environment = launcher.environment.clone();
                environment.extend(request.environment_overrides.clone());
                Ok(ResolvedLaunch {
                    source,
                    executable: ResolvedExecutable {
                        mode: ExecutableMode::BottleInPlace,
                        sha256: Some(digest.to_owned()),
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
        RuntimeEventKind::TimedOut | RuntimeEventKind::GracePeriodExpired => {
            if !state.cancel_requested && state.record.error.is_none() {
                state.record.error = Some("runtime exceeded its completion deadline".into());
            }
        }
        RuntimeEventKind::Started
        | RuntimeEventKind::Output
        | RuntimeEventKind::TerminateRequested
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
            generation_id: None,
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
                polling: Arc::new(Mutex::new(())),
            },
        );
        (manager, handle, root)
    }

    fn managed_fixture(
        cleanup_failed: bool,
    ) -> (JobManager, Arc<CompletedProcess>, PathBuf, crate::ApplicationDefinition) {
        let (manager, handle, root) = terminal_poll_fixture(cleanup_failed);
        manager.registry.seed_defaults().unwrap();
        let app = manager.registry.get_application("7zip").unwrap().application;
        let mut active = manager.active.lock().unwrap().remove("cleanup-job").unwrap();
        active.record.id = "job-managed".into();
        active.record.application_id = app.id.clone();
        active.record.kind = JobKind::Install;
        let generation = manager.registry.lifecycle.stage(&app, &active.record.id).unwrap();
        active.record.generation_id = Some(generation.id);
        let binding = &manager.config.runtime_bindings[0];
        let runtime = InstalledRuntime::from_config(
            &manager.config,
            &compatforge_domain::RuntimeSelection {
                provider: compatforge_domain::RuntimeKind::Wine,
                pack_id: binding.pack_id.clone(),
                pack_digest: binding.pack_digest.clone(),
            },
        )
        .unwrap();
        manager
            .registry
            .lifecycle
            .bind_runtime(&app.id, &active.record.id, runtime)
            .unwrap();
        manager.registry.write_job(&active.record).unwrap();
        manager.active.lock().unwrap().insert(active.record.id.clone(), active);
        (manager, handle, root, app)
    }

    fn write_managed_launcher(manager: &JobManager, app: &crate::ApplicationDefinition) -> PathBuf {
        let state = manager.registry.lifecycle.state(&app.id).unwrap();
        let generation = &state.generations[0];
        let path = manager
            .registry
            .lifecycle
            .launcher_path(generation, &app.launchers[0].executable);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, include_bytes!("../../../tests/fixtures/hello-x86_64.exe")).unwrap();
        path
    }

    #[test]
    fn daemon_tick_activates_install_without_client_poll_and_does_not_rewrite_idle_jobs() {
        let (manager, handle, root, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        let events = std::mem::take(&mut *handle.events.lock().unwrap());
        let before = std::fs::read(root.join("service/jobs/job-managed.json")).unwrap();
        manager.poll_active_jobs().unwrap();
        assert_eq!(
            std::fs::read(root.join("service/jobs/job-managed.json")).unwrap(),
            before,
            "idle daemon polling must not rewrite persistent job metadata"
        );
        *handle.events.lock().unwrap() = events;
        manager.poll_active_jobs().unwrap();
        assert_eq!(manager.registry.lifecycle.selected(&app.id).unwrap().definition, app);
        assert_eq!(handle.joins.load(Ordering::SeqCst), 1);
        assert!(manager.active.lock().unwrap().is_empty());
    }

    struct PausedFirstEvent {
        events: Mutex<std::collections::VecDeque<RuntimeEvent>>,
        dequeued: std::sync::mpsc::SyncSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        stop_requested: std::sync::mpsc::SyncSender<()>,
    }

    impl ShutdownTarget for PausedFirstEvent {
        fn request_stop(&self) -> Result<(), String> {
            let _ = self.stop_requested.try_send(());
            Ok(())
        }
        fn wait_for_stop(&self, _: Duration) -> Result<(), String> {
            Ok(())
        }
    }

    impl JobProcess for PausedFirstEvent {
        fn next_event(&self, _: Duration) -> EventPoll {
            let Some(event) = self.events.lock().unwrap().pop_front() else {
                return EventPoll::Closed;
            };
            if event.sequence == 1 {
                self.dequeued.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
            EventPoll::Event(event)
        }
    }

    type PausedFixture = (
        Arc<JobManager>,
        crate::ApplicationDefinition,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    );

    fn paused_managed_fixture(kind: &str) -> PausedFixture {
        let (manager, _, _, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        let (dequeued, observed) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let (stop_requested, stopped) = std::sync::mpsc::sync_channel(1);
        let first = serde_json::from_value(serde_json::json!({"schemaVersion":"1","sequence":1,"kind":kind,"requestId":"job-managed","elapsedMilliseconds":1,"message":"first event held before state update"})).unwrap();
        let exited = serde_json::from_value(serde_json::json!({"schemaVersion":"1","sequence":2,"kind":"exited","requestId":"job-managed","elapsedMilliseconds":2,"exit":{"code":0,"success":true}})).unwrap();
        manager.active.lock().unwrap().get_mut("job-managed").unwrap().handle = Arc::new(PausedFirstEvent {
            events: Mutex::new([first, exited].into()),
            dequeued,
            release: Mutex::new(resume),
            stop_requested,
        });
        (Arc::new(manager), app, observed, release, stopped)
    }

    #[test]
    fn concurrent_poll_cannot_commit_exit_before_an_already_dequeued_adverse_event() {
        for kind in ["timed-out", "failed"] {
            let (manager, app, observed, release, _) = paused_managed_fixture(kind);
            let polling = manager.clone();
            let first = std::thread::spawn(move || polling.poll("job-managed", 0));
            observed.recv_timeout(Duration::from_secs(5)).unwrap();
            // The first reader has consumed the adverse event but cannot apply
            // it until we resume it. The competing call must reject promptly
            // without consuming the successful exit behind that event.
            let second = manager.poll("job-managed", 0);
            let selected_before_resume = manager.registry.lifecycle.selected(&app.id).is_ok();
            release.send(()).unwrap();
            let first = first.join().unwrap();
            assert!(
                matches!(second, Err(JobError::Conflict("job is already being polled"))),
                "competing result for {kind}: {second:?}"
            );
            assert!(!selected_before_resume, "exit bypassed the held {kind} event");
            assert_eq!(first.unwrap().job.status, JobStatus::Failed);
            assert!(manager.registry.lifecycle.selected(&app.id).is_err());
        }
    }

    #[test]
    fn cancel_can_stop_a_job_while_its_poll_reader_is_paused() {
        let (manager, app, observed, release, stopped) = paused_managed_fixture("started");
        let polling = manager.clone();
        let first = std::thread::spawn(move || polling.poll("job-managed", 0));
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(manager.cancel("job-managed").unwrap().status, JobStatus::Cancelling);
        stopped.recv_timeout(Duration::from_secs(5)).unwrap();
        release.send(()).unwrap();
        assert_eq!(first.join().unwrap().unwrap().job.status, JobStatus::Cancelled);
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
    }

    #[test]
    fn shutdown_and_a_paused_poll_do_not_deadlock_or_activate_the_installer() {
        let (manager, app, observed, release, stopped) = paused_managed_fixture("started");
        let polling = manager.clone();
        let first = std::thread::spawn(move || polling.poll("job-managed", 0));
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        let closing = manager.clone();
        let (done, completed) = std::sync::mpsc::sync_channel(1);
        let shutdown = std::thread::spawn(move || done.send(closing.shutdown_and_wait()).unwrap());
        stopped.recv_timeout(Duration::from_secs(5)).unwrap();
        release.send(()).unwrap();
        completed
            .recv_timeout(Duration::from_secs(5))
            .expect("shutdown lock ordering deadlocked")
            .unwrap();
        shutdown.join().unwrap();
        let polled = first.join().unwrap().unwrap();
        assert_eq!(polled.job.status, JobStatus::Cancelled);
        assert!(manager.registry.lifecycle.state(&app.id).unwrap().operation.is_none());
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
    }

    #[test]
    fn shutdown_during_terminal_poll_join_returns_cancelled_without_activation() {
        struct PausedJoin {
            events: Mutex<std::collections::VecDeque<RuntimeEvent>>,
            joins: AtomicU64,
            joining: std::sync::mpsc::SyncSender<()>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
            stopped: std::sync::mpsc::SyncSender<()>,
        }
        impl ShutdownTarget for PausedJoin {
            fn request_stop(&self) -> Result<(), String> {
                let _ = self.stopped.try_send(());
                Ok(())
            }
            fn wait_for_stop(&self, _: Duration) -> Result<(), String> {
                if self.joins.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.joining.send(()).unwrap();
                    self.release.lock().unwrap().recv().unwrap();
                }
                Ok(())
            }
        }
        impl JobProcess for PausedJoin {
            fn next_event(&self, _: Duration) -> EventPoll {
                self.events
                    .lock()
                    .unwrap()
                    .pop_front()
                    .map_or(EventPoll::Closed, EventPoll::Event)
            }
        }
        let (manager, handle, _, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        let (joining, in_join) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let (stopped, stopping) = std::sync::mpsc::sync_channel(1);
        manager.active.lock().unwrap().get_mut("job-managed").unwrap().handle = Arc::new(PausedJoin {
            events: Mutex::new(handle.events.lock().unwrap().drain(..).collect()),
            joins: AtomicU64::new(0),
            joining,
            release: Mutex::new(resume),
            stopped,
        });
        let manager = Arc::new(manager);
        let polling = manager.clone();
        let poll = std::thread::spawn(move || polling.poll("job-managed", 0));
        in_join.recv_timeout(Duration::from_secs(5)).unwrap();
        let closing = manager.clone();
        let (done, completed) = std::sync::mpsc::sync_channel(1);
        let shutdown = std::thread::spawn(move || done.send(closing.shutdown_and_wait()).unwrap());
        stopping.recv_timeout(Duration::from_secs(5)).unwrap();
        release.send(()).unwrap();
        completed
            .recv_timeout(Duration::from_secs(5))
            .expect("shutdown deadlocked during terminal poll join")
            .unwrap();
        shutdown.join().unwrap();
        assert_eq!(poll.join().unwrap().unwrap().job.status, JobStatus::Cancelled);
        assert_eq!(
            manager.registry.read_job("job-managed").unwrap().status,
            JobStatus::Cancelled
        );
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
    }

    #[test]
    fn launch_preparation_rejects_content_changed_after_generation_verification() {
        let (manager, _, _, app) = managed_fixture(false);
        let launcher_path = write_managed_launcher(&manager, &app);
        manager.poll("job-managed", 0).unwrap();
        let generation = manager
            .registry
            .lifecycle
            .begin_launch(&app.id, "job-mutation-test", JobKind::Launch)
            .unwrap();
        let request: JobRequest =
            serde_json::from_value(serde_json::json!({"schemaVersion":"1","applicationId":app.id,"kind":"launch"}))
                .unwrap();
        let resolved = manager.resolve_launch(&generation, &request).unwrap();
        let mut launch: LaunchRequest =
            serde_json::from_str(include_str!("../../../examples/launch-request.json")).unwrap();
        launch.bottle_id = generation.bottle_id;
        launch.executable.path = resolved.source.to_string_lossy().into_owned();
        launch.executable.mode = resolved.executable.mode;
        launch.executable.sha256 = resolved.executable.sha256;
        let mut bytes = std::fs::read(&launcher_path).unwrap();
        bytes.push(42);
        std::fs::write(&launcher_path, bytes).unwrap();
        let prepared = PreparedLaunch::prepare(&manager.config, &launcher_path, &launch);
        assert!(
            matches!(
                prepared,
                Err(compatforge_orchestrator::PreparationError::DigestMismatch)
            ),
            "changed content was not rejected against the installed digest: {prepared:?}"
        );
    }

    #[test]
    fn job_history_capacity_rejects_new_work_but_allows_terminal_updates_and_restart() {
        let (manager, _, root) = terminal_poll_fixture(false);
        let mut record = manager.active.lock().unwrap().remove("cleanup-job").unwrap().record;
        manager.registry.seed_defaults().unwrap();
        record.status = JobStatus::Succeeded;
        for index in 0..crate::registry::MAX_JOB_RECORDS {
            record.id = format!("job-history-{index}");
            std::fs::write(
                root.join("service/jobs").join(format!("{}.json", record.id)),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        let request: JobRequest = serde_json::from_value(serde_json::json!({"schemaVersion":"1","applicationId":"7zip","kind":"install","executablePath":std::env::current_exe().unwrap()})).unwrap();
        let error = manager.submit(request).unwrap_err();
        assert!(
            matches!(error, JobError::Registry(RegistryError::Conflict(message)) if message.contains("job history capacity")),
            "{error}"
        );
        assert!(manager.registry.lifecycle.state("7zip").unwrap().generations.is_empty());
        assert_eq!(std::fs::read_dir(root.join("storage/bottles")).unwrap().count(), 0);
        assert_eq!(
            manager.registry.list_jobs().unwrap().len(),
            crate::registry::MAX_JOB_RECORDS
        );
        record.status = JobStatus::Failed;
        record.error = Some("existing terminal update remains writable".into());
        manager.registry.write_job(&record).unwrap();
        assert_eq!(manager.registry.read_job(&record.id).unwrap().status, JobStatus::Failed);
        drop(manager);
        let registry = Registry::new(root.join("service"), root.join("storage")).unwrap();
        registry.recover_interrupted_jobs().unwrap();
        assert_eq!(registry.list_jobs().unwrap().len(), crate::registry::MAX_JOB_RECORDS);
        assert_eq!(registry.read_job(&record.id).unwrap().status, JobStatus::Failed);
    }

    #[test]
    fn managed_poll_requires_all_launchers_and_confirmed_cleanup() {
        let (manager, handle, _, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
        let result = manager.poll("job-managed", 0).unwrap();
        assert_eq!(result.job.status, JobStatus::Succeeded);
        assert_eq!(handle.joins.load(Ordering::SeqCst), 1);
        assert_eq!(manager.registry.lifecycle.selected(&app.id).unwrap().definition, app);
        assert!(manager.registry.lifecycle.state(&app.id).unwrap().operation.is_none());
    }

    #[test]
    fn saved_success_event_cannot_bypass_generation_commit_or_failed_activation() {
        let (manager, _, _, app) = managed_fixture(false);
        let mut record = manager.registry.read_job("job-managed").unwrap();
        record.status = JobStatus::Succeeded;
        manager.registry.write_job(&record).unwrap();
        assert_eq!(
            manager.registry.read_job("job-managed").unwrap().status,
            JobStatus::Running
        );
        assert!(manager.registry.lifecycle.finish(&record).is_err()); // missing launcher
                                                                      // The old job file still says success, as after a job-file write error.
        assert_eq!(
            manager.registry.read_job("job-managed").unwrap().status,
            JobStatus::Failed
        );
        assert_eq!(manager.registry.list_jobs().unwrap()[0].status, JobStatus::Failed);
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
        manager.active.lock().unwrap().clear();
    }

    #[test]
    fn timed_out_installer_with_zero_exit_cannot_activate() {
        let (manager, handle, _, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        handle.events.lock().unwrap().push_front(serde_json::from_value(serde_json::json!({
            "schemaVersion":"1", "sequence":1, "kind":"timed-out", "requestId":"job-managed", "elapsedMilliseconds":1,
            "message":"runtime exceeded deadline"
        })).unwrap());
        assert_eq!(manager.poll("job-managed", 0).unwrap().job.status, JobStatus::Failed);
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
    }

    #[test]
    fn managed_cancellation_and_cleanup_failure_cannot_select_partial_files() {
        let (manager, _, _, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        manager.cancel("job-managed").unwrap();
        assert_eq!(manager.poll("job-managed", 0).unwrap().job.status, JobStatus::Cancelled);
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
        let (manager, _, _, app) = managed_fixture(true);
        write_managed_launcher(&manager, &app);
        assert_eq!(manager.poll("job-managed", 0).unwrap().job.status, JobStatus::Failed);
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
        assert!(
            manager
                .registry
                .lifecycle
                .state(&app.id)
                .unwrap()
                .operation
                .unwrap()
                .quarantined
        );
        assert!(manager.uninstall(&app.id).is_err());
        assert!(manager.recover(&app.id).is_err());
    }

    #[test]
    fn managed_shutdown_persists_cancellation_and_reopen_does_not_quarantine() {
        let (manager, handle, root, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        manager.shutdown_and_wait().unwrap();
        assert_eq!(handle.joins.load(Ordering::SeqCst), 1);
        assert_eq!(
            manager.registry.read_job("job-managed").unwrap().status,
            JobStatus::Cancelled
        );
        drop(manager);
        let registry = Registry::new(root.join("service"), root.join("storage")).unwrap();
        registry.recover_interrupted_jobs().unwrap();
        assert!(registry.lifecycle.state(&app.id).unwrap().operation.is_none());
        assert!(!registry.application_installed(&app));
    }

    #[test]
    fn crash_recovery_preserves_unselected_state_and_blocks_install_conflicts() {
        let (manager, _, root, app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        let mut settings = manager.registry.read_settings().unwrap();
        settings.maximum_parallel_jobs = 4;
        manager.registry.write_settings(&settings).unwrap();
        let request: JobRequest = serde_json::from_value(serde_json::json!({"schemaVersion":"1","applicationId":app.id,"kind":"install","executablePath":std::env::current_exe().unwrap()})).unwrap();
        assert!(matches!(manager.submit(request), Err(JobError::Conflict(_))));
        assert!(manager.uninstall(&app.id).is_err());
        drop(manager);
        let registry = Registry::new(root.join("service"), root.join("storage")).unwrap();
        registry.recover_interrupted_jobs().unwrap();
        assert_eq!(registry.read_job("job-managed").unwrap().status, JobStatus::Failed);
        assert!(
            registry
                .lifecycle
                .state(&app.id)
                .unwrap()
                .operation
                .unwrap()
                .quarantined
        );
        assert!(registry.lifecycle.selected(&app.id).is_err());
    }

    #[test]
    fn changed_installer_hash_fails_before_runtime_and_preserves_selected_version() {
        let (manager, _, root, mut app) = managed_fixture(false);
        write_managed_launcher(&manager, &app);
        manager.poll("job-managed", 0).unwrap();
        let old = manager.registry.lifecycle.selected(&app.id).unwrap();
        app.version = "updated".into();
        app.launchers[0].executable = "different/new.exe".into();
        manager.registry.upsert_application(app.clone()).unwrap();
        let installer = root.join(&app.installer.as_ref().unwrap().file_name);
        std::fs::write(&installer, include_bytes!("../../../tests/fixtures/hello-x86_64.exe")).unwrap();
        let request: JobRequest = serde_json::from_value(
            serde_json::json!({"schemaVersion":"1","applicationId":app.id,"kind":"install","executablePath":installer}),
        )
        .unwrap();
        let error = manager.submit(request).unwrap_err();
        assert!(matches!(error, JobError::Preparation(_)), "{error}");
        assert!(manager.active.lock().unwrap().is_empty());
        assert_eq!(manager.registry.lifecycle.selected(&app.id).unwrap(), old);
        assert_eq!(
            manager.registry.lifecycle.state(&app.id).unwrap().generations[1].status,
            crate::GenerationStatus::Failed
        );
    }

    #[test]
    fn successful_cleanup_retry_releases_owned_quarantine() {
        let (manager, _, _, app) = managed_fixture(true);
        write_managed_launcher(&manager, &app);
        manager.poll("job-managed", 0).unwrap();
        manager.active.lock().unwrap().get_mut("job-managed").unwrap().handle = Arc::new(CompletedProcess {
            events: Mutex::new(std::collections::VecDeque::new()),
            cleanup_failed: false,
            joins: AtomicU64::new(0),
        });
        manager.shutdown_and_wait().unwrap();
        assert!(manager.registry.lifecycle.state(&app.id).unwrap().operation.is_none());
        assert!(manager.registry.lifecycle.selected(&app.id).is_err());
    }

    #[test]
    fn shared_logical_bottle_and_uncleared_terminal_handles_conflict() {
        let (manager, _, _, app) = managed_fixture(true);
        write_managed_launcher(&manager, &app);
        manager.poll("job-managed", 0).unwrap();
        let mut other = app.clone();
        other.id = "other-app".into();
        manager.registry.upsert_application(other.clone()).unwrap();
        assert!(manager.ensure_idle(&other.id, &other.bottle_id).is_err());
        assert!(manager
            .rollback(&RollbackRequest {
                application_id: app.id,
                generation_id: "gen-job-managed".into()
            })
            .is_err());
    }

    #[test]
    fn successful_installer_exit_without_verified_generation_is_not_installed() {
        let (manager, _, _) = terminal_poll_fixture(false);
        manager
            .active
            .lock()
            .unwrap()
            .get_mut("cleanup-job")
            .unwrap()
            .record
            .kind = JobKind::Install;
        assert_eq!(manager.poll("cleanup-job", 0).unwrap().job.status, JobStatus::Failed);
    }

    #[test]
    fn installer_accepts_local_display_session_but_rejects_runtime_environment_override() {
        let mut request: JobRequest = serde_json::from_value(serde_json::json!({
            "schemaVersion":"1", "applicationId":"7zip", "kind":"install", "executablePath": std::env::current_exe().unwrap(),
            "environmentOverrides":{"DISPLAY":":98"}
        })).unwrap();
        assert!(request.validate().is_ok());
        request
            .environment_overrides
            .insert("WINEPREFIX".into(), "/tmp/unreviewed".into());
        assert!(request.validate().is_err());
        request.environment_overrides.clear();
        request
            .environment_overrides
            .insert("DISPLAY".into(), "remote:0".into());
        assert!(request.validate().is_err());
    }

    #[test]
    fn install_cannot_override_reviewed_arguments_or_environment() {
        let request: JobRequest = serde_json::from_value(serde_json::json!({
            "schemaVersion":"1", "applicationId":"7zip", "kind":"install",
            "executablePath": std::env::current_exe().unwrap(), "argumentOverrides":["/unreviewed"]
        }))
        .unwrap();
        assert!(request.validate().is_err());
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
        let error = manager.shutdown_and_wait().unwrap_err();
        assert_eq!(error.failures[0].phase, ShutdownPhase::Persist);
        // Process cleanup succeeds even though persisting that fact failed.
        std::fs::remove_dir(&job_path).unwrap();
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
            generation_id: None,
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
                polling: Arc::new(Mutex::new(())),
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
