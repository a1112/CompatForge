//! A dormant startup owner registered by the service before activation.
use super::*;
use std::sync::Condvar;

struct State {
    ready: (Mutex<bool>, Condvar),
    cancelled: AtomicBool,
    spawn_gate: Mutex<()>,
    result: Mutex<Option<Result<Arc<LaunchHandle>, ProcessError>>>,
}

pub struct PreparingLaunch {
    state: Arc<State>,
    receiver: Mutex<Receiver<RuntimeEvent>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl PreparingLaunch {
    pub(super) fn new_with_validation(
        plan: LaunchPlan,
        validation: impl FnOnce(&AtomicBool) -> Result<(), ProcessError> + Send + 'static,
    ) -> Result<Self, ProcessError> {
        Self::new_with_start(plan, move |plan, operations| {
            operations.check_cancelled()?;
            validation(&operations.0.cancelled)?;
            operations.check_cancelled()?;
            ProcessSupervisor::start_with_operations(plan, operations)
        })
    }
    pub(super) fn new(plan: LaunchPlan) -> Result<Self, ProcessError> {
        Self::new_with_start(plan, |plan, operations| {
            ProcessSupervisor::start_with_operations(plan, operations)
        })
    }

    fn new_with_start(
        plan: LaunchPlan,
        start: impl FnOnce(&LaunchPlan, &CancellableOperations) -> Result<LaunchHandle, ProcessError> + Send + 'static,
    ) -> Result<Self, ProcessError> {
        plan.validate().map_err(ProcessError::InvalidPlan)?;
        let state = Arc::new(State {
            ready: (Mutex::new(false), Condvar::new()),
            cancelled: AtomicBool::new(false),
            spawn_gate: Mutex::new(()),
            result: Mutex::new(None),
        });
        let worker_state = Arc::clone(&state);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("compatforge-preparing".into())
            .spawn(move || {
                let mut ready = lock_recover(&worker_state.ready.0);
                while !*ready && !worker_state.cancelled.load(Ordering::Acquire) {
                    ready = worker_state
                        .ready
                        .1
                        .wait(ready)
                        .unwrap_or_else(|error| error.into_inner());
                }
                drop(ready);
                let operations = CancellableOperations(Arc::clone(&worker_state));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| start(&plan, &operations)))
                    .unwrap_or(Err(ProcessError::StartupCleanup {
                        startup: StartupStage::AppearancePreparation,
                        cleanup: CleanupStage::ClientCleanup,
                    }));
                let result = operations.map_cancel(result).map(Arc::new);
                // Cancellation and guest spawn use the same gate. If spawn won the
                // race, the newly owned handle must immediately receive the stop.
                let _gate = lock_recover(&worker_state.spawn_gate);
                if let Ok(handle) = &result {
                    if worker_state.cancelled.load(Ordering::Acquire) {
                        let _ = handle.terminate();
                    }
                }
                let emitter = EventEmitter::new(plan.request_id, sender);
                if let Err(error) = &result {
                    if !matches!(error, ProcessError::Cancelled) {
                        emitter.emit(RuntimeEventKind::Failed, None, None, None, Some(error.to_string()));
                    }
                    emitter.emit(
                        RuntimeEventKind::Exited,
                        None,
                        None,
                        Some(ProcessExit {
                            code: None,
                            success: false,
                        }),
                        None,
                    );
                }
                *lock_recover(&worker_state.result) = Some(result);
            })
            .map_err(ProcessError::Spawn)?;
        Ok(Self {
            state,
            receiver: Mutex::new(receiver),
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Call only after persistent job registration and cleanup ownership.
    pub fn activate(&self) {
        *lock_recover(&self.state.ready.0) = true;
        self.state.ready.1.notify_all();
    }

    pub fn next_event(&self, timeout: Duration) -> EventPoll {
        let handle = lock_recover(&self.state.result)
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .cloned();
        if let Some(handle) = handle {
            return handle.next_event(timeout);
        }
        let started = Instant::now();
        let poll = match lock_recover(&self.receiver).recv_timeout(timeout) {
            Ok(event) => EventPoll::Event(event),
            Err(RecvTimeoutError::Timeout) => EventPoll::Timeout,
            Err(RecvTimeoutError::Disconnected) => EventPoll::Closed,
        };
        // Publishing the running handle closes the preparation channel and
        // wakes a reader already waiting for configuration to finish.
        if matches!(poll, EventPoll::Closed) {
            let handle = lock_recover(&self.state.result)
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .cloned();
            if let Some(handle) = handle {
                return handle.next_event(timeout.saturating_sub(started.elapsed()));
            }
        }
        poll
    }

    pub fn terminate(&self) -> Result<(), ProcessError> {
        {
            let _ready = lock_recover(&self.state.ready.0);
            let _gate = lock_recover(&self.state.spawn_gate);
            self.state.cancelled.store(true, Ordering::Release);
        }
        self.state.ready.1.notify_all();
        let handle = lock_recover(&self.state.result)
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .cloned();
        match handle {
            Some(handle) => handle.terminate(),
            None => Ok(()),
        }
    }

    pub fn terminate_and_wait(&self, grace: Duration) -> Result<(), ProcessError> {
        self.terminate()?;
        let deadline = Instant::now()
            .checked_add(grace)
            .and_then(|value| value.checked_add(SUPERVISOR_FORCE_COMPLETION_TIMEOUT))
            .ok_or_else(|| ProcessError::Terminate(io::Error::other("invalid preparation completion deadline")))?;
        let mut worker = lock_recover(&self.worker);
        while worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            if Instant::now() >= deadline {
                return Err(ProcessError::Terminate(io::Error::other(
                    "preparation cleanup remains owned and incomplete",
                )));
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        if let Some(worker) = worker.take() {
            worker
                .join()
                .map_err(|_| ProcessError::Terminate(io::Error::other("preparation worker panicked")))?;
        }
        drop(worker);
        let result = lock_recover(&self.state.result);
        match result.as_ref() {
            Some(Ok(handle)) => {
                let handle = Arc::clone(handle);
                drop(result);
                handle.terminate_and_wait_until(Duration::ZERO, deadline)
            }
            Some(Err(ProcessError::StartupCleanup { startup, cleanup })) => Err(ProcessError::StartupCleanup {
                startup: *startup,
                cleanup: *cleanup,
            }),
            Some(Err(_)) => Ok(()),
            None => Err(ProcessError::Terminate(io::Error::other(
                "preparation result unavailable",
            ))),
        }
    }
}

impl Drop for PreparingLaunch {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

struct CancellableOperations(Arc<State>);
impl CancellableOperations {
    fn map_cancel<T>(&self, result: Result<T, ProcessError>) -> Result<T, ProcessError> {
        match result {
            Err(ProcessError::Startup(_) | ProcessError::Spawn(_)) if self.0.cancelled.load(Ordering::Acquire) => {
                Err(ProcessError::Cancelled)
            }
            other => other,
        }
    }
}
impl StartupOperations for CancellableOperations {
    fn cancellation(&self) -> Option<&AtomicBool> {
        Some(&self.0.cancelled)
    }
    fn check_cancelled(&self) -> Result<(), ProcessError> {
        if self.0.cancelled.load(Ordering::Acquire) {
            Err(ProcessError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn wineboot(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
        self.check_cancelled()?;
        self.map_cancel(initialize_wine_prefix_with_cancel(
            plan,
            WINE_PREFIX_BOOTSTRAP_TIMEOUT,
            Command::spawn,
            Some(&self.0.cancelled),
        ))
    }
    fn appearance(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
        self.check_cancelled()?;
        self.map_cancel(prepare_wine_appearance_with_cancel(plan, Some(&self.0.cancelled)))
    }
    fn fonts(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
        self.check_cancelled()?;
        prepare_pinned_bottle_font(plan)
    }
    fn guest_alias(&self, plan: &LaunchPlan) -> Result<Option<PathBuf>, ProcessError> {
        self.check_cancelled()?;
        prepare_guest_execution_alias(plan)
    }
    fn spawn(&self, command: &mut Command) -> io::Result<Child> {
        let _gate = lock_recover(&self.0.spawn_gate);
        self.check_cancelled()
            .map_err(|_| io::Error::other("guest spawn cancelled"))?;
        command.spawn()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation_is_dormant_and_cancelled_before_activation_without_side_effects() {
        let plan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let handle = PreparingLaunch::new_with_validation(plan, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(ProcessError::Cancelled)
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        handle.terminate_and_wait(Duration::ZERO).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn cancellation_interrupts_owned_validation_before_guest_spawn() {
        let plan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
        let (started, observed) = mpsc::channel();
        let handle = PreparingLaunch::new_with_validation(plan, move |cancelled| {
            started.send(()).unwrap();
            while !cancelled.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(10));
            }
            Err(ProcessError::Cancelled)
        })
        .unwrap();
        handle.activate();
        observed.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.terminate_and_wait(Duration::ZERO).unwrap();
        assert!(
            matches!(handle.next_event(Duration::from_secs(1)), EventPoll::Event(event) if event.kind==RuntimeEventKind::Exited && event.exit.as_ref().is_some_and(|exit| !exit.success))
        );
    }
    #[test]
    fn preparing_worker_panic_emits_failure_and_never_confirms_cleanup() {
        let plan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
        let handle = PreparingLaunch::new_with_start(plan, |_, _| panic!("injected preparation panic")).unwrap();
        handle.activate();
        assert!(
            matches!(handle.next_event(Duration::from_secs(3)), EventPoll::Event(event) if event.kind == RuntimeEventKind::Failed)
        );
        assert!(handle.terminate_and_wait(Duration::ZERO).is_err());
        assert!(handle.terminate_and_wait(Duration::ZERO).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn preparing_cancel_after_spawn_before_publication_stops_the_new_handle() {
        let mut plan: LaunchPlan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
        plan.process = compatforge_domain::NativeCommand {
            executable: "/bin/sleep".into(),
            arguments: vec!["30".into()],
            environment: Default::default(),
            working_directory: std::env::temp_dir().to_str().unwrap().into(),
        };
        plan.guest_artifact = None;
        plan.bottle_executable = None;
        plan.wine_appearance = None;
        plan.lifecycle = compatforge_domain::ProcessLifecycle::default();
        plan.graphics.backend = GraphicsBackendKind::WineD3d;
        plan.graphics.version = None;
        plan.translator.provider = compatforge_domain::TranslatorKind::Native;
        plan.translator.version = None;
        plan.mounts.clear();
        let (spawned, observed) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let handle = PreparingLaunch::new_with_start(plan, move |plan, ops| {
            let inner = ProcessSupervisor::start_with_operations(plan, ops)?;
            spawned.send(()).unwrap();
            proceed.recv().unwrap();
            Ok(inner)
        })
        .unwrap();
        handle.activate();
        observed.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.terminate().unwrap();
        release.send(()).unwrap();
        handle.terminate_and_wait(Duration::ZERO).unwrap();
        assert!(lock_recover(&handle.state.result)
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .is_finished());
    }
}
