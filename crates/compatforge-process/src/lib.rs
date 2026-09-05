//! Cross-platform process-tree supervision for authorized CompatForge launch plans.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, target_os = "macos"))]
use compatforge_domain::BottleExecutableBinding;
use compatforge_domain::{
    ContractError, LaunchPlan, OutputStream, ProcessExit, ProcessOutput, RuntimeEvent, RuntimeEventKind, RuntimeKind,
    WineServerLifecycle, SCHEMA_VERSION_V1,
};
use compatforge_guest_artifact::{
    verify_binding_contents, verify_in_place_binding_contents, GuestArtifactError, PinnedBottleExecutable,
};
use sha2::{Digest, Sha256};
#[cfg(any(test, target_os = "macos"))]
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read};
#[cfg(target_os = "macos")]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(20);
#[cfg(not(test))]
const WINE_SERVER_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
// Exercise the same scheduling budget as production on loaded macOS hosts.
#[cfg(test)]
const WINE_SERVER_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const SUPERVISOR_FORCE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(16);
const WINE_PREFIX_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(90);
const EXECUTABLE_BUSY_RETRY_LIMIT: usize = 20;
const EXECUTABLE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);
const RUNTIME_EXECUTABLE_DIGEST_ENV: &str = "COMPATFORGE_RUNTIME_EXECUTABLE_SHA256";
const WINESERVER_EXECUTABLE_DIGEST_ENV: &str = "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256";
const FONT_CONFIG_FILE_ENV: &str = "FONTCONFIG_FILE";
const FONT_CONFIG_DIGEST_ENV: &str = "COMPATFORGE_FONT_CONFIG_SHA256";
const BOTTLE_FONT_FILE_ENV: &str = "COMPATFORGE_BOTTLE_FONT_FILE";
const BOTTLE_FONT_DIGEST_ENV: &str = "COMPATFORGE_BOTTLE_FONT_SHA256";
const BOTTLE_FONT_FILE_NAME: &str = "compatforge-cjk.ttc";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupStage {
    Wineboot,
    FontPreparation,
    GuestAlias,
    GuestVerification,
    RuntimeVerification,
    PinnedExecution,
    ProcessTreePreparation,
    GuestSpawn,
    ProcessTreeAttachment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupStage {
    RuntimeVerification,
    ServerSpawn,
    ServerWait,
    ServerExit,
    ClientCleanup,
    TreeTermination,
    RootReap,
}

#[derive(Debug)]
pub enum ProcessError {
    InvalidPlan(ContractError),
    InvalidGuestArtifact(GuestArtifactError),
    InvalidRuntimeEvidence(&'static str),
    UnsafeDirectory(&'static str),
    Isolation(io::Error),
    Spawn(io::Error),
    Terminate(io::Error),
    WinePrefixBusy(String),
    Startup(StartupStage),
    StartupCleanup {
        startup: StartupStage,
        cleanup: CleanupStage,
    },
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(error) => write!(formatter, "invalid launch plan: {error}"),
            Self::InvalidGuestArtifact(error) => write!(formatter, "invalid guest artifact: {error}"),
            Self::InvalidRuntimeEvidence(field) => write!(formatter, "invalid pinned Runtime evidence: {field}"),
            Self::UnsafeDirectory(field) => write!(formatter, "unsafe launch directory: {field}"),
            Self::Isolation(error) => write!(formatter, "process-tree isolation failed: {error}"),
            Self::Spawn(error) => write!(formatter, "process spawn failed: {error}"),
            Self::Terminate(error) => write!(formatter, "process termination failed: {error}"),
            Self::WinePrefixBusy(prefix) => write!(formatter, "Wine prefix already has an active launch: {prefix}"),
            Self::Startup(startup) => write!(formatter, "Wine startup failed: {startup:?}"),
            Self::StartupCleanup { startup, cleanup } => {
                write!(formatter, "Wine startup cleanup failed: {startup:?}; {cleanup:?}")
            }
        }
    }
}

impl std::error::Error for ProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPlan(error) => Some(error),
            Self::InvalidGuestArtifact(error) => Some(error),
            Self::Isolation(error) | Self::Spawn(error) | Self::Terminate(error) => Some(error),
            Self::InvalidRuntimeEvidence(_)
            | Self::UnsafeDirectory(_)
            | Self::WinePrefixBusy(_)
            | Self::Startup(_)
            | Self::StartupCleanup { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventPoll {
    Event(RuntimeEvent),
    Timeout,
    Closed,
}

pub struct ProcessSupervisor;

impl ProcessSupervisor {
    /// Start a plan that has already been authorized against a trusted context.
    pub fn start(plan: &LaunchPlan) -> Result<LaunchHandle, ProcessError> {
        Self::start_with_operations(plan, &SystemStartupOperations)
    }

    fn start_with_operations(
        plan: &LaunchPlan,
        operations: &impl StartupOperations,
    ) -> Result<LaunchHandle, ProcessError> {
        plan.validate().map_err(ProcessError::InvalidPlan)?;
        verify_guest_inputs(plan)?;
        verify_pinned_runtime(plan)?;
        verify_pinned_font_config(plan)?;
        verify_pinned_bottle_font(plan)?;
        materialize_launch_directories(plan)?;
        let wine_session = WineSession::acquire(plan)?;
        let mut startup_guard = wine_session.map(StartupWineSessionGuard::new);
        startup_step(&mut startup_guard, StartupStage::Wineboot, operations.wineboot(plan))?;
        startup_step(
            &mut startup_guard,
            StartupStage::GuestVerification,
            verify_guest_inputs(plan),
        )?;
        startup_step(
            &mut startup_guard,
            StartupStage::RuntimeVerification,
            verify_pinned_runtime(plan),
        )?;
        startup_step(
            &mut startup_guard,
            StartupStage::FontPreparation,
            operations.fonts(plan),
        )?;
        let guest_execution_alias = startup_step(
            &mut startup_guard,
            StartupStage::GuestAlias,
            operations.guest_alias(plan),
        )?;
        let keep_alive_after_root_exit = managed_wine_gui_requires_idle_wait(plan);

        let mut command = Command::new(&plan.process.executable);
        command
            .args(execution_arguments(plan, guest_execution_alias.as_deref()))
            .current_dir(&plan.process.working_directory)
            .env_clear()
            .envs(&plan.process.environment)
            .stdin(Stdio::null())
            .stdout(if keep_alive_after_root_exit {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stderr(if keep_alive_after_root_exit {
                Stdio::null()
            } else {
                Stdio::piped()
            });

        supervise_command_with_operations(plan, command, startup_guard, (), operations, || {
            verify_guest_inputs(plan)?;
            // Recheck the actual alias too; the binding source alone cannot
            // prove that a replaced alias still names the approved bytes.
            prepare_guest_execution_alias(plan)?;
            verify_pinned_runtime(plan)
        })
    }

    /// Start the fixed, captured SumatraPDF Bottle executable without reopening
    /// its logical pathname. The caller retains ownership of `pinned`.
    pub fn start_pinned_bottle(
        plan: &LaunchPlan,
        pinned: &PinnedBottleExecutable,
    ) -> Result<LaunchHandle, ProcessError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (plan, pinned);
            Err(ProcessError::InvalidGuestArtifact(
                GuestArtifactError::PinnedUnsupportedPlatform,
            ))
        }

        #[cfg(target_os = "macos")]
        start_pinned_bottle_macos(plan, pinned)
    }
}

trait StartupOperations {
    fn wineboot(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
        initialize_wine_prefix(plan)
    }

    fn fonts(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
        prepare_pinned_bottle_font(plan)
    }

    fn guest_alias(&self, plan: &LaunchPlan) -> Result<Option<PathBuf>, ProcessError> {
        prepare_guest_execution_alias(plan)
    }

    fn spawn(&self, command: &mut Command) -> io::Result<Child> {
        command.spawn()
    }

    fn attach(&self, prepared: platform::PreparedProcessTree, child: &Child) -> io::Result<platform::ProcessTree> {
        prepared.attach(child)
    }
}

trait PollClock {
    fn now(&self) -> Instant;
    fn wait(&self);
}

struct SystemPollClock;

impl PollClock for SystemPollClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn wait(&self) {
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

trait BoundedChild {
    fn poll(&mut self) -> io::Result<Option<bool>>;
    fn force_kill_tree(&mut self) -> io::Result<()>;
}

#[derive(Debug)]
struct AuxiliaryFailure {
    cleanup: Option<CleanupStage>,
}

impl AuxiliaryFailure {
    fn into_process_error(self, startup: StartupStage) -> ProcessError {
        match self.cleanup {
            Some(cleanup) => ProcessError::StartupCleanup { startup, cleanup },
            None => ProcessError::Startup(startup),
        }
    }
}

fn reap_bounded<C: BoundedChild>(child: &mut C, clock: &impl PollClock, timeout: Duration) -> Result<(), CleanupStage> {
    let signal_error = child.force_kill_tree().err();
    let deadline = clock.now() + timeout;
    loop {
        match child.poll() {
            Ok(Some(_)) => {
                return if signal_error.is_some() {
                    Err(CleanupStage::TreeTermination)
                } else {
                    Ok(())
                }
            }
            _ if clock.now() >= deadline => return Err(CleanupStage::RootReap),
            _ => clock.wait(),
        }
    }
}

fn wait_bounded<C: BoundedChild>(
    child: &mut C,
    clock: &impl PollClock,
    timeout: Duration,
) -> Result<bool, AuxiliaryFailure> {
    let deadline = clock.now() + timeout;
    loop {
        match child.poll() {
            Ok(Some(success)) => return Ok(success),
            Ok(None) if clock.now() < deadline => clock.wait(),
            _ => {
                return Err(AuxiliaryFailure {
                    cleanup: reap_bounded(child, clock, WINE_SERVER_COMMAND_TIMEOUT).err(),
                })
            }
        }
    }
}

impl BoundedChild for Child {
    fn poll(&mut self) -> io::Result<Option<bool>> {
        self.try_wait().map(|status| status.map(|status| status.success()))
    }
    fn force_kill_tree(&mut self) -> io::Result<()> {
        platform::force_kill_unattached(self)
    }
}

struct AuxiliaryProcess {
    child: Child,
    tree: platform::ProcessTree,
    cleanup_failure: Option<CleanupStage>,
}

impl BoundedChild for AuxiliaryProcess {
    fn poll(&mut self) -> io::Result<Option<bool>> {
        self.child.poll()
    }
    fn force_kill_tree(&mut self) -> io::Result<()> {
        self.tree.force_kill()
    }
}

fn spawn_auxiliary(command: &mut Command) -> Result<AuxiliaryProcess, AuxiliaryFailure> {
    spawn_auxiliary_with(command, Command::spawn)
}

fn spawn_auxiliary_with(
    command: &mut Command,
    spawn: impl FnOnce(&mut Command) -> io::Result<Child>,
) -> Result<AuxiliaryProcess, AuxiliaryFailure> {
    let prepared = platform::PreparedProcessTree::prepare(command).map_err(|_| AuxiliaryFailure { cleanup: None })?;
    let child = spawn(command).map_err(|_| AuxiliaryFailure { cleanup: None })?;
    attach_auxiliary(child, prepared)
}

fn attach_auxiliary(
    mut child: Child,
    prepared: platform::PreparedProcessTree,
) -> Result<AuxiliaryProcess, AuxiliaryFailure> {
    match prepared.attach(&child) {
        Ok(tree) => Ok(AuxiliaryProcess {
            child,
            tree,
            cleanup_failure: None,
        }),
        Err(_) => Err(AuxiliaryFailure {
            cleanup: reap_bounded(&mut child, &SystemPollClock, WINE_SERVER_COMMAND_TIMEOUT).err(),
        }),
    }
}

#[cfg(any(test, target_os = "macos"))]
fn read_auxiliary_chunk(reader: &mut impl Read, output: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
    let mut buffer = [0_u8; 4096];
    let available = limit.saturating_sub(output.len());
    let read_length = buffer.len().min(available.saturating_add(1));
    match reader.read(&mut buffer[..read_length]) {
        Ok(0) => Ok(true),
        Ok(count) if count > available => Err(io::Error::other("auxiliary output limit exceeded")),
        Ok(count) => {
            output.extend_from_slice(&buffer[..count]);
            Ok(false)
        }
        Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn capture_auxiliary(command: &mut Command, timeout: Duration, limit: usize) -> io::Result<(ExitStatus, Vec<u8>)> {
    use std::os::fd::AsRawFd;
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    let mut process = spawn_auxiliary(command).map_err(|_| io::Error::other("auxiliary spawn failed"))?;
    let result = (|| {
        let mut stdout = process
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("auxiliary output unavailable"))?;
        let descriptor = stdout.as_raw_fd();
        // SAFETY: stdout owns this live descriptor. These flag operations do
        // not close or transfer it; nonblocking reads make the deadline real
        // even when a descendant retains the write end after the root exits.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::other("auxiliary output setup failed"));
        }
        let deadline = Instant::now() + timeout;
        let mut output = Vec::with_capacity(limit);
        let mut eof = false;
        loop {
            if !eof {
                eof = read_auxiliary_chunk(&mut stdout, &mut output, limit)?;
            }
            let status = process.child.try_wait()?;
            if eof {
                if let Some(status) = status {
                    return Ok((status, output));
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("auxiliary capture timed out"));
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
    })();
    let cleanup = reap_bounded(&mut process, &SystemPollClock, WINE_SERVER_COMMAND_TIMEOUT);
    match cleanup {
        Err(stage) => Err(io::Error::other(format!("auxiliary cleanup failed: {stage:?}"))),
        Ok(()) => result,
    }
}

struct SystemStartupOperations;

impl StartupOperations for SystemStartupOperations {}

fn verify_guest_inputs(plan: &LaunchPlan) -> Result<(), ProcessError> {
    if let Some(binding) = &plan.guest_artifact {
        verify_binding_contents(binding).map_err(ProcessError::InvalidGuestArtifact)?;
    }
    if let Some(binding) = &plan.bottle_executable {
        verify_in_place_binding_contents(binding).map_err(ProcessError::InvalidGuestArtifact)?;
    }
    Ok(())
}

#[cfg(any(test, target_os = "macos"))]
#[derive(Debug)]
struct PinnedCommandSpec {
    executable: String,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    current_dir: String,
}

#[cfg(any(test, target_os = "macos"))]
fn validate_pinned_launch_contract(plan: &LaunchPlan, binding: &BottleExecutableBinding) -> Result<(), ProcessError> {
    plan.validate().map_err(|_| invalid_pinned_launch())?;
    if plan.runtime.provider != RuntimeKind::Wine
        || plan.guest_artifact.is_some()
        || plan.bottle_executable.as_ref() != Some(binding)
        || plan.process.arguments.as_slice() != [binding.path.as_str()]
    {
        return Err(invalid_pinned_launch());
    }
    Ok(())
}

#[cfg(any(test, target_os = "macos"))]
fn pinned_command_spec(
    plan: &LaunchPlan,
    binding: &BottleExecutableBinding,
    descriptor: i32,
) -> Result<PinnedCommandSpec, ProcessError> {
    validate_pinned_launch_contract(plan, binding)?;
    if descriptor <= 2 {
        return Err(invalid_pinned_launch());
    }
    Ok(PinnedCommandSpec {
        executable: plan.process.executable.clone(),
        arguments: vec![format!("/dev/fd/{descriptor}")],
        environment: plan.process.environment.clone(),
        current_dir: plan.process.working_directory.clone(),
    })
}

#[cfg(target_os = "macos")]
struct ProcessOwnedPinnedExecution {
    file: std::fs::File,
}

#[cfg(target_os = "macos")]
impl ProcessOwnedPinnedExecution {
    fn duplicate(pinned: &PinnedBottleExecutable) -> Result<Self, ProcessError> {
        use std::os::fd::AsRawFd;

        let mut file = pinned.duplicate_execution_file().map_err(|_| pinned_launch_failed())?;
        file.seek(SeekFrom::Start(0)).map_err(|_| pinned_launch_failed())?;
        let descriptor = file.as_raw_fd();
        // SAFETY: `descriptor` is owned by the live `file`. F_GETFD only reads
        // descriptor flags and neither transfers nor reconstructs ownership.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0 {
            return Err(pinned_launch_failed());
        }
        // SAFETY: F_SETFD updates flags on the same live, process-owned
        // duplicate. Clearing only CLOEXEC is what permits the subsequent
        // direct exec to inherit it; `file` remains its sole Rust owner.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(pinned_launch_failed());
        }
        // SAFETY: F_GETFD performs the same non-owning flag query used above.
        let inherited_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if inherited_flags < 0 || inherited_flags & libc::FD_CLOEXEC != 0 {
            return Err(pinned_launch_failed());
        }
        Ok(Self { file })
    }

    fn descriptor(&self) -> i32 {
        use std::os::fd::AsRawFd;

        self.file.as_raw_fd()
    }
}

#[cfg(target_os = "macos")]
fn start_pinned_bottle_macos(plan: &LaunchPlan, pinned: &PinnedBottleExecutable) -> Result<LaunchHandle, ProcessError> {
    pinned.revalidate().map_err(|_| pinned_launch_failed())?;
    validate_pinned_launch_contract(plan, pinned.binding())?;
    verify_pinned_runtime(plan).map_err(|_| pinned_launch_failed())?;
    validate_existing_pinned_directory(Path::new(&plan.process.working_directory))?;
    let wine_session = WineSession::acquire(plan).map_err(|_| pinned_launch_failed())?;
    let mut startup_guard = wine_session.map(StartupWineSessionGuard::new);
    let execution = startup_step(
        &mut startup_guard,
        StartupStage::PinnedExecution,
        ProcessOwnedPinnedExecution::duplicate(pinned),
    )?;
    let command_spec = startup_step(
        &mut startup_guard,
        StartupStage::PinnedExecution,
        pinned_command_spec(plan, pinned.binding(), execution.descriptor()),
    )?;
    let mut command = Command::new(command_spec.executable);
    command
        .args(command_spec.arguments)
        .current_dir(command_spec.current_dir)
        .env_clear()
        .envs(command_spec.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    supervise_command_with_operations(
        plan,
        command,
        startup_guard,
        execution,
        &SystemStartupOperations,
        || {
            pinned.revalidate().map_err(|_| pinned_launch_failed())?;
            verify_pinned_runtime(plan)
        },
    )
    .map_err(sanitize_pinned_launch_error)
}

#[cfg(target_os = "macos")]
fn validate_existing_pinned_directory(path: &Path) -> Result<(), ProcessError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid_pinned_launch());
    }
    let mut cursor = Path::new("").to_path_buf();
    for component in path.components() {
        cursor.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&cursor).map_err(|_| pinned_launch_failed())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(invalid_pinned_launch());
        }
    }
    Ok(())
}

fn managed_wine_gui_requires_idle_wait(plan: &LaunchPlan) -> bool {
    plan.bottle_executable.is_some()
        || plan
            .guest_artifact
            .as_ref()
            .is_some_and(|binding| binding.subsystem == "windowsGui")
}

#[cfg(any(test, target_os = "macos"))]
fn invalid_pinned_launch() -> ProcessError {
    ProcessError::InvalidGuestArtifact(GuestArtifactError::InvalidPinnedContract)
}

#[cfg(any(test, target_os = "macos"))]
fn pinned_launch_failed() -> ProcessError {
    ProcessError::InvalidGuestArtifact(GuestArtifactError::PinnedCaptureFailed)
}

#[cfg(any(test, target_os = "macos"))]
fn sanitize_pinned_launch_error(error: ProcessError) -> ProcessError {
    match error {
        ProcessError::Startup(_) | ProcessError::StartupCleanup { .. } => error,
        _ => pinned_launch_failed(),
    }
}

fn release_parent_duplicate_after_spawn_attempt<G, T, E>(
    guard: G,
    spawn: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let result = spawn();
    drop(guard);
    result
}

fn supervise_command_with_operations<G>(
    plan: &LaunchPlan,
    mut command: Command,
    mut startup_guard: Option<StartupWineSessionGuard>,
    parent_execution_guard: G,
    operations: &impl StartupOperations,
    before_spawn: impl FnOnce() -> Result<(), ProcessError>,
) -> Result<LaunchHandle, ProcessError> {
    let keep_alive_after_root_exit = managed_wine_gui_requires_idle_wait(plan);
    let prepared_tree = startup_step(
        &mut startup_guard,
        StartupStage::ProcessTreePreparation,
        platform::PreparedProcessTree::prepare(&mut command).map_err(ProcessError::Isolation),
    )?;
    let verification = before_spawn();
    let stage = match &verification {
        Err(ProcessError::InvalidGuestArtifact(_)) => StartupStage::GuestVerification,
        _ => StartupStage::RuntimeVerification,
    };
    startup_step(&mut startup_guard, stage, verification)?;
    let mut child = startup_step(
        &mut startup_guard,
        StartupStage::GuestSpawn,
        release_parent_duplicate_after_spawn_attempt(parent_execution_guard, || operations.spawn(&mut command))
            .map_err(ProcessError::Spawn),
    )?;
    let process_tree = match operations.attach(prepared_tree, &child) {
        Ok(process_tree) => Arc::new(process_tree),
        Err(error) => {
            let rollback = reap_bounded(&mut child, &SystemPollClock, WINE_SERVER_COMMAND_TIMEOUT);
            let error = match rollback {
                Ok(()) => ProcessError::Isolation(error),
                Err(cleanup) => ProcessError::StartupCleanup {
                    startup: StartupStage::ProcessTreeAttachment,
                    cleanup,
                },
            };
            return startup_step(&mut startup_guard, StartupStage::ProcessTreeAttachment, Err(error));
        }
    };

    let process_id = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(child));
    let root_exited = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));
    let termination_started = Arc::new(AtomicBool::new(false));
    let cleanup_failed = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    let emitter = Arc::new(EventEmitter::new(plan.request_id.clone(), sender));
    let wine_session = startup_guard.as_ref().map(|guard| Arc::clone(&guard.session));
    let controller = Arc::new(TerminationController {
        child: Arc::clone(&child),
        process_tree: Arc::clone(&process_tree),
        emitter: Arc::clone(&emitter),
        root_exited: Arc::clone(&root_exited),
        completed: Arc::clone(&completed),
        termination_started: Arc::clone(&termination_started),
        process_id,
        grace_period: Duration::from_millis(plan.lifecycle.termination_grace_milliseconds),
        wine_session: wine_session.clone(),
        keep_alive_after_root_exit,
        cleanup_failed: Arc::clone(&cleanup_failed),
        force_cleanup_started: AtomicBool::new(false),
        completion_lock: Mutex::new(()),
        workers: Mutex::new(Vec::new()),
    });

    emitter.emit(RuntimeEventKind::Started, Some(process_id), None, None, None);
    let mut output_readers = Vec::new();
    if let Some(pipe) = stdout {
        output_readers.push(spawn_output_reader(pipe, OutputStream::Stdout, Arc::clone(&emitter)));
    }
    if let Some(pipe) = stderr {
        output_readers.push(spawn_output_reader(pipe, OutputStream::Stderr, Arc::clone(&emitter)));
    }
    let exit_watcher = spawn_exit_watcher(
        child,
        process_tree,
        ExitWatcherConfig {
            root_exited: Arc::clone(&root_exited),
            completed: Arc::clone(&completed),
            emitter: Arc::clone(&emitter),
            wine_session,
            output_readers,
            termination_started: Arc::clone(&termination_started),
            keep_alive_after_root_exit,
            cleanup_failed,
        },
    );
    controller.register_worker(exit_watcher);
    // Both long-lived owners now hold clones of this exact session. Until
    // this point an unwind quarantines the lease without executing commands.
    if let Some(guard) = startup_guard.take() {
        guard.commit();
    }
    if let Some(maximum_runtime) = plan.lifecycle.maximum_runtime_milliseconds {
        let timeout_watcher = spawn_timeout_watcher(
            Arc::downgrade(&controller),
            root_exited,
            Arc::clone(&completed),
            keep_alive_after_root_exit,
            Duration::from_millis(maximum_runtime),
        );
        controller.register_worker(timeout_watcher);
    }

    Ok(LaunchHandle {
        receiver: Mutex::new(receiver),
        controller,
    })
}

fn execution_arguments(plan: &LaunchPlan, guest_alias: Option<&Path>) -> Vec<String> {
    let mut arguments = plan.process.arguments.clone();
    if let Some(alias) = guest_alias {
        if let Some(first) = arguments.first_mut() {
            *first = alias.to_string_lossy().into_owned();
        }
    }
    arguments
}

/// Wine selects the PE loader from the filename suffix. Immutable guest
/// objects intentionally use extensionless content-addressed paths, so make
/// a same-filesystem hard-link with a deterministic `.exe` suffix immediately
/// before launch. The source object remains the binding of record and the
/// alias is rechecked for type, size and digest before it is used.
fn prepare_guest_execution_alias(plan: &LaunchPlan) -> Result<Option<PathBuf>, ProcessError> {
    if plan.runtime.provider != RuntimeKind::Wine {
        return Ok(None);
    }
    let Some(binding) = &plan.guest_artifact else {
        return Ok(None);
    };
    let source = Path::new(&binding.stored_path);
    if source.extension().is_some() {
        return Ok(None);
    }
    let Some(name) = source.file_name().and_then(|value| value.to_str()) else {
        return Err(ProcessError::InvalidRuntimeEvidence("guest execution alias"));
    };
    let alias = source.with_file_name(format!("{name}.exe"));
    match std::fs::symlink_metadata(&alias) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(ProcessError::InvalidRuntimeEvidence("guest execution alias"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::hard_link(source, &alias)
                .map_err(|_| ProcessError::InvalidRuntimeEvidence("guest execution alias"))?;
        }
        Err(_) => return Err(ProcessError::InvalidRuntimeEvidence("guest execution alias")),
    }
    let metadata =
        std::fs::symlink_metadata(&alias).map_err(|_| ProcessError::InvalidRuntimeEvidence("guest execution alias"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != binding.size_bytes
        || sha256_file(&alias).map_err(|_| ProcessError::InvalidRuntimeEvidence("guest execution alias"))?
            != binding.digest
    {
        return Err(ProcessError::InvalidRuntimeEvidence("guest execution alias"));
    }
    Ok(Some(alias))
}

/// Initialize a newly materialized Wine prefix with the same pinned Wine
/// executable that will launch the guest. This is deliberately a direct
/// executable invocation with a bounded wait: it never consults PATH or a
/// shell, and it runs only when the prefix has not yet produced Wine's
/// system32 marker. Existing prefixes are left untouched.
fn initialize_wine_prefix(plan: &LaunchPlan) -> Result<(), ProcessError> {
    initialize_wine_prefix_with_timeout(plan, WINE_PREFIX_BOOTSTRAP_TIMEOUT)
}

fn initialize_wine_prefix_with_timeout(plan: &LaunchPlan, timeout: Duration) -> Result<(), ProcessError> {
    initialize_wine_prefix_with_spawn(plan, timeout, Command::spawn)
}

fn initialize_wine_prefix_with_spawn(
    plan: &LaunchPlan,
    timeout: Duration,
    spawn: impl FnOnce(&mut Command) -> io::Result<Child>,
) -> Result<(), ProcessError> {
    if plan.runtime.provider != RuntimeKind::Wine {
        return Ok(());
    }
    // A managed Wine launch always carries a wineserver lifecycle.  Keep the
    // low-level process/FFI compatibility path usable for callers that only
    // label a command as Wine but intentionally provide no managed prefix
    // lifecycle (for example, a native process probe).
    if plan.lifecycle.wineserver.is_none() {
        return Ok(());
    }
    let Some(prefix) = plan.process.environment.get("WINEPREFIX") else {
        return Ok(());
    };
    let prefix = Path::new(prefix);
    let marker = prefix.join("drive_c/windows/system32/ntdll.dll");
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => return Ok(()),
        Ok(_) => return Err(ProcessError::UnsafeDirectory("Wine prefix marker")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(ProcessError::UnsafeDirectory("Wine prefix marker")),
    }

    let mut command = Command::new(&plan.process.executable);
    command
        .args(["wineboot", "-u"])
        .current_dir(&plan.process.working_directory)
        .env_clear()
        .envs(&plan.process.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child =
        spawn_auxiliary_with(&mut command, spawn).map_err(|error| error.into_process_error(StartupStage::Wineboot))?;
    match wait_bounded(&mut child, &SystemPollClock, timeout) {
        Ok(true) => {
            let metadata =
                std::fs::symlink_metadata(&marker).map_err(|_| ProcessError::UnsafeDirectory("Wine prefix marker"))?;
            if metadata.is_file() && !metadata.file_type().is_symlink() {
                return Ok(());
            }
            Err(ProcessError::UnsafeDirectory("Wine prefix marker"))
        }
        Ok(false) => Err(ProcessError::Spawn(io::Error::other("wineboot exited unsuccessfully"))),
        Err(error) => Err(error.into_process_error(StartupStage::Wineboot)),
    }
}

/// Materialize the working directory and Wine prefix only after plan
/// authorization and digest checks. Every existing path component is checked
/// with `symlink_metadata` so a path collision cannot redirect the launch.
fn materialize_launch_directories(plan: &LaunchPlan) -> Result<(), ProcessError> {
    ensure_directory(Path::new(&plan.process.working_directory), "working directory")?;
    if let Some(prefix) = plan.process.environment.get("WINEPREFIX") {
        ensure_directory(Path::new(prefix), "WINEPREFIX")?;
    }
    Ok(())
}

fn ensure_directory(path: &Path, field: &'static str) -> Result<(), ProcessError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ProcessError::UnsafeDirectory(field));
    }
    let mut cursor = Path::new("").to_path_buf();
    for component in path.components() {
        cursor.push(component.as_os_str());
        match std::fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProcessError::UnsafeDirectory(field));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&cursor).map_err(|_| ProcessError::UnsafeDirectory(field))?;
                let metadata = std::fs::symlink_metadata(&cursor).map_err(|_| ProcessError::UnsafeDirectory(field))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProcessError::UnsafeDirectory(field));
                }
            }
            Err(_) => return Err(ProcessError::UnsafeDirectory(field)),
        }
    }
    Ok(())
}

fn verify_pinned_runtime(plan: &LaunchPlan) -> Result<(), ProcessError> {
    let environment = &plan.process.environment;
    let managed = plan.lifecycle.wineserver.is_some()
        || [
            "COMPATFORGE_RUNTIME_PACK_DIGEST",
            RUNTIME_EXECUTABLE_DIGEST_ENV,
            WINESERVER_EXECUTABLE_DIGEST_ENV,
            "WINESERVER",
        ]
        .iter()
        .any(|key| environment.contains_key(*key));
    // Legacy native/FFI probes may label a command with Pack + WINEPREFIX
    // without claiming a managed Wine lifecycle or pinned Runtime evidence.
    if !managed {
        return Ok(());
    }
    if plan.runtime.provider != RuntimeKind::Wine {
        return Err(ProcessError::InvalidRuntimeEvidence("Runtime provider"));
    }
    let (Some(runtime_digest), Some(wineserver_digest)) = (
        environment.get(RUNTIME_EXECUTABLE_DIGEST_ENV),
        environment.get(WINESERVER_EXECUTABLE_DIGEST_ENV),
    ) else {
        return Err(ProcessError::InvalidRuntimeEvidence("incomplete Runtime evidence"));
    };
    let lifecycle = plan
        .lifecycle
        .wineserver
        .as_ref()
        .ok_or(ProcessError::InvalidRuntimeEvidence("wineserver lifecycle"))?;
    // Validate the plan's exact identity before materialization or commands.
    // Store manifest association remains the Provider/PreparedLaunch's job.
    for (key, expected) in [
        ("WINESERVER", &lifecycle.executable),
        ("WINEPREFIX", &lifecycle.prefix),
        ("COMPATFORGE_RUNTIME_PACK", &plan.runtime.pack_id),
        ("COMPATFORGE_RUNTIME_PACK_DIGEST", &plan.runtime.pack_digest),
    ] {
        if environment.get(key) != Some(expected) {
            return Err(ProcessError::InvalidRuntimeEvidence(key));
        }
    }
    verify_pinned_executable(
        Path::new(&plan.process.executable),
        runtime_digest,
        "runtime executable",
    )?;
    verify_pinned_executable(
        Path::new(&lifecycle.executable),
        wineserver_digest,
        "wineserver executable",
    )
}

fn verify_pinned_font_config(plan: &LaunchPlan) -> Result<(), ProcessError> {
    let path = plan.process.environment.get(FONT_CONFIG_FILE_ENV);
    let digest = plan.process.environment.get(FONT_CONFIG_DIGEST_ENV);
    match (path, digest) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(ProcessError::InvalidRuntimeEvidence(
            "incomplete font configuration evidence",
        )),
        (Some(path), Some(digest)) => verify_pinned_regular_file(Path::new(path), digest, "font configuration"),
    }
}

fn verify_pinned_bottle_font(plan: &LaunchPlan) -> Result<(), ProcessError> {
    let path = plan.process.environment.get(BOTTLE_FONT_FILE_ENV);
    let digest = plan.process.environment.get(BOTTLE_FONT_DIGEST_ENV);
    match (path, digest) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            Err(ProcessError::InvalidRuntimeEvidence("incomplete Bottle font evidence"))
        }
        (Some(path), Some(digest)) => verify_pinned_regular_file(Path::new(path), digest, "Bottle font"),
    }
}

/// Link a digest-pinned host CJK font into the managed prefix and install a
/// fixed, product-owned set of Wine GDI substitutions. The source file is
/// never copied or modified, and an existing non-owned target is rejected.
fn prepare_pinned_bottle_font(plan: &LaunchPlan) -> Result<(), ProcessError> {
    let (Some(source), Some(_digest)) = (
        plan.process.environment.get(BOTTLE_FONT_FILE_ENV),
        plan.process.environment.get(BOTTLE_FONT_DIGEST_ENV),
    ) else {
        return Ok(());
    };
    if plan.runtime.provider != RuntimeKind::Wine || plan.lifecycle.wineserver.is_none() {
        return Err(ProcessError::InvalidRuntimeEvidence("Bottle font Wine lifecycle"));
    }
    let prefix = plan
        .process
        .environment
        .get("WINEPREFIX")
        .ok_or(ProcessError::InvalidRuntimeEvidence("Bottle font WINEPREFIX"))?;
    let fonts = Path::new(prefix).join("drive_c/windows/Fonts");
    ensure_directory(&fonts, "Bottle fonts directory")?;
    let target = fonts.join(BOTTLE_FONT_FILE_NAME);
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let destination =
                std::fs::read_link(&target).map_err(|_| ProcessError::InvalidRuntimeEvidence("Bottle font link"))?;
            if destination != Path::new(source) {
                return Err(ProcessError::InvalidRuntimeEvidence("Bottle font link"));
            }
        }
        Ok(_) => return Err(ProcessError::InvalidRuntimeEvidence("Bottle font link")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            #[cfg(unix)]
            std::os::unix::fs::symlink(source, &target)
                .map_err(|_| ProcessError::InvalidRuntimeEvidence("Bottle font link"))?;
            #[cfg(not(unix))]
            return Err(ProcessError::InvalidRuntimeEvidence("Bottle font link"));
        }
        Err(_) => return Err(ProcessError::InvalidRuntimeEvidence("Bottle font link")),
    }
    verify_pinned_bottle_font(plan)?;

    const REGISTRY_KEYS: &[&str] = &[
        r"HKCU\Software\Wine\Fonts\Replacements",
        r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\FontSubstitutes",
    ];
    const REGISTRY_NAMES: &[&str] = &[
        "Tahoma",
        "Arial",
        "Segoe UI",
        "Microsoft Sans Serif",
        "MS Shell Dlg",
        "MS Shell Dlg 2",
        "Microsoft YaHei",
        "SimHei",
        "SimSun",
    ];
    for key in REGISTRY_KEYS {
        for name in REGISTRY_NAMES {
            run_bounded_wine_command(plan, &["reg", "add", key, "/v", name, "/d", "Heiti SC", "/f"])?;
        }
    }
    run_bounded_wine_command(
        plan,
        &[
            "reg",
            "add",
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts",
            "/v",
            "Heiti SC (TrueType)",
            "/d",
            BOTTLE_FONT_FILE_NAME,
            "/f",
        ],
    )
}

fn run_bounded_wine_command(plan: &LaunchPlan, arguments: &[&str]) -> Result<(), ProcessError> {
    verify_pinned_runtime(plan)?;
    let mut command = Command::new(&plan.process.executable);
    command
        .args(arguments)
        .current_dir(&plan.process.working_directory)
        .env_clear()
        .envs(&plan.process.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child =
        spawn_auxiliary(&mut command).map_err(|error| error.into_process_error(StartupStage::FontPreparation))?;
    match wait_bounded(&mut child, &SystemPollClock, WINE_PREFIX_BOOTSTRAP_TIMEOUT) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ProcessError::Startup(StartupStage::FontPreparation)),
        Err(error) => Err(error.into_process_error(StartupStage::FontPreparation)),
    }
}

fn verify_pinned_executable(path: &Path, expected: &str, field: &'static str) -> Result<(), ProcessError> {
    if expected.len() != 71
        || !expected.starts_with("sha256:")
        || !expected[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProcessError::InvalidRuntimeEvidence(field));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ProcessError::InvalidRuntimeEvidence(field))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || !is_executable(path) {
        return Err(ProcessError::InvalidRuntimeEvidence(field));
    }
    let actual = sha256_file(path).map_err(|_| ProcessError::InvalidRuntimeEvidence(field))?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(ProcessError::InvalidRuntimeEvidence(field));
    }
    Ok(())
}

fn verify_pinned_regular_file(path: &Path, expected: &str, field: &'static str) -> Result<(), ProcessError> {
    if !path.is_absolute()
        || expected.len() != 71
        || !expected.starts_with("sha256:")
        || !expected[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProcessError::InvalidRuntimeEvidence(field));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ProcessError::InvalidRuntimeEvidence(field))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProcessError::InvalidRuntimeEvidence(field));
    }
    let actual = sha256_file(path).map_err(|_| ProcessError::InvalidRuntimeEvidence(field))?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(ProcessError::InvalidRuntimeEvidence(field));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let mut value = String::from("sha256:");
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing a digest to a string cannot fail");
    }
    Ok(value)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

pub struct LaunchHandle {
    receiver: Mutex<Receiver<RuntimeEvent>>,
    controller: Arc<TerminationController>,
}

impl LaunchHandle {
    #[must_use]
    pub fn next_event(&self, timeout: Duration) -> EventPoll {
        let receiver = lock_recover(&self.receiver);
        match receiver.recv_timeout(timeout) {
            Ok(event) => EventPoll::Event(event),
            Err(RecvTimeoutError::Timeout) => EventPoll::Timeout,
            Err(RecvTimeoutError::Disconnected) => EventPoll::Closed,
        }
    }

    /// Request idempotent graceful termination followed by forced tree cleanup.
    pub fn terminate(&self) -> Result<(), ProcessError> {
        self.controller.request_termination(TerminationReason::User)
    }

    /// Terminate if still live, complete bounded forced cleanup when needed,
    /// and join every supervisor worker before returning.
    pub fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), ProcessError> {
        let _completion_guard = lock_recover(&self.controller.completion_lock);
        let termination_error = self.terminate().err();
        let force_error = if self.controller.wait_until_completed(graceful_wait) {
            None
        } else {
            self.controller.force_cleanup().err()
        };
        if !self
            .controller
            .wait_until_completed(SUPERVISOR_FORCE_COMPLETION_TIMEOUT)
        {
            let _ = self.controller.force_kill_and_reap();
        }
        let join_error = self.controller.join_workers().err();
        if let Some(error) = join_error.or(force_error).or(termination_error) {
            return Err(error);
        }
        if !self.is_finished() || self.controller.cleanup_failed.load(Ordering::Acquire) {
            return Err(ProcessError::Terminate(io::Error::other(
                "process cleanup did not complete successfully",
            )));
        }
        Ok(())
    }

    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.controller.completed.load(Ordering::Acquire)
    }
}

impl Drop for LaunchHandle {
    fn drop(&mut self) {
        let _ = self.controller.request_termination(TerminationReason::HandleDropped);
    }
}

#[derive(Clone, Copy)]
enum TerminationReason {
    User,
    Timeout,
    HandleDropped,
}

struct TerminationController {
    child: Arc<Mutex<Child>>,
    process_tree: Arc<platform::ProcessTree>,
    emitter: Arc<EventEmitter>,
    root_exited: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    termination_started: Arc<AtomicBool>,
    process_id: u32,
    grace_period: Duration,
    wine_session: Option<Arc<WineSession>>,
    keep_alive_after_root_exit: bool,
    cleanup_failed: Arc<AtomicBool>,
    force_cleanup_started: AtomicBool,
    completion_lock: Mutex<()>,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl TerminationController {
    fn request_termination(self: &Arc<Self>, reason: TerminationReason) -> Result<(), ProcessError> {
        if self.completed.load(Ordering::Acquire)
            || (self.root_exited.load(Ordering::Acquire) && !self.keep_alive_after_root_exit)
        {
            return Ok(());
        }
        if self
            .termination_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        let (kind, message) = match reason {
            TerminationReason::Timeout => (RuntimeEventKind::TimedOut, Some("maximum runtime exceeded".into())),
            TerminationReason::User => (
                RuntimeEventKind::TerminateRequested,
                Some("termination requested".into()),
            ),
            TerminationReason::HandleDropped => (
                RuntimeEventKind::TerminateRequested,
                Some("launch handle released while process was running".into()),
            ),
        };
        self.emitter.emit(kind, Some(self.process_id), None, None, message);

        if let Err(error) = self.process_tree.request_graceful() {
            self.emitter.emit(
                RuntimeEventKind::Failed,
                Some(self.process_id),
                None,
                None,
                Some(format!("graceful process-tree termination failed: {error}")),
            );
            let _ = self.process_tree.force_kill();
            return Err(ProcessError::Terminate(error));
        }

        let controller = Arc::clone(self);
        let worker = thread::spawn(move || controller.escalate_after_grace());
        self.register_worker(worker);
        Ok(())
    }

    fn escalate_after_grace(&self) {
        let deadline = Instant::now() + self.grace_period;
        while Instant::now() < deadline {
            if self.completed.load(Ordering::Acquire)
                || (self.root_exited.load(Ordering::Acquire) && !self.keep_alive_after_root_exit)
            {
                return;
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        if self.completed.load(Ordering::Acquire)
            || (self.root_exited.load(Ordering::Acquire) && !self.keep_alive_after_root_exit)
        {
            return;
        }
        let _ = self.force_cleanup();
    }

    fn register_worker(&self, worker: thread::JoinHandle<()>) {
        lock_recover(&self.workers).push(worker);
    }

    #[cfg(test)]
    fn worker_count(&self) -> usize {
        lock_recover(&self.workers).len()
    }

    fn wait_until_completed(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !self.completed.load(Ordering::Acquire) && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(PROCESS_POLL_INTERVAL.min(remaining));
        }
        self.completed.load(Ordering::Acquire)
    }

    fn force_cleanup(&self) -> Result<(), ProcessError> {
        if self.force_cleanup_started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.emitter.emit(
            RuntimeEventKind::GracePeriodExpired,
            Some(self.process_id),
            None,
            None,
            Some("graceful termination period expired; forcing process tree shutdown".into()),
        );
        let mut first_error = None;
        if let Some(wine_session) = &self.wine_session {
            if let Err(error) = wine_session.stop(&self.emitter) {
                self.emitter.emit(
                    RuntimeEventKind::Failed,
                    Some(self.process_id),
                    None,
                    None,
                    Some(format!("wineserver cleanup failed: {error}")),
                );
                first_error = Some(error);
            }
        }
        if let Err(error) = self.process_tree.force_kill() {
            self.emitter.emit(
                RuntimeEventKind::Failed,
                Some(self.process_id),
                None,
                None,
                Some(format!("forced process-tree termination failed: {error}")),
            );
            if first_error.is_none() {
                first_error = Some(error);
            }
            let mut child = lock_recover(&self.child);
            let _ = child.kill();
        }
        if let Some(error) = first_error {
            self.cleanup_failed.store(true, Ordering::Release);
            Err(ProcessError::Terminate(error))
        } else {
            Ok(())
        }
    }

    fn force_kill_and_reap(&self) -> Result<(), ProcessError> {
        let tree_error = self.process_tree.force_kill().err();
        let mut child = lock_recover(&self.child);
        let kill_error = child.kill().err();
        let wait_error = child.wait().err();
        if let Some(error) = tree_error.or(kill_error).or(wait_error) {
            self.cleanup_failed.store(true, Ordering::Release);
            Err(ProcessError::Terminate(error))
        } else {
            Ok(())
        }
    }

    fn join_workers(&self) -> Result<(), ProcessError> {
        let mut panicked = false;
        loop {
            let workers = std::mem::take(&mut *lock_recover(&self.workers));
            if workers.is_empty() {
                break;
            }
            for worker in workers {
                panicked |= worker.join().is_err();
            }
        }
        if panicked {
            self.cleanup_failed.store(true, Ordering::Release);
            Err(ProcessError::Terminate(io::Error::other(
                "process supervisor worker panicked",
            )))
        } else {
            Ok(())
        }
    }
}

struct EventEmitter {
    request_id: String,
    started: Instant,
    state: Mutex<EventState>,
    sender: Sender<RuntimeEvent>,
}

struct EventState {
    sequence: u64,
    terminal: bool,
}

impl EventEmitter {
    fn new(request_id: String, sender: Sender<RuntimeEvent>) -> Self {
        Self {
            request_id,
            started: Instant::now(),
            state: Mutex::new(EventState {
                sequence: 0,
                terminal: false,
            }),
            sender,
        }
    }

    fn emit(
        &self,
        kind: RuntimeEventKind,
        process_id: Option<u32>,
        output: Option<ProcessOutput>,
        exit: Option<ProcessExit>,
        message: Option<String>,
    ) {
        let mut state = lock_recover(&self.state);
        if state.terminal {
            return;
        }
        let elapsed_milliseconds = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let event = RuntimeEvent {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: self.request_id.clone(),
            sequence: state.sequence,
            elapsed_milliseconds,
            kind,
            process_id,
            output,
            exit,
            message,
        };
        state.sequence = state.sequence.saturating_add(1);
        if kind == RuntimeEventKind::Exited {
            state.terminal = true;
        }
        let _ = self.sender.send(event);
    }
}

fn spawn_output_reader(
    pipe: impl Read + Send + 'static,
    stream: OutputStream,
    emitter: Arc<EventEmitter>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(_) => emitter.emit(
                    RuntimeEventKind::Output,
                    None,
                    Some(ProcessOutput {
                        stream,
                        text: String::from_utf8_lossy(&buffer).into_owned(),
                    }),
                    None,
                    None,
                ),
                Err(error) => {
                    emitter.emit(
                        RuntimeEventKind::Failed,
                        None,
                        None,
                        None,
                        Some(format!("failed to read {stream:?}: {error}")),
                    );
                    break;
                }
            }
        }
    })
}

struct ExitWatcherConfig {
    root_exited: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    emitter: Arc<EventEmitter>,
    wine_session: Option<Arc<WineSession>>,
    output_readers: Vec<thread::JoinHandle<()>>,
    termination_started: Arc<AtomicBool>,
    keep_alive_after_root_exit: bool,
    cleanup_failed: Arc<AtomicBool>,
}

fn spawn_exit_watcher(
    child: Arc<Mutex<Child>>,
    process_tree: Arc<platform::ProcessTree>,
    config: ExitWatcherConfig,
) -> thread::JoinHandle<()> {
    let ExitWatcherConfig {
        root_exited,
        completed,
        emitter,
        wine_session,
        output_readers,
        termination_started,
        keep_alive_after_root_exit,
        cleanup_failed,
    } = config;
    thread::spawn(move || {
        let result = loop {
            let result = lock_recover(&child).try_wait();
            match result {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
                Err(error) => break Err(error),
            }
        };
        root_exited.store(true, Ordering::Release);

        if keep_alive_after_root_exit {
            if let Some(wine_session) = wine_session.as_ref() {
                if let Err(error) = wine_session.wait_until_idle(&termination_started) {
                    cleanup_failed.store(true, Ordering::Release);
                    emitter.emit(
                        RuntimeEventKind::Failed,
                        None,
                        None,
                        None,
                        Some(format!("waiting for wineserver idle failed: {error}")),
                    );
                }
            } else {
                while !termination_started.load(Ordering::Acquire) {
                    thread::sleep(PROCESS_POLL_INTERVAL);
                }
            }
        }

        if let Some(wine_session) = wine_session {
            if let Err(error) = wine_session.stop(&emitter) {
                cleanup_failed.store(true, Ordering::Release);
                emitter.emit(
                    RuntimeEventKind::Failed,
                    None,
                    None,
                    None,
                    Some(format!("wineserver cleanup failed: {error}")),
                );
            }
        }
        if let Err(error) = process_tree.force_kill() {
            cleanup_failed.store(true, Ordering::Release);
            emitter.emit(
                RuntimeEventKind::Failed,
                None,
                None,
                None,
                Some(format!("descendant process cleanup failed: {error}")),
            );
        }
        // Descendants may inherit the output pipes, so terminate the tree before
        // draining readers and publishing the terminal event.
        for output_reader in output_readers {
            if output_reader.join().is_err() {
                cleanup_failed.store(true, Ordering::Release);
                emitter.emit(
                    RuntimeEventKind::Failed,
                    None,
                    None,
                    None,
                    Some("output reader panicked".into()),
                );
            }
        }

        let wait_failed = result.is_err();
        match result {
            Ok(status) => emit_exit(&emitter, status),
            Err(error) => emitter.emit(
                RuntimeEventKind::Failed,
                None,
                None,
                None,
                Some(format!("process wait failed: {error}")),
            ),
        }
        if wait_failed {
            cleanup_failed.store(true, Ordering::Release);
        }
        completed.store(true, Ordering::Release);
    })
}

fn spawn_timeout_watcher(
    controller: Weak<TerminationController>,
    root_exited: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    keep_alive_after_root_exit: bool,
    maximum_runtime: Duration,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let deadline = Instant::now() + maximum_runtime;
        while Instant::now() < deadline {
            if completed.load(Ordering::Acquire)
                || (root_exited.load(Ordering::Acquire) && !keep_alive_after_root_exit)
                || controller.strong_count() == 0
            {
                return;
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        if let Some(controller) = controller.upgrade() {
            let _ = controller.request_termination(TerminationReason::Timeout);
        }
    })
}

fn emit_exit(emitter: &EventEmitter, status: ExitStatus) {
    emitter.emit(
        RuntimeEventKind::Exited,
        None,
        None,
        Some(ProcessExit {
            code: status.code(),
            success: status.success(),
        }),
        None,
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseState {
    Live,
    Released,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopOutcome {
    Complete,
    Failed(CleanupStage),
}

struct StartupWineSessionGuard {
    session: Arc<WineSession>,
    armed: bool,
}

impl StartupWineSessionGuard {
    fn new(session: Arc<WineSession>) -> Self {
        Self { session, armed: true }
    }

    fn commit(mut self) {
        self.armed = false;
    }

    fn abort(mut self, startup: StartupStage) -> Result<(), ProcessError> {
        let outcome = self.session.stop_core(None);
        self.armed = false;
        match outcome {
            StopOutcome::Complete => Err(ProcessError::Startup(startup)),
            StopOutcome::Failed(cleanup) => Err(ProcessError::StartupCleanup { startup, cleanup }),
        }
    }
}

impl Drop for StartupWineSessionGuard {
    fn drop(&mut self) {
        if self.armed {
            self.session.poison_lease();
        }
    }
}

fn startup_step<T>(
    guard: &mut Option<StartupWineSessionGuard>,
    stage: StartupStage,
    result: Result<T, ProcessError>,
) -> Result<T, ProcessError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if let Some(guard) = guard.take() {
                if let ProcessError::StartupCleanup { cleanup, .. } = error {
                    let _ = guard.session.prior_cleanup_failure.set(cleanup);
                }
                guard.abort(stage)?;
                unreachable!("aborting startup always returns an error");
            }
            Err(error)
        }
    }
}

struct WineSession {
    lifecycle: WineServerLifecycle,
    environment: Vec<(String, String)>,
    working_directory: String,
    expected_wineserver_digest: String,
    stop_outcome: OnceLock<StopOutcome>,
    prior_cleanup_failure: OnceLock<CleanupStage>,
    lease_state: Mutex<LeaseState>,
    stopping: AtomicBool,
    idle_cleanup_lock: Mutex<()>,
}

trait NaturalIdleCommand {
    fn try_wait_success(&mut self) -> io::Result<Option<bool>>;
    fn interrupt_and_reap(&mut self) -> io::Result<()>;
}

trait NaturalIdleCleanupSteps {
    fn poll_for_exit(&mut self) -> io::Result<bool>;
    fn kill_for_cleanup(&mut self) -> io::Result<()>;
    fn wait_for_reap_bounded(&mut self) -> io::Result<()>;
}

fn interrupt_and_reap_natural_idle<C: NaturalIdleCleanupSteps>(command: &mut C) -> io::Result<()> {
    let poll_error = match command.poll_for_exit() {
        Ok(true) => return Ok(()),
        Ok(false) => None,
        Err(error) => Some(error),
    };
    let kill_error = command.kill_for_cleanup().err();
    let wait_error = command.wait_for_reap_bounded().err();
    if let Some(error) = wait_error.or(kill_error).or(poll_error) {
        Err(error)
    } else {
        Ok(())
    }
}

impl NaturalIdleCleanupSteps for Child {
    fn poll_for_exit(&mut self) -> io::Result<bool> {
        self.try_wait().map(|status| status.is_some())
    }

    fn kill_for_cleanup(&mut self) -> io::Result<()> {
        self.kill()
    }

    fn wait_for_reap_bounded(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + WINE_SERVER_COMMAND_TIMEOUT;
        loop {
            match self.try_wait()? {
                Some(_) => return Ok(()),
                None if Instant::now() >= deadline => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "wineserver -w cleanup did not reap within the cleanup deadline",
                    ));
                }
                None => thread::sleep(PROCESS_POLL_INTERVAL),
            }
        }
    }
}

impl NaturalIdleCommand for Child {
    fn try_wait_success(&mut self) -> io::Result<Option<bool>> {
        self.try_wait().map(|status| status.map(|status| status.success()))
    }

    fn interrupt_and_reap(&mut self) -> io::Result<()> {
        interrupt_and_reap_natural_idle(self)
    }
}

impl NaturalIdleCommand for AuxiliaryProcess {
    fn try_wait_success(&mut self) -> io::Result<Option<bool>> {
        self.poll()
    }
    fn interrupt_and_reap(&mut self) -> io::Result<()> {
        reap_bounded(self, &SystemPollClock, WINE_SERVER_COMMAND_TIMEOUT).map_err(|stage| {
            self.cleanup_failure = Some(stage);
            io::Error::other(format!("Wine cleanup failed: {stage:?}"))
        })
    }
}

#[cfg(test)]
fn wait_for_natural_idle_command<C: NaturalIdleCommand>(
    command: &mut C,
    termination_started: &AtomicBool,
    wait_for_next_poll: impl FnMut(),
) -> io::Result<()> {
    wait_for_natural_idle_command_with_stop(
        command,
        || termination_started.load(Ordering::Acquire),
        wait_for_next_poll,
    )
}

fn wait_for_natural_idle_command_with_stop<C: NaturalIdleCommand>(
    command: &mut C,
    termination_requested: impl Fn() -> bool,
    mut wait_for_next_poll: impl FnMut(),
) -> io::Result<()> {
    loop {
        if termination_requested() {
            return command.interrupt_and_reap();
        }
        match command.try_wait_success() {
            Ok(Some(true)) => return Ok(()),
            Ok(Some(false)) => return Err(io::Error::other("wineserver -w exited unsuccessfully")),
            Ok(None) => wait_for_next_poll(),
            Err(error) => {
                return match command.interrupt_and_reap() {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(cleanup_error),
                };
            }
        }
    }
}

impl WineSession {
    fn acquire(plan: &LaunchPlan) -> Result<Option<Arc<Self>>, ProcessError> {
        let Some(mut lifecycle) = plan.lifecycle.wineserver.clone() else {
            return Ok(None);
        };
        lifecycle.prefix = std::fs::canonicalize(&lifecycle.prefix)
            .map_err(|_| ProcessError::UnsafeDirectory("WINEPREFIX"))?
            .to_str()
            .ok_or(ProcessError::UnsafeDirectory("WINEPREFIX"))?
            .into();
        let expected_wineserver_digest = plan
            .process
            .environment
            .get(WINESERVER_EXECUTABLE_DIGEST_ENV)
            .ok_or(ProcessError::InvalidRuntimeEvidence("wineserver executable"))?
            .clone();
        let mut leases = lock_recover(wine_prefix_leases());
        if !leases.insert(lifecycle.prefix.clone()) {
            return Err(ProcessError::WinePrefixBusy(lifecycle.prefix));
        }
        drop(leases);

        Ok(Some(Arc::new(Self {
            lifecycle,
            environment: plan
                .process
                .environment
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            working_directory: plan.process.working_directory.clone(),
            expected_wineserver_digest,
            stop_outcome: OnceLock::new(),
            prior_cleanup_failure: OnceLock::new(),
            lease_state: Mutex::new(LeaseState::Live),
            stopping: AtomicBool::new(false),
            idle_cleanup_lock: Mutex::new(()),
        })))
    }

    fn stop(&self, emitter: &EventEmitter) -> io::Result<()> {
        match self.stop_core(Some(emitter)) {
            StopOutcome::Complete => Ok(()),
            StopOutcome::Failed(stage) => Err(io::Error::other(format!("Wine cleanup failed: {stage:?}"))),
        }
    }

    fn stop_core(&self, emitter: Option<&EventEmitter>) -> StopOutcome {
        *self.stop_outcome.get_or_init(|| {
            self.stopping.store(true, Ordering::Release);
            // A natural-idle command may still own a subprocess. Wake it and
            // include its bounded reap result before memoizing cleanup/releasing.
            let _idle_guard = lock_recover(&self.idle_cleanup_lock);
            if let Some(emitter) = emitter {
                emitter.emit(
                    RuntimeEventKind::WineServerStopRequested,
                    None,
                    None,
                    None,
                    Some(format!("stopping wineserver for prefix {}", self.lifecycle.prefix)),
                );
            }

            // A root/descendant may have already caused wineserver to exit. In
            // that case `-k` returns status 1, while the authoritative `-w`
            // rendezvous succeeds; cleanup is still complete and idempotent.
            let kill_result = self.run_command("-k");
            // Wine's macOS driver may detach a GUI client from the launch process
            // group. Some Runtime builds leave that host process blocked after
            // wineserver exits instead of terminating it, which produces a frozen
            // window whose Close and Exit actions no longer work. Bind the
            // fallback to this prefix's system32 directory or ntdll mapping so
            // another Bottle is never selected merely because it is also running
            // Wine. Some macOS Wine builds retain the directory as their current
            // working directory without keeping the marker file open.
            let client_cleanup_result = platform::force_kill_wine_prefix_clients(Path::new(&self.lifecycle.prefix));
            let wait_result = self.run_command("-w");
            let outcome = match (kill_result, wait_result, client_cleanup_result) {
                (Err(CleanupStage::RuntimeVerification), _, _) | (_, Err(CleanupStage::RuntimeVerification), _) => {
                    StopOutcome::Failed(CleanupStage::RuntimeVerification)
                }
                (_, _, Err(_)) => StopOutcome::Failed(CleanupStage::ClientCleanup),
                (_, Err(stage), _) => StopOutcome::Failed(stage),
                (Err(stage), _, _) if stage != CleanupStage::ServerExit => StopOutcome::Failed(stage),
                _ => StopOutcome::Complete,
            };
            let outcome = self
                .prior_cleanup_failure
                .get()
                .map_or(outcome, |stage| StopOutcome::Failed(*stage));
            if outcome == StopOutcome::Complete {
                self.release_lease();
            } else {
                self.poison_lease();
            }
            outcome
        })
    }

    /// Wait until the managed Wine server reports that every process in the
    /// managed prefix has exited. Unlike `stop`, this does not terminate a
    /// normally closing GUI application; an explicit termination request may
    /// still run `stop` concurrently and wake this rendezvous.
    fn wait_until_idle(&self, termination_started: &AtomicBool) -> io::Result<()> {
        let _idle_guard = lock_recover(&self.idle_cleanup_lock);
        if termination_started.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut child = self.spawn_command("-w").map_err(|stage| {
            let _ = self.prior_cleanup_failure.set(stage);
            io::Error::other(format!("Wine cleanup failed: {stage:?}"))
        })?;
        let result = wait_for_natural_idle_command_with_stop(
            &mut child,
            || termination_started.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire),
            || {
                thread::sleep(PROCESS_POLL_INTERVAL);
            },
        );
        if result.is_err() {
            let _ = self
                .prior_cleanup_failure
                .set(child.cleanup_failure.unwrap_or(CleanupStage::ServerWait));
        }
        result
    }

    fn run_command(&self, argument: &str) -> Result<(), CleanupStage> {
        let mut child = self.spawn_command(argument)?;
        match wait_bounded(&mut child, &SystemPollClock, WINE_SERVER_COMMAND_TIMEOUT) {
            Ok(true) => Ok(()),
            Ok(false) => Err(CleanupStage::ServerExit),
            Err(error) => Err(error.cleanup.unwrap_or(CleanupStage::ServerWait)),
        }
    }

    fn spawn_command(&self, argument: &str) -> Result<AuxiliaryProcess, CleanupStage> {
        let mut command = Command::new(&self.lifecycle.executable);
        command
            .arg(argument)
            .current_dir(&self.working_directory)
            .env_clear()
            .envs(self.environment.iter().cloned())
            .env("WINEPREFIX", &self.lifecycle.prefix)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let prepared = platform::PreparedProcessTree::prepare(&mut command).map_err(|_| CleanupStage::ServerSpawn)?;
        let child = spawn_with_verified_retries(
            || self.verify_wineserver(),
            || command.spawn(),
            is_executable_file_busy,
            || thread::sleep(EXECUTABLE_BUSY_RETRY_DELAY),
        )?;
        attach_auxiliary(child, prepared).map_err(|error| error.cleanup.unwrap_or(CleanupStage::ServerSpawn))
    }

    fn release_lease(&self) {
        let mut state = lock_recover(&self.lease_state);
        if *state == LeaseState::Live {
            let _ = lock_recover(wine_prefix_leases()).remove(&self.lifecycle.prefix);
            *state = LeaseState::Released;
        }
    }

    fn poison_lease(&self) {
        let mut state = lock_recover(&self.lease_state);
        if *state == LeaseState::Live {
            *state = LeaseState::Poisoned;
        }
    }

    fn verify_wineserver(&self) -> Result<(), CleanupStage> {
        verify_pinned_executable(
            Path::new(&self.lifecycle.executable),
            &self.expected_wineserver_digest,
            "wineserver executable",
        )
        .map_err(|_| CleanupStage::RuntimeVerification)
    }
}

fn spawn_with_verified_retries<T>(
    mut verify: impl FnMut() -> Result<(), CleanupStage>,
    mut spawn: impl FnMut() -> io::Result<T>,
    is_retryable: impl Fn(&io::Error) -> bool,
    mut wait: impl FnMut(),
) -> Result<T, CleanupStage> {
    let mut attempts = 0;
    loop {
        verify()?;
        match spawn() {
            Ok(child) => return Ok(child),
            Err(error) if is_retryable(&error) && attempts < EXECUTABLE_BUSY_RETRY_LIMIT => {
                attempts += 1;
                wait();
            }
            Err(_) => return Err(CleanupStage::ServerSpawn),
        }
    }
}

#[cfg(unix)]
fn is_executable_file_busy(error: &io::Error) -> bool {
    // ETXTBSY is 26 on the Unix targets supported by this workspace. Using
    // raw_os_error keeps the Rust 1.78 MSRV; ErrorKind::ExecutableFileBusy was
    // not stabilized until Rust 1.83.
    error.raw_os_error() == Some(26)
}

#[cfg(not(unix))]
fn is_executable_file_busy(_error: &io::Error) -> bool {
    false
}

impl Drop for WineSession {
    fn drop(&mut self) {
        self.poison_lease();
    }
}

fn wine_prefix_leases() -> &'static Mutex<HashSet<String>> {
    static LEASES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    #[cfg(target_os = "macos")]
    use std::process::Stdio;
    use std::process::{Child, Command};
    #[cfg(target_os = "macos")]
    use std::thread;
    #[cfg(target_os = "macos")]
    use std::time::Duration;

    const SIGKILL: i32 = 9;
    const SIGTERM: i32 = 15;
    const ESRCH: i32 = 3;
    #[cfg(target_os = "macos")]
    const EPERM: i32 = 1;
    #[cfg(target_os = "macos")]
    const SIGNAL_RETRY_LIMIT: usize = 50;
    #[cfg(target_os = "macos")]
    const SIGNAL_RETRY_DELAY: Duration = Duration::from_millis(5);

    #[cfg(target_os = "macos")]
    const LSOF_PATH: &str = "/usr/sbin/lsof";

    extern "C" {
        fn kill(process_id: i32, signal: i32) -> i32;
        fn setpgid(process_id: i32, process_group_id: i32) -> i32;
    }

    #[cfg(target_os = "macos")]
    fn retry_permission_denied_signal(
        mut signal_once: impl FnMut() -> io::Result<()>,
        mut wait_before_retry: impl FnMut(),
    ) -> io::Result<()> {
        let mut retries = 0;
        loop {
            match signal_once() {
                Ok(()) => return Ok(()),
                Err(error) if error.raw_os_error() == Some(EPERM) && retries < SIGNAL_RETRY_LIMIT => {
                    retries += 1;
                    wait_before_retry();
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub struct PreparedProcessTree;

    impl PreparedProcessTree {
        pub fn prepare(command: &mut Command) -> io::Result<Self> {
            // SAFETY: `setpgid` is async-signal-safe and the closure captures no
            // heap-backed state, which is required between fork and exec.
            unsafe {
                command.pre_exec(|| {
                    // SAFETY: zero selects the calling child process and creates
                    // a group whose id equals that child's process id.
                    if setpgid(0, 0) == -1 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            Ok(Self)
        }

        pub fn attach(self, child: &Child) -> io::Result<ProcessTree> {
            let process_group_id = i32::try_from(child.id())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child pid does not fit in i32"))?;
            Ok(ProcessTree { process_group_id })
        }
    }

    pub struct ProcessTree {
        process_group_id: i32,
    }

    pub fn force_kill_unattached(child: &mut Child) -> io::Result<()> {
        let process_group_id = i32::try_from(child.id()).map_err(|_| io::Error::other("invalid process group"))?;
        // The child was spawned through PreparedProcessTree::prepare, which
        // creates this exact process group before exec, even if attach fails.
        std::mem::ManuallyDrop::new(ProcessTree { process_group_id }).force_kill()
    }

    #[cfg(target_os = "macos")]
    pub fn force_kill_wine_prefix_clients(prefix: &Path) -> io::Result<()> {
        let system32 = prefix.join("drive_c/windows/system32");
        let marker = system32.join("ntdll.dll");
        if !marker.exists() {
            return Ok(());
        }
        if !system32.is_dir() || system32.is_symlink() || !marker.is_file() || marker.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Wine prefix ntdll marker is unavailable",
            ));
        }
        let mut command = Command::new(LSOF_PATH);
        command
            .args(["-t", "--"])
            .arg(&marker)
            .arg(&system32)
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        let (status, captured) = super::capture_auxiliary(&mut command, super::WINE_SERVER_COMMAND_TIMEOUT, 64 * 1024)?;
        // lsof uses status 1 when no process has the file open. That is the
        // normal result after a clean Wine shutdown.
        if !status.success() && status.code() != Some(1) {
            return Err(io::Error::other(format!(
                "Wine prefix client discovery exited with {}",
                status
            )));
        }
        let current_process = i32::try_from(std::process::id())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "current pid does not fit in i32"))?;
        for line in String::from_utf8_lossy(&captured).lines() {
            let process_id = line
                .parse::<i32>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "lsof emitted an invalid pid"))?;
            if process_id <= 1 || process_id == current_process {
                continue;
            }
            // SAFETY: the positive PID was returned for an open mapping of the
            // exact, validated prefix marker. SIGKILL does not access Rust
            // memory, and ESRCH means the client exited between discovery and
            // delivery.
            if unsafe { kill(process_id, SIGKILL) } == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn force_kill_wine_prefix_clients(_prefix: &Path) -> io::Result<()> {
        Ok(())
    }

    impl ProcessTree {
        pub fn request_graceful(&self) -> io::Result<()> {
            self.send_signal(SIGTERM)
        }

        pub fn force_kill(&self) -> io::Result<()> {
            self.send_signal(SIGKILL)
        }

        fn send_signal(&self, signal: i32) -> io::Result<()> {
            #[cfg(target_os = "macos")]
            {
                retry_permission_denied_signal(|| self.send_signal_once(signal), || thread::sleep(SIGNAL_RETRY_DELAY))
            }
            #[cfg(not(target_os = "macos"))]
            self.send_signal_once(signal)
        }

        fn send_signal_once(&self, signal: i32) -> io::Result<()> {
            // SAFETY: the negative id targets the process group created for this
            // launch. No Rust memory is shared with the operating system call.
            if unsafe { kill(-self.process_group_id, signal) } != -1 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ESRCH) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }

    impl Drop for ProcessTree {
        fn drop(&mut self) {
            let _ = self.force_kill();
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    mod tests {
        use super::*;
        use std::cell::Cell;

        #[test]
        fn permission_denied_signal_retries_until_success() {
            let calls = Cell::new(0);
            let waits = Cell::new(0);

            retry_permission_denied_signal(
                || {
                    let next = calls.get() + 1;
                    calls.set(next);
                    if next < 3 {
                        Err(io::Error::from_raw_os_error(EPERM))
                    } else {
                        Ok(())
                    }
                },
                || waits.set(waits.get() + 1),
            )
            .unwrap();

            assert_eq!(calls.get(), 3);
            assert_eq!(waits.get(), 2);
        }

        #[test]
        fn permission_denied_signal_returns_error_after_retry_budget() {
            let calls = Cell::new(0);
            let waits = Cell::new(0);

            let error = retry_permission_denied_signal(
                || {
                    calls.set(calls.get() + 1);
                    Err(io::Error::from_raw_os_error(EPERM))
                },
                || waits.set(waits.get() + 1),
            )
            .unwrap_err();

            assert_eq!(error.raw_os_error(), Some(EPERM));
            assert_eq!(calls.get(), SIGNAL_RETRY_LIMIT + 1);
            assert_eq!(waits.get(), SIGNAL_RETRY_LIMIT);
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command};

    type Bool = i32;
    type Dword = u32;
    type Handle = *mut c_void;

    const CREATE_NEW_PROCESS_GROUP: Dword = 0x0000_0200;
    const CTRL_BREAK_EVENT: Dword = 1;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x0000_2000;

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: Dword,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: Dword,
        affinity: usize,
        priority_class: Dword,
        scheduling_class: Dword,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
        fn CloseHandle(object: Handle) -> Bool;
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn GenerateConsoleCtrlEvent(control_event: Dword, process_group_id: Dword) -> Bool;
        fn SetInformationJobObject(job: Handle, class: i32, information: *const c_void, length: Dword) -> Bool;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> Bool;
    }

    pub struct PreparedProcessTree {
        job: JobHandle,
    }

    impl PreparedProcessTree {
        pub fn prepare(command: &mut Command) -> io::Result<Self> {
            command.creation_flags(CREATE_NEW_PROCESS_GROUP);
            Ok(Self {
                job: JobHandle::create()?,
            })
        }

        pub fn attach(self, child: &Child) -> io::Result<ProcessTree> {
            let process = child.as_raw_handle().cast::<c_void>();
            // SAFETY: both handles are live kernel handles. Assignment does not
            // transfer ownership of either handle.
            if unsafe { AssignProcessToJobObject(self.job.raw(), process) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(ProcessTree {
                job: self.job,
                process_group_id: child.id(),
            })
        }
    }

    pub struct ProcessTree {
        job: JobHandle,
        process_group_id: u32,
    }

    pub fn force_kill_unattached(child: &mut Child) -> io::Result<()> {
        match child.try_wait()? {
            Some(_) => Ok(()),
            None => child.kill(),
        }
    }

    pub fn force_kill_wine_prefix_clients(_prefix: &Path) -> io::Result<()> {
        Ok(())
    }

    impl ProcessTree {
        pub fn request_graceful(&self) -> io::Result<()> {
            // CTRL_BREAK is best-effort: GUI processes and detached console
            // processes commonly cannot receive it, so timeout escalation to
            // the Job Object remains the reliable termination mechanism.
            // SAFETY: the group id belongs to the child created with
            // CREATE_NEW_PROCESS_GROUP.
            let _ = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, self.process_group_id) };
            Ok(())
        }

        pub fn force_kill(&self) -> io::Result<()> {
            // SAFETY: the Job Object handle remains owned by `self`.
            if unsafe { TerminateJobObject(self.job.raw(), 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    struct JobHandle(usize);

    impl JobHandle {
        fn create() -> io::Result<Self> {
            // SAFETY: null security attributes and name request an unnamed Job
            // Object with default security.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self(handle as usize);
            let mut limits = JobObjectExtendedLimitInformation::default();
            limits.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let length = u32::try_from(std::mem::size_of_val(&limits))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Job Object limits are too large"))?;
            // SAFETY: `limits` has the layout required by the selected Job
            // Object information class and is valid for `length` bytes.
            if unsafe {
                SetInformationJobObject(
                    job.raw(),
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    std::ptr::addr_of!(limits).cast::<c_void>(),
                    length,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        fn raw(&self) -> Handle {
            self.0 as Handle
        }
    }

    impl Drop for JobHandle {
        fn drop(&mut self) {
            // SAFETY: `self` uniquely owns this Job Object handle.
            let _ = unsafe { CloseHandle(self.raw()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::{
        BottleExecutableBinding, CpuArchitecture, GraphicsBackendKind, GraphicsSelection, GuestArtifactBinding,
        NativeCommand, NetworkPolicy, ProcessLifecycle, RuntimeKind, RuntimeSelection, SandboxPolicy, SandboxProfile,
        TranslatorKind, TranslatorSelection,
    };
    use std::collections::BTreeMap;

    fn fixture_plan() -> LaunchPlan {
        LaunchPlan {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: "process-test".into(),
            runtime: RuntimeSelection {
                provider: RuntimeKind::Wine,
                pack_id: "test-runtime".into(),
                pack_digest: format!("sha256:{}", "0".repeat(64)),
            },
            translator: TranslatorSelection {
                provider: TranslatorKind::Native,
                version: None,
            },
            graphics: GraphicsSelection {
                backend: GraphicsBackendKind::WineD3d,
                version: None,
                options: BTreeMap::new(),
            },
            process: NativeCommand {
                executable: std::env::current_exe().unwrap().to_string_lossy().into_owned(),
                arguments: vec!["--list".into()],
                environment: BTreeMap::new(),
                working_directory: std::env::current_dir().unwrap().to_string_lossy().into_owned(),
            },
            guest_artifact: None,
            bottle_executable: None,
            mounts: Vec::new(),
            sandbox: SandboxPolicy {
                profile: SandboxProfile::Desktop,
                network: NetworkPolicy::Deny,
                allow_devices: Vec::new(),
            },
            lifecycle: ProcessLifecycle::default(),
            decision_trace: Vec::new(),
        }
    }

    struct RuntimeEvidenceFixture {
        root: PathBuf,
        plan: LaunchPlan,
        wine_log: PathBuf,
        guest_log: PathBuf,
        wineserver_log: PathBuf,
    }

    impl RuntimeEvidenceFixture {
        fn new() -> Self {
            use std::sync::atomic::AtomicU64;

            static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
            let temporary = std::env::temp_dir();
            #[cfg(unix)]
            let temporary = temporary.canonicalize().unwrap();
            let root = temporary.join(format!(
                "compatforge-runtime-evidence-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&root).unwrap();
            let prefix = root.join("prefix");
            std::fs::create_dir(&prefix).unwrap();
            std::fs::create_dir(root.join("alternate-prefix")).unwrap();
            #[cfg(windows)]
            let (wine_name, guest_name, server_name) = ("wine.cmd", "guest.cmd", "wineserver.cmd");
            #[cfg(not(windows))]
            let (wine_name, guest_name, server_name) = ("wine", "guest", "wineserver");
            let wine = root.join(wine_name);
            let guest = root.join(guest_name);
            let wineserver = root.join(server_name);
            #[cfg(windows)]
            let sources = [
                "@echo off\r\necho %*>>\"%COMPATFORGE_TEST_WINE_LOG%\"\r\nif \"%~1\"==\"wineboot\" (\r\nmkdir \"%WINEPREFIX%\\drive_c\\windows\\system32\"\r\necho marker>\"%WINEPREFIX%\\drive_c\\windows\\system32\\ntdll.dll\"\r\nexit /b 0\r\n)\r\ncall \"%~1\"\r\nexit /b %errorlevel%\r\n",
                "@echo off\r\necho guest>\"%COMPATFORGE_TEST_GUEST_LOG%\"\r\nexit /b 0\r\n",
                "@echo off\r\necho %*>>\"%COMPATFORGE_TEST_WINESERVER_LOG%\"\r\nexit /b 0\r\n",
            ];
            #[cfg(not(windows))]
            let sources = [
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMPATFORGE_TEST_WINE_LOG\"\nif [ \"$1\" = wineboot ]; then\n/bin/mkdir -p \"$WINEPREFIX/drive_c/windows/system32\" || exit 1\nprintf marker > \"$WINEPREFIX/drive_c/windows/system32/ntdll.dll\"\nelse\nexec \"$1\"\nfi\n",
                "#!/bin/sh\nprintf guest > \"$COMPATFORGE_TEST_GUEST_LOG\"\n",
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMPATFORGE_TEST_WINESERVER_LOG\"\n",
            ];
            for (path, source) in [&wine, &guest, &wineserver].into_iter().zip(sources) {
                std::fs::write(path, source).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            std::fs::copy(
                &wineserver,
                root.join(server_name)
                    .with_file_name(format!("alternate-{server_name}")),
            )
            .unwrap();
            let wine_digest = sha256_file(&wine).unwrap();
            let wineserver_digest = sha256_file(&wineserver).unwrap();
            assert_ne!(wine_digest, wineserver_digest);
            let wine_log = root.join("wine.log");
            let guest_log = root.join("guest.log");
            let wineserver_log = root.join("wineserver.log");
            let mut plan = fixture_plan();
            plan.runtime.pack_digest = format!("sha256:{}", "a".repeat(64));
            plan.process.executable = wine.to_str().unwrap().into();
            plan.process.arguments = vec![guest.to_str().unwrap().into()];
            // Invalid evidence must not even materialize this working directory.
            plan.process.working_directory = root.join("launch-working").to_str().unwrap().into();
            plan.process.environment = BTreeMap::from([
                ("COMPATFORGE_RUNTIME_PACK".into(), plan.runtime.pack_id.clone()),
                (
                    "COMPATFORGE_RUNTIME_PACK_DIGEST".into(),
                    plan.runtime.pack_digest.clone(),
                ),
                (RUNTIME_EXECUTABLE_DIGEST_ENV.into(), wine_digest),
                (WINESERVER_EXECUTABLE_DIGEST_ENV.into(), wineserver_digest),
                ("WINESERVER".into(), wineserver.to_str().unwrap().into()),
                ("WINEPREFIX".into(), prefix.to_str().unwrap().into()),
                ("COMPATFORGE_TEST_WINE_LOG".into(), wine_log.to_str().unwrap().into()),
                ("COMPATFORGE_TEST_GUEST_LOG".into(), guest_log.to_str().unwrap().into()),
                (
                    "COMPATFORGE_TEST_WINESERVER_LOG".into(),
                    wineserver_log.to_str().unwrap().into(),
                ),
            ]);
            plan.lifecycle.wineserver = Some(WineServerLifecycle {
                executable: wineserver.to_str().unwrap().into(),
                prefix: prefix.to_str().unwrap().into(),
            });
            plan.lifecycle.termination_grace_milliseconds = 100;
            plan.lifecycle.maximum_runtime_milliseconds = Some(5_000);
            plan.validate().unwrap();
            assert!(!prefix.join("drive_c/windows/system32/ntdll.dll").exists());
            Self {
                root,
                plan,
                wine_log,
                guest_log,
                wineserver_log,
            }
        }

        fn valid_plan(&self) -> LaunchPlan {
            self.plan.clone()
        }

        fn alternate_wineserver(&self) -> PathBuf {
            let server = Path::new(&self.plan.lifecycle.wineserver.as_ref().unwrap().executable);
            self.root
                .join(format!("alternate-{}", server.file_name().unwrap().to_str().unwrap()))
        }

        fn alternate_prefix(&self) -> PathBuf {
            self.root.join("alternate-prefix")
        }

        fn alternate_pack_digest(&self) -> String {
            format!("sha256:{}", "b".repeat(64))
        }

        fn assert_no_command_logs(&self) {
            for path in [&self.wine_log, &self.guest_log, &self.wineserver_log] {
                assert!(!path.exists(), "unexpected command log: {}", path.display());
            }
        }

        fn assert_valid_launch_runs_commands(&self, plan: &LaunchPlan) {
            self.assert_no_command_logs();
            let handle = ProcessSupervisor::start(plan).unwrap();
            let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
            let cleanup = handle.terminate_and_wait(Duration::from_secs(1));
            cleanup.unwrap();
            assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
            assert!(events.last().unwrap().exit.as_ref().unwrap().success);
            assert!(std::fs::read_to_string(&self.wine_log).unwrap().contains("wineboot -u"));
            assert!(std::fs::read_to_string(&self.guest_log).unwrap().contains("guest"));
            assert!(std::fs::read_to_string(&self.wineserver_log).unwrap().contains("-w"));
        }
    }

    impl Drop for RuntimeEvidenceFixture {
        fn drop(&mut self) {
            let removed = std::fs::remove_dir_all(&self.root);
            if !std::thread::panicking() {
                removed.unwrap();
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StartupFault {
        Wineboot,
        Fonts,
        Alias,
        GuestMutation,
        WineMutation,
        ServerMutation,
        Spawn,
        Attach,
        Reap,
    }

    struct FaultingStartup {
        fault: StartupFault,
        guest_spawns: std::cell::Cell<usize>,
    }

    impl StartupOperations for FaultingStartup {
        fn wineboot(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
            initialize_wine_prefix(plan)?;
            if self.fault == StartupFault::Wineboot {
                return Err(ProcessError::Spawn(io::Error::other("injected wineboot exit")));
            }
            if self.fault == StartupFault::Reap {
                let clock = VirtualClock {
                    start: Instant::now(),
                    ticks: std::cell::Cell::new(0),
                };
                let mut child = StuckAuxiliary {
                    signalled: 0,
                    reaps: false,
                    signal_fails: false,
                };
                return Err(wait_bounded(&mut child, &clock, Duration::ZERO)
                    .unwrap_err()
                    .into_process_error(StartupStage::Wineboot));
            }
            let mutation = match self.fault {
                StartupFault::GuestMutation => Some(plan.process.arguments[0].as_str()),
                StartupFault::WineMutation => Some(plan.process.executable.as_str()),
                StartupFault::ServerMutation => Some(plan.lifecycle.wineserver.as_ref().unwrap().executable.as_str()),
                _ => None,
            };
            if let Some(path) = mutation {
                let mut contents = std::fs::read(path).unwrap();
                contents.extend_from_slice(b"\n");
                std::fs::write(path, contents).unwrap();
            }
            Ok(())
        }

        fn fonts(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
            if self.fault == StartupFault::Fonts {
                return Err(ProcessError::InvalidRuntimeEvidence("injected fonts"));
            }
            prepare_pinned_bottle_font(plan)
        }

        fn guest_alias(&self, plan: &LaunchPlan) -> Result<Option<PathBuf>, ProcessError> {
            if self.fault == StartupFault::Alias {
                return Err(ProcessError::InvalidRuntimeEvidence("injected alias"));
            }
            prepare_guest_execution_alias(plan)
        }

        fn spawn(&self, command: &mut Command) -> io::Result<Child> {
            self.guest_spawns.set(self.guest_spawns.get() + 1);
            // Mutation tests stop here on the old implementation: do not run
            // altered fixture executables even while proving the missing check.
            if self.fault != StartupFault::Attach {
                return Err(io::Error::other("injected main spawn"));
            }
            command.spawn()
        }

        fn attach(
            &self,
            _prepared: platform::PreparedProcessTree,
            _child: &Child,
        ) -> io::Result<platform::ProcessTree> {
            Err(io::Error::other("injected attach"))
        }
    }

    fn startup_bound_fixture() -> RuntimeEvidenceFixture {
        let mut fixture = RuntimeEvidenceFixture::new();
        let guest = Path::new(&fixture.plan.process.arguments[0]);
        fixture.plan.guest_artifact = Some(GuestArtifactBinding {
            digest: sha256_file(guest).unwrap(),
            size_bytes: std::fs::metadata(guest).unwrap().len(),
            stored_path: guest.to_str().unwrap().into(),
            original_name: "guest.exe".into(),
            architecture: CpuArchitecture::X86_64,
            image_kind: "executable".into(),
            subsystem: "windowsConsole".into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        });
        fixture.plan.validate().unwrap();
        fixture
    }

    fn configure_server_exit(fixture: &mut RuntimeEvidenceFixture, fail_argument: &str) {
        let server = &fixture.plan.lifecycle.wineserver.as_ref().unwrap().executable;
        #[cfg(windows)]
        let contents = format!("@echo off\r\necho %*>>\"%COMPATFORGE_TEST_WINESERVER_LOG%\"\r\nif \"%~1\"==\"{fail_argument}\" exit /b 1\r\nexit /b 0\r\n");
        #[cfg(not(windows))]
        let contents = format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMPATFORGE_TEST_WINESERVER_LOG\"\n[ \"$1\" != \"{fail_argument}\" ]\n");
        std::fs::write(server, contents).unwrap();
        fixture.plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(Path::new(server)).unwrap(),
        );
    }

    #[test]
    fn startup_transaction_failure_matrix_stops_exact_server_and_releases_only_on_success() {
        for fault in [
            StartupFault::Wineboot,
            StartupFault::Fonts,
            StartupFault::Alias,
            StartupFault::GuestMutation,
            StartupFault::WineMutation,
            StartupFault::ServerMutation,
            StartupFault::Spawn,
            StartupFault::Attach,
            StartupFault::Reap,
        ] {
            for fail_argument in ["none", "-k", "-w"] {
                let mut fixture = startup_bound_fixture();
                configure_server_exit(&mut fixture, fail_argument);
                let operations = FaultingStartup {
                    fault,
                    guest_spawns: std::cell::Cell::new(0),
                };
                let error = ProcessSupervisor::start_with_operations(&fixture.plan, &operations)
                    .err()
                    .expect("startup must fail");
                let poisoned =
                    matches!(fault, StartupFault::ServerMutation | StartupFault::Reap) || fail_argument == "-w";
                if matches!(
                    fault,
                    StartupFault::GuestMutation | StartupFault::WineMutation | StartupFault::ServerMutation
                ) {
                    assert_eq!(
                        operations.guest_spawns.get(),
                        0,
                        "{fault:?}: Guest spawn crossed a mutation boundary"
                    );
                    assert!(!fixture.guest_log.exists());
                }
                if fault == StartupFault::ServerMutation {
                    assert!(!fixture.wineserver_log.exists(), "substituted server was executed");
                } else {
                    let commands = std::fs::read_to_string(&fixture.wineserver_log).unwrap_or_default();
                    assert_eq!(
                        commands.lines().collect::<Vec<_>>(),
                        ["-k", "-w"],
                        "{fault:?}: missing synchronous cleanup, {error}"
                    );
                }
                let reacquired = WineSession::acquire(&fixture.plan);
                assert_eq!(reacquired.is_err(), poisoned, "{fault:?}: wrong lease terminal state");
                assert!(
                    error.to_string().starts_with(if poisoned {
                        "Wine startup cleanup failed:"
                    } else {
                        "Wine startup failed:"
                    }),
                    "unexpected error: {error}"
                );
            }
        }
    }

    #[test]
    fn startup_transaction_canonical_prefix_lease_and_abandoned_session_are_quarantined() {
        let fixture = RuntimeEvidenceFixture::new();
        let first = WineSession::acquire(&fixture.plan).unwrap().unwrap();
        let mut alias = fixture.valid_plan();
        let prefix = Path::new(&alias.lifecycle.wineserver.as_ref().unwrap().prefix).join(".");
        alias.lifecycle.wineserver.as_mut().unwrap().prefix = prefix.to_str().unwrap().into();
        alias
            .process
            .environment
            .insert("WINEPREFIX".into(), prefix.to_str().unwrap().into());
        assert!(matches!(
            WineSession::acquire(&alias),
            Err(ProcessError::WinePrefixBusy(_))
        ));
        drop(first);
        assert!(matches!(
            WineSession::acquire(&fixture.plan),
            Err(ProcessError::WinePrefixBusy(_))
        ));
        assert!(
            !fixture.wineserver_log.exists(),
            "Drop must not execute cleanup commands"
        );
    }

    #[test]
    fn startup_transaction_wine_session_cleanup_failure_is_memoized() {
        let mut fixture = RuntimeEvidenceFixture::new();
        configure_server_exit(&mut fixture, "-w");
        materialize_launch_directories(&fixture.plan).unwrap();
        let session = WineSession::acquire(&fixture.plan).unwrap().unwrap();
        let (sender, _receiver) = mpsc::channel();
        let emitter = EventEmitter::new("startup-cleanup".into(), sender);
        assert!(session.stop(&emitter).is_err());
        assert!(
            session.stop(&emitter).is_err(),
            "repeated stop must preserve the first failure"
        );
        assert!(WineSession::acquire(&fixture.plan).is_err());
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-k", "-w"]
        );
    }

    #[test]
    fn startup_transaction_wine_session_concurrent_stop_preserves_failure_for_every_caller() {
        let mut fixture = RuntimeEvidenceFixture::new();
        configure_server_exit(&mut fixture, "-w");
        materialize_launch_directories(&fixture.plan).unwrap();
        let session = WineSession::acquire(&fixture.plan).unwrap().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let workers = (0..4)
            .map(|_| {
                let session = Arc::clone(&session);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    session.stop_core(None)
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), StopOutcome::Failed(CleanupStage::ServerExit));
        }
        assert!(WineSession::acquire(&fixture.plan).is_err());
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-k", "-w"]
        );
    }

    #[test]
    fn startup_transaction_natural_idle_failure_cannot_be_erased_by_later_cleanup_success() {
        let mut fixture = RuntimeEvidenceFixture::new();
        fixture.plan.process.environment.insert(
            "COMPATFORGE_TEST_IDLE_SENTINEL".into(),
            fixture.root.join("idle.failed").to_str().unwrap().into(),
        );
        #[cfg(windows)]
        let source = "@echo off\r\necho %*>>\"%COMPATFORGE_TEST_WINESERVER_LOG%\"\r\nif \"%~1\"==\"-w\" if not exist \"%COMPATFORGE_TEST_IDLE_SENTINEL%\" (\r\necho failed>\"%COMPATFORGE_TEST_IDLE_SENTINEL%\"\r\nexit /b 1\r\n)\r\nexit /b 0\r\n";
        #[cfg(not(windows))]
        let source = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMPATFORGE_TEST_WINESERVER_LOG\"\nif [ \"$1\" = -w ] && [ ! -f \"$COMPATFORGE_TEST_IDLE_SENTINEL\" ]; then\nprintf failed > \"$COMPATFORGE_TEST_IDLE_SENTINEL\"\nexit 1\nfi\nexit 0\n";
        let executable = &fixture.plan.lifecycle.wineserver.as_ref().unwrap().executable;
        std::fs::write(executable, source).unwrap();
        fixture.plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(Path::new(executable)).unwrap(),
        );
        materialize_launch_directories(&fixture.plan).unwrap();
        let session = WineSession::acquire(&fixture.plan).unwrap().unwrap();
        assert!(session.wait_until_idle(&AtomicBool::new(false)).is_err());
        assert!(matches!(session.stop_core(None), StopOutcome::Failed(_)));
        assert!(WineSession::acquire(&fixture.plan).is_err());
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-w", "-k", "-w"]
        );
    }

    #[test]
    fn startup_transaction_real_wineboot_nonzero_stops_server_before_returning() {
        let mut fixture = RuntimeEvidenceFixture::new();
        #[cfg(windows)]
        let contents = "@echo off\r\necho %*>>\"%COMPATFORGE_TEST_WINE_LOG%\"\r\nexit /b 23\r\n";
        #[cfg(not(windows))]
        let contents = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMPATFORGE_TEST_WINE_LOG\"\nexit 23\n";
        std::fs::write(&fixture.plan.process.executable, contents).unwrap();
        fixture.plan.process.environment.insert(
            RUNTIME_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(Path::new(&fixture.plan.process.executable)).unwrap(),
        );
        assert!(matches!(
            ProcessSupervisor::start(&fixture.plan),
            Err(ProcessError::Startup(StartupStage::Wineboot))
        ));
        assert_eq!(
            std::fs::read_to_string(&fixture.wine_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["wineboot -u"]
        );
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-k", "-w"]
        );
        assert!(!fixture.guest_log.exists());
        assert!(WineSession::acquire(&fixture.plan).is_ok());
    }

    #[test]
    fn startup_transaction_guest_mutation_after_wineboot_stops_before_font_commands() {
        struct MutateGuestBeforeFonts(std::cell::Cell<bool>);
        impl StartupOperations for MutateGuestBeforeFonts {
            fn wineboot(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
                initialize_wine_prefix(plan)?;
                std::fs::write(&plan.process.arguments[0], b"changed guest").unwrap();
                Ok(())
            }
            fn fonts(&self, _plan: &LaunchPlan) -> Result<(), ProcessError> {
                self.0.set(true);
                Ok(())
            }
        }
        let fixture = startup_bound_fixture();
        let operations = MutateGuestBeforeFonts(std::cell::Cell::new(false));
        assert!(ProcessSupervisor::start_with_operations(&fixture.plan, &operations).is_err());
        assert!(
            !operations.0.get(),
            "Guest mutation was not checked before font preparation"
        );
        assert!(!fixture.guest_log.exists());
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-k", "-w"]
        );
    }

    #[test]
    fn startup_transaction_replaced_guest_alias_is_rechecked_at_main_spawn_boundary() {
        struct ReplaceAlias(std::cell::Cell<bool>);
        impl StartupOperations for ReplaceAlias {
            fn guest_alias(&self, plan: &LaunchPlan) -> Result<Option<PathBuf>, ProcessError> {
                let alias = prepare_guest_execution_alias(plan)?.unwrap();
                std::fs::remove_file(&alias).unwrap();
                std::fs::write(&alias, b"substituted alias").unwrap();
                Ok(Some(alias))
            }
            fn spawn(&self, _command: &mut Command) -> io::Result<Child> {
                self.0.set(true);
                Err(io::Error::other("unexpected main spawn"))
            }
        }
        let mut fixture = startup_bound_fixture();
        let object = fixture.root.join("extensionless-object");
        std::fs::copy(&fixture.plan.process.arguments[0], &object).unwrap();
        fixture.plan.process.arguments[0] = object.to_str().unwrap().into();
        fixture.plan.guest_artifact.as_mut().unwrap().stored_path = object.to_str().unwrap().into();
        let operations = ReplaceAlias(std::cell::Cell::new(false));
        assert!(ProcessSupervisor::start_with_operations(&fixture.plan, &operations).is_err());
        verify_guest_inputs(&fixture.plan).unwrap();
        assert!(!operations.0.get(), "replaced alias crossed the main spawn boundary");
        assert!(!fixture.guest_log.exists());
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-k", "-w"]
        );
    }

    #[test]
    fn startup_transaction_armed_guard_drop_quarantines_without_external_commands() {
        let fixture = RuntimeEvidenceFixture::new();
        let session = WineSession::acquire(&fixture.plan).unwrap().unwrap();
        let guard = StartupWineSessionGuard::new(Arc::clone(&session));
        drop(guard);
        assert_eq!(*lock_recover(&session.lease_state), LeaseState::Poisoned);
        assert!(WineSession::acquire(&fixture.plan).is_err());
        assert!(!fixture.wineserver_log.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_transaction_linux_wineboot_timeout_kills_descendant_holding_pipe() {
        struct ShortWineboot;
        impl StartupOperations for ShortWineboot {
            fn wineboot(&self, plan: &LaunchPlan) -> Result<(), ProcessError> {
                initialize_wine_prefix_with_spawn(plan, Duration::from_millis(300), |command| {
                    command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
                })
            }
        }
        let mut fixture = RuntimeEvidenceFixture::new();
        let pid_file = fixture.root.join("descendant.pid");
        let source = "#!/bin/sh\n/bin/sleep 60 &\nprintf '%s' \"$!\" > \"$COMPATFORGE_TEST_DESCENDANT_PID\"\nwait\n";
        std::fs::write(&fixture.plan.process.executable, source).unwrap();
        fixture.plan.process.environment.insert(
            "COMPATFORGE_TEST_DESCENDANT_PID".into(),
            pid_file.to_str().unwrap().into(),
        );
        fixture.plan.process.environment.insert(
            RUNTIME_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(Path::new(&fixture.plan.process.executable)).unwrap(),
        );
        let started = Instant::now();
        assert!(matches!(
            ProcessSupervisor::start_with_operations(&fixture.plan, &ShortWineboot),
            Err(ProcessError::Startup(StartupStage::Wineboot))
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = std::fs::read_to_string(pid_file).unwrap().parse::<u32>().unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err() || stat.unwrap().contains(") Z "),
            "descendant remained runnable after tree termination"
        );
        assert!(!fixture.guest_log.exists());
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-k", "-w"]
        );
        assert!(WineSession::acquire(&fixture.plan).is_ok());
    }

    struct VirtualClock {
        start: Instant,
        ticks: std::cell::Cell<u64>,
    }

    impl PollClock for VirtualClock {
        fn now(&self) -> Instant {
            self.start + Duration::from_secs(self.ticks.get())
        }
        fn wait(&self) {
            self.ticks.set(self.ticks.get() + 1);
        }
    }

    struct StuckAuxiliary {
        signalled: usize,
        reaps: bool,
        signal_fails: bool,
    }

    impl BoundedChild for StuckAuxiliary {
        fn poll(&mut self) -> io::Result<Option<bool>> {
            Ok((self.signalled > 0 && self.reaps).then_some(false))
        }
        fn force_kill_tree(&mut self) -> io::Result<()> {
            self.signalled += 1;
            if self.signal_fails {
                Err(io::Error::other("injected signal"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn startup_transaction_wineboot_timeout_uses_bounded_tree_signal_and_reap() {
        for (reaps, signal_fails, expected) in [
            (true, false, None),
            (true, true, Some(CleanupStage::TreeTermination)),
            (false, false, Some(CleanupStage::RootReap)),
        ] {
            let clock = VirtualClock {
                start: Instant::now(),
                ticks: std::cell::Cell::new(0),
            };
            let mut child = StuckAuxiliary {
                signalled: 0,
                reaps,
                signal_fails,
            };
            let error = wait_bounded(&mut child, &clock, Duration::from_secs(2)).unwrap_err();
            assert_eq!(child.signalled, 1);
            assert_eq!(error.cleanup, expected);
            assert!(
                clock.ticks.get() <= 7,
                "timeout plus root-reap deadline must bound all paths"
            );
        }
    }

    #[test]
    fn startup_transaction_auxiliary_capture_rejects_overflow_before_allocating_past_limit() {
        let mut input = io::Cursor::new(vec![b'x'; 65_537]);
        let mut output = Vec::new();
        let result = loop {
            match read_auxiliary_chunk(&mut input, &mut output, 65_536) {
                Ok(false) => continue,
                value => break value,
            }
        };
        assert!(result.is_err(), "overlong auxiliary output was accepted");
        assert!(output.len() <= 65_536);
    }

    #[test]
    fn startup_transaction_cleanup_busy_retry_reverifies_before_every_attempt() {
        let verified = std::cell::Cell::new(0);
        let spawned = std::cell::Cell::new(0);
        let result: Result<(), CleanupStage> = spawn_with_verified_retries(
            || {
                verified.set(verified.get() + 1);
                if verified.get() == 2 {
                    Err(CleanupStage::RuntimeVerification)
                } else {
                    Ok(())
                }
            },
            || {
                spawned.set(spawned.get() + 1);
                Err(io::Error::from_raw_os_error(26))
            },
            |error| error.raw_os_error() == Some(26),
            || {},
        );
        assert_eq!(result, Err(CleanupStage::RuntimeVerification));
        assert_eq!(verified.get(), 2);
        assert_eq!(spawned.get(), 1, "changed executable reached the retry spawn");
    }

    #[test]
    fn startup_transaction_cleanup_mutation_between_k_and_w_never_executes_replacement() {
        let mut fixture = RuntimeEvidenceFixture::new();
        #[cfg(windows)]
        let source = "@echo off\r\necho %*>>\"%COMPATFORGE_TEST_WINESERVER_LOG%\"\r\nif \"%~1\"==\"-k\" echo.>>\"%WINESERVER%\"\r\nexit /b 0\r\n";
        #[cfg(not(windows))]
        let source = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMPATFORGE_TEST_WINESERVER_LOG\"\nif [ \"$1\" = -k ]; then printf '\\n' >> \"$WINESERVER\"; fi\nexit 0\n";
        let executable = &fixture.plan.lifecycle.wineserver.as_ref().unwrap().executable;
        std::fs::write(executable, source).unwrap();
        fixture.plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(Path::new(executable)).unwrap(),
        );
        let operations = FaultingStartup {
            fault: StartupFault::Alias,
            guest_spawns: std::cell::Cell::new(0),
        };
        assert!(matches!(
            ProcessSupervisor::start_with_operations(&fixture.plan, &operations),
            Err(ProcessError::StartupCleanup {
                startup: StartupStage::GuestAlias,
                cleanup: CleanupStage::RuntimeVerification
            })
        ));
        assert_eq!(
            std::fs::read_to_string(&fixture.wineserver_log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["-k"]
        );
        assert!(WineSession::acquire(&fixture.plan).is_err());
        assert!(!fixture.guest_log.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_transaction_linux_auxiliary_capture_bounds_a_descendant_held_pipe_after_root_exit() {
        let fixture = RuntimeEvidenceFixture::new();
        let pid_file = fixture.root.join("capture-descendant.pid");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "/bin/sleep 60 & printf '%s' \"$!\" > \"$PID_FILE\"; exit 0"])
            .env_clear()
            .env("PID_FILE", &pid_file);
        let started = Instant::now();
        assert!(capture_auxiliary(&mut command, Duration::from_millis(300), 65_536).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = std::fs::read_to_string(pid_file).unwrap().parse::<u32>().unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err() || stat.unwrap().contains(") Z "),
            "pipe-holding descendant remained runnable"
        );
    }

    fn assert_runtime_evidence_rejected(fixture: &RuntimeEvidenceFixture, mutate: impl FnOnce(&mut LaunchPlan)) {
        let mut plan = fixture.valid_plan();
        mutate(&mut plan);
        match ProcessSupervisor::start(&plan) {
            Err(ProcessError::InvalidRuntimeEvidence(_)) => {}
            Err(error) => panic!("expected InvalidRuntimeEvidence, got {error:?}"),
            Ok(handle) => {
                // During RED the old validator can actually start the guest.
                // Reap every worker before failing or removing fixture files.
                let cleanup = handle.terminate_and_wait(Duration::from_secs(1));
                panic!("expected InvalidRuntimeEvidence, got a launch handle; cleanup: {cleanup:?}");
            }
        }
        fixture.assert_no_command_logs();
        assert!(!Path::new(&plan.process.working_directory).exists());
    }

    #[test]
    fn runtime_evidence_valid_fixture_runs_wineboot_guest_and_wineserver() {
        let fixture = RuntimeEvidenceFixture::new();
        fixture.assert_valid_launch_runs_commands(&fixture.valid_plan());
    }

    #[test]
    fn runtime_evidence_mismatched_wineserver_environment_is_rejected_before_spawn() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process.environment.insert(
                "WINESERVER".into(),
                fixture.alternate_wineserver().to_str().unwrap().into(),
            );
        });
    }

    #[test]
    fn runtime_evidence_mismatched_pack_environment_is_rejected_before_spawn() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process
                .environment
                .insert("COMPATFORGE_RUNTIME_PACK".into(), "different-pack".into());
        });
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process.environment.insert(
                "COMPATFORGE_RUNTIME_PACK_DIGEST".into(),
                fixture.alternate_pack_digest(),
            );
        });
    }

    #[test]
    fn runtime_evidence_mismatched_pack_digest_is_rejected_before_spawn() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process.environment.insert(
                "COMPATFORGE_RUNTIME_PACK_DIGEST".into(),
                fixture.alternate_pack_digest(),
            );
        });
    }

    #[test]
    fn runtime_evidence_missing_or_unpaired_digests_are_rejected_before_spawn() {
        for missing in [
            RUNTIME_EXECUTABLE_DIGEST_ENV,
            WINESERVER_EXECUTABLE_DIGEST_ENV,
            "COMPATFORGE_RUNTIME_PACK_DIGEST",
        ] {
            let fixture = RuntimeEvidenceFixture::new();
            assert_runtime_evidence_rejected(&fixture, |plan| {
                plan.process.environment.remove(missing);
            });
        }
    }

    #[test]
    fn runtime_evidence_swapped_digests_are_rejected_before_spawn() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            let runtime = plan.process.environment.remove(RUNTIME_EXECUTABLE_DIGEST_ENV).unwrap();
            let wineserver = plan
                .process
                .environment
                .remove(WINESERVER_EXECUTABLE_DIGEST_ENV)
                .unwrap();
            plan.process
                .environment
                .insert(RUNTIME_EXECUTABLE_DIGEST_ENV.into(), wineserver);
            plan.process
                .environment
                .insert(WINESERVER_EXECUTABLE_DIGEST_ENV.into(), runtime);
        });
    }

    #[test]
    fn runtime_evidence_wine_lifecycle_without_complete_evidence_is_rejected_before_spawn() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process.environment.remove(RUNTIME_EXECUTABLE_DIGEST_ENV);
            plan.process.environment.remove(WINESERVER_EXECUTABLE_DIGEST_ENV);
        });
    }

    #[test]
    fn runtime_evidence_wineprefix_must_equal_lifecycle_prefix() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process
                .environment
                .insert("WINEPREFIX".into(), fixture.alternate_prefix().to_str().unwrap().into());
        });
    }

    #[test]
    fn runtime_evidence_each_marker_even_empty_activates_managed_validation() {
        for marker in [
            "COMPATFORGE_RUNTIME_PACK_DIGEST",
            RUNTIME_EXECUTABLE_DIGEST_ENV,
            WINESERVER_EXECUTABLE_DIGEST_ENV,
            "WINESERVER",
        ] {
            let fixture = RuntimeEvidenceFixture::new();
            assert_runtime_evidence_rejected(&fixture, |plan| {
                plan.lifecycle.wineserver = None;
                for key in [
                    "COMPATFORGE_RUNTIME_PACK_DIGEST",
                    RUNTIME_EXECUTABLE_DIGEST_ENV,
                    WINESERVER_EXECUTABLE_DIGEST_ENV,
                    "WINESERVER",
                ] {
                    plan.process.environment.remove(key);
                }
                plan.process.environment.insert(marker.into(), String::new());
            });
        }
    }

    #[test]
    fn runtime_evidence_lifecycle_alone_activates_managed_validation() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            for key in [
                "COMPATFORGE_RUNTIME_PACK_DIGEST",
                RUNTIME_EXECUTABLE_DIGEST_ENV,
                WINESERVER_EXECUTABLE_DIGEST_ENV,
                "WINESERVER",
            ] {
                plan.process.environment.remove(key);
            }
        });
    }

    #[test]
    fn runtime_evidence_missing_identity_fields_are_rejected_before_spawn() {
        for missing in ["WINESERVER", "WINEPREFIX", "COMPATFORGE_RUNTIME_PACK"] {
            let fixture = RuntimeEvidenceFixture::new();
            assert_runtime_evidence_rejected(&fixture, |plan| {
                plan.process.environment.remove(missing);
            });
        }
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.lifecycle.wineserver = None;
        });
    }

    #[test]
    fn runtime_evidence_requires_wine_provider() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.runtime.provider = RuntimeKind::Remote;
        });
    }

    #[test]
    fn runtime_evidence_rejects_malformed_executable_digests() {
        for field in [RUNTIME_EXECUTABLE_DIGEST_ENV, WINESERVER_EXECUTABLE_DIGEST_ENV] {
            for malformed in [
                String::new(),
                "sha256:abc".into(),
                format!("sha256:{}", "g".repeat(64)),
                format!("SHA256:{}", "a".repeat(64)),
            ] {
                let fixture = RuntimeEvidenceFixture::new();
                assert_runtime_evidence_rejected(&fixture, |plan| {
                    plan.process.environment.insert(field.into(), malformed);
                });
            }
        }
    }

    #[test]
    fn runtime_evidence_preserves_uppercase_executable_digest_hex() {
        let fixture = RuntimeEvidenceFixture::new();
        let mut plan = fixture.valid_plan();
        for field in [RUNTIME_EXECUTABLE_DIGEST_ENV, WINESERVER_EXECUTABLE_DIGEST_ENV] {
            let digest = plan.process.environment.get_mut(field).unwrap();
            *digest = format!("sha256:{}", digest[7..].to_ascii_uppercase());
        }
        fixture.assert_valid_launch_runs_commands(&plan);
    }

    #[test]
    fn runtime_evidence_pack_digest_identity_is_exact_even_for_valid_uppercase_hex() {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process.environment.insert(
                "COMPATFORGE_RUNTIME_PACK_DIGEST".into(),
                format!("sha256:{}", "A".repeat(64)),
            );
        });
    }

    #[test]
    fn runtime_evidence_legacy_pack_and_wineprefix_alone_remain_unmanaged() {
        let fixture = RuntimeEvidenceFixture::new();
        let mut plan = fixture_plan();
        plan.process.working_directory = fixture.root.to_str().unwrap().into();
        plan.process
            .environment
            .insert("COMPATFORGE_RUNTIME_PACK".into(), plan.runtime.pack_id.clone());
        plan.process
            .environment
            .insert("WINEPREFIX".into(), fixture.alternate_prefix().to_str().unwrap().into());
        let handle = ProcessSupervisor::start(&plan).unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        handle.terminate_and_wait(Duration::from_secs(1)).unwrap();
        assert!(events.last().unwrap().exit.as_ref().unwrap().success);
        fixture.assert_no_command_logs();
    }

    fn pinned_fixture_plan() -> (LaunchPlan, BottleExecutableBinding) {
        let mut plan = fixture_plan();
        let binding = BottleExecutableBinding {
            bottle_id: "gui-sumatrapdf".into(),
            digest: format!("sha256:{}", "1".repeat(64)),
            size_bytes: 4096,
            path: "/reviewed/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe".into(),
            original_name: "SumatraPDF.exe".into(),
            architecture: CpuArchitecture::X86_64,
            image_kind: "executable".into(),
            subsystem: "windowsGui".into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        };
        plan.process.executable = "/reviewed/CrossOver/bin/wine64".into();
        plan.process.arguments = vec![binding.path.clone()];
        plan.process
            .environment
            .insert("WINEPREFIX".into(), "/reviewed/bottles/gui-sumatrapdf/prefix".into());
        plan.bottle_executable = Some(binding.clone());
        (plan, binding)
    }

    #[test]
    fn pinned_command_uses_only_reviewed_wine_and_actual_descriptor() {
        let (plan, binding) = pinned_fixture_plan();
        let serialized_before = serde_json::to_string(&plan).unwrap();

        let command = pinned_command_spec(&plan, &binding, 41).unwrap();

        assert_eq!(command.executable, plan.process.executable);
        assert_eq!(command.arguments, ["/dev/fd/41"]);
        assert_eq!(command.current_dir, plan.process.working_directory);
        assert_eq!(command.environment, plan.process.environment);
        assert!(!command.arguments.iter().any(|argument| argument == &binding.path));
        assert_eq!(serde_json::to_string(&plan).unwrap(), serialized_before);
        assert!(!serialized_before.contains("/dev/fd/41"));
    }

    #[test]
    fn pinned_command_rejects_non_wine_extra_arguments_mismatch_and_fallback() {
        let (plan, binding) = pinned_fixture_plan();
        let assert_rejected = |plan: &LaunchPlan, binding: &BottleExecutableBinding| {
            assert!(matches!(
                pinned_command_spec(plan, binding, 41),
                Err(ProcessError::InvalidGuestArtifact(
                    GuestArtifactError::InvalidPinnedContract
                ))
            ));
        };

        let mut non_wine = plan.clone();
        non_wine.runtime.provider = RuntimeKind::Remote;
        assert_rejected(&non_wine, &binding);

        let mut extra = plan.clone();
        extra.process.arguments.push("--unsafe-extra".into());
        assert_rejected(&extra, &binding);

        let mut mismatched = binding.clone();
        mismatched.digest = format!("sha256:{}", "2".repeat(64));
        assert_rejected(&plan, &mismatched);

        let mut fallback = plan.clone();
        fallback.process.arguments.clear();
        assert_rejected(&fallback, &binding);

        let mut immutable_fallback = plan.clone();
        immutable_fallback.guest_artifact = Some(GuestArtifactBinding {
            digest: binding.digest.clone(),
            size_bytes: binding.size_bytes,
            stored_path: binding.path.clone(),
            original_name: binding.original_name.clone(),
            architecture: binding.architecture,
            image_kind: binding.image_kind.clone(),
            subsystem: binding.subsystem.clone(),
            inspection_schema_version: binding.inspection_schema_version.clone(),
        });
        assert_rejected(&immutable_fallback, &binding);
    }

    #[test]
    fn pinned_parent_duplicate_is_released_for_spawn_and_every_later_phase() {
        #[derive(Clone)]
        struct DropProbe(Arc<Mutex<Vec<&'static str>>>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                lock_recover(&self.0).push("duplicate-closed");
            }
        }

        for post_spawn_phase in ["attach-failure", "timeout", "cleanup"] {
            let order = Arc::new(Mutex::new(Vec::new()));
            let guard = DropProbe(Arc::clone(&order));
            let result: Result<(), ()> = release_parent_duplicate_after_spawn_attempt(guard, || {
                lock_recover(&order).push("spawn");
                Ok(())
            });
            result.unwrap();
            lock_recover(&order).push(post_spawn_phase);
            assert_eq!(&*lock_recover(&order), &["spawn", "duplicate-closed", post_spawn_phase]);
        }

        let order = Arc::new(Mutex::new(Vec::new()));
        let guard = DropProbe(Arc::clone(&order));
        let result: Result<(), ()> = release_parent_duplicate_after_spawn_attempt(guard, || {
            lock_recover(&order).push("spawn-failure");
            Err(())
        });
        assert!(result.is_err());
        assert_eq!(&*lock_recover(&order), &["spawn-failure", "duplicate-closed"]);
    }

    #[test]
    fn pinned_api_and_pre_exec_boundary_remain_closed() {
        let _api: fn(
            &LaunchPlan,
            &compatforge_guest_artifact::PinnedBottleExecutable,
        ) -> Result<LaunchHandle, ProcessError> = ProcessSupervisor::start_pinned_bottle;
        let source = include_str!("lib.rs");
        assert_eq!(
            source
                .lines()
                .filter(|line| line.trim_start().starts_with("command.pre_exec("))
                .count(),
            1
        );
        assert!(source.contains("setpgid(0, 0)"));
    }

    #[test]
    fn pinned_descriptor_is_absent_from_errors_events_and_the_ordinary_plan() {
        let (mut plan, binding) = pinned_fixture_plan();
        plan.process.arguments.push("rejected".into());
        let error = pinned_command_spec(&plan, &binding, 41).unwrap_err();
        let rendered_error = error.to_string();
        assert!(!rendered_error.contains("41"));
        assert!(!rendered_error.contains("/dev/fd"));

        let event = RuntimeEvent {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: plan.request_id.clone(),
            sequence: 0,
            elapsed_milliseconds: 0,
            kind: RuntimeEventKind::Failed,
            process_id: None,
            output: None,
            exit: None,
            message: Some(rendered_error),
        };
        assert!(!serde_json::to_string(&event).unwrap().contains("/dev/fd"));
        assert!(!serde_json::to_string(&plan).unwrap().contains("/dev/fd"));
    }

    #[test]
    fn pinned_launch_errors_erase_raw_paths_and_descriptor_numbers() {
        let raw = ProcessError::Spawn(io::Error::other(
            "could not execute /secret/reviewed-wine with /dev/fd/41",
        ));
        let sanitized = sanitize_pinned_launch_error(raw);
        let rendered = sanitized.to_string();
        assert_eq!(
            rendered,
            "invalid guest artifact: pinned Bottle executable capture failed"
        );
        assert!(!rendered.contains("/secret"));
        assert!(!rendered.contains("41"));
        assert!(std::error::Error::source(&sanitized).is_some());
    }

    #[test]
    fn ordinary_start_argument_selection_remains_byte_compatible() {
        let plan = fixture_plan();
        let before = serde_json::to_string(&plan).unwrap();
        assert_eq!(execution_arguments(&plan, None), plan.process.arguments);
        assert_eq!(serde_json::to_string(&plan).unwrap(), before);
    }

    #[cfg(target_os = "macos")]
    fn macos_pinned_fixture(
        label: &str,
    ) -> (
        PathBuf,
        compatforge_guest_artifact::PinnedBottleExecutable,
        LaunchPlan,
        Vec<u8>,
        PathBuf,
        PathBuf,
        PathBuf,
    ) {
        use compatforge_guest_artifact::{GuestArtifactStore, HeldExternalWorkRoot};
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let provisional_root = std::env::temp_dir().join(format!("compatforge-process-pinned-{label}-{nonce}"));
        std::fs::create_dir_all(&provisional_root).unwrap();
        let root = provisional_root.canonicalize().unwrap();
        let storage = root.join("store");
        let work = root.join("external-work");
        let source = storage.join("bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/hello-x86_64.exe");
        let mut gui_bytes = std::fs::read(fixture).unwrap();
        gui_bytes[0xdc..0xde].copy_from_slice(&2_u16.to_le_bytes());
        std::fs::write(&source, &gui_bytes).unwrap();

        let inherited_work = std::fs::File::open(&work).unwrap();
        let held = HeldExternalWorkRoot::duplicate_inherited(inherited_work.as_raw_fd(), &work, &[&storage]).unwrap();
        let pinned = GuestArtifactStore::new(&storage)
            .pin_sumatra_bottle_executable("gui-sumatrapdf", &source, &held)
            .unwrap();

        let output = root.join("child-bytes.bin");
        let arguments = root.join("child-arguments.txt");
        let gate = root.join("child-read-gate");
        let reviewed_wine = root.join("reviewed-wine");
        let mut wine = std::fs::File::create(&reviewed_wine).unwrap();
        wine.write_all(
            b"#!/bin/sh\nwhile [ ! -f \"$COMPATFORGE_PINNED_GATE\" ]; do :; done\nprintf '%s\\n' \"$@\" > \"$COMPATFORGE_PINNED_ARGUMENTS\"\n/bin/cat \"$1\" > \"$COMPATFORGE_PINNED_OUTPUT\"\n",
        )
        .unwrap();
        wine.sync_all().unwrap();
        drop(wine);
        let mut permissions = std::fs::metadata(&reviewed_wine).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&reviewed_wine, permissions).unwrap();

        let mut plan = fixture_plan();
        plan.process.executable = reviewed_wine.to_string_lossy().into_owned();
        plan.process.arguments = vec![pinned.binding().path.clone()];
        plan.process.working_directory = storage.join("bottles/gui-sumatrapdf").to_string_lossy().into_owned();
        plan.process.environment.insert(
            "COMPATFORGE_PINNED_OUTPUT".into(),
            output.to_string_lossy().into_owned(),
        );
        plan.process.environment.insert(
            "COMPATFORGE_PINNED_ARGUMENTS".into(),
            arguments.to_string_lossy().into_owned(),
        );
        plan.process
            .environment
            .insert("COMPATFORGE_PINNED_GATE".into(), gate.to_string_lossy().into_owned());
        plan.bottle_executable = Some(pinned.binding().clone());
        (root, pinned, plan, gui_bytes, output, arguments, gate)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_process_owned_duplicate_is_rewound_inheritable_and_caller_lease_stays_valid() {
        use std::os::fd::AsRawFd;

        let (root, pinned, _plan, _bytes, _output, _arguments, _gate) = macos_pinned_fixture("owned-duplicate");
        let execution = ProcessOwnedPinnedExecution::duplicate(&pinned).unwrap();
        let descriptor = execution.file.as_raw_fd();
        // SAFETY: `descriptor` belongs to the live `execution` file and lseek
        // only reads its current kernel-maintained offset.
        assert_eq!(unsafe { libc::lseek(descriptor, 0, libc::SEEK_CUR) }, 0);
        // SAFETY: F_GETFD only queries flags for the live descriptor.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
        drop(execution);
        // SAFETY: querying the former number proves this owner closed it; no
        // ownership is reconstructed from the raw integer.
        assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);
        pinned.revalidate().unwrap();
        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_start_inherits_only_the_process_duplicate_and_closes_the_parent_copy() {
        let (root, pinned, plan, bytes, output, arguments, gate) = macos_pinned_fixture("start");
        let handle = ProcessSupervisor::start_pinned_bottle(&plan, &pinned).unwrap();
        pinned.revalidate().unwrap();
        std::fs::write(gate, b"revalidation-complete").unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while (std::fs::read(&output).ok().as_deref() != Some(bytes.as_slice()) || !arguments.exists())
            && Instant::now() < deadline
        {
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        let child_arguments = std::fs::read_to_string(&arguments).unwrap();
        let lines = child_arguments.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let descriptor = lines[0].strip_prefix("/dev/fd/").unwrap().parse::<i32>().unwrap();
        // SAFETY: F_GETFD does not take ownership. The process-owned parent
        // descriptor must already be closed once spawn returned.
        assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);

        handle.terminate().unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(5));
        assert!(events.iter().all(|event| {
            !serde_json::to_string(event)
                .unwrap()
                .contains(&format!("/dev/fd/{descriptor}"))
        }));
        drop(handle);
        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_a_tampered_bound_guest_before_spawning() {
        let root = std::env::temp_dir().join(format!("compatforge-process-guest-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let guest_path = root.join("guest.exe");
        std::fs::write(&guest_path, b"tampered").unwrap();
        let stored_path = guest_path.to_string_lossy().into_owned();
        let mut plan = fixture_plan();
        plan.process.arguments = vec![stored_path.clone()];
        plan.guest_artifact = Some(GuestArtifactBinding {
            digest: format!("sha256:{}", "0".repeat(64)),
            size_bytes: 8,
            stored_path,
            original_name: "guest.exe".into(),
            architecture: CpuArchitecture::X86_64,
            image_kind: "executable".into(),
            subsystem: "windowsConsole".into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        });
        assert!(matches!(
            ProcessSupervisor::start(&plan),
            Err(ProcessError::InvalidGuestArtifact(
                GuestArtifactError::DigestMismatch { .. }
            ))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_a_tampered_pinned_runtime_before_spawning() {
        let fixture = RuntimeEvidenceFixture::new();
        let mut plan = fixture.valid_plan();
        plan.process.environment.insert(
            RUNTIME_EXECUTABLE_DIGEST_ENV.into(),
            format!("sha256:{}", "0".repeat(64)),
        );
        assert!(matches!(
            ProcessSupervisor::start(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("runtime executable"))
        ));
        fixture.assert_no_command_logs();
    }

    #[test]
    fn refuses_a_tampered_pinned_wineserver_before_spawning() {
        let fixture = RuntimeEvidenceFixture::new();
        let mut plan = fixture.valid_plan();
        plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            format!("sha256:{}", "0".repeat(64)),
        );
        assert!(matches!(
            ProcessSupervisor::start(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("wineserver executable"))
        ));
        fixture.assert_no_command_logs();
    }

    #[test]
    fn accepts_complete_fresh_runtime_evidence_and_rejects_incomplete_evidence() {
        let fixture = RuntimeEvidenceFixture::new();
        let mut plan = fixture.valid_plan();
        let digest = plan
            .process
            .environment
            .remove(WINESERVER_EXECUTABLE_DIGEST_ENV)
            .unwrap();
        assert!(matches!(
            verify_pinned_runtime(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("incomplete Runtime evidence"))
        ));
        plan.process
            .environment
            .insert(WINESERVER_EXECUTABLE_DIGEST_ENV.into(), digest);
        verify_pinned_runtime(&plan).unwrap();
    }

    #[test]
    fn accepts_a_pinned_font_configuration_and_rejects_incomplete_or_tampered_evidence() {
        let root = std::env::temp_dir().join(format!("compatforge-font-evidence-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("fonts.conf");
        std::fs::write(&config, b"font configuration").unwrap();
        let mut plan = fixture_plan();
        plan.process
            .environment
            .insert(FONT_CONFIG_FILE_ENV.into(), config.to_string_lossy().into_owned());
        assert!(matches!(
            verify_pinned_font_config(&plan),
            Err(ProcessError::InvalidRuntimeEvidence(
                "incomplete font configuration evidence"
            ))
        ));
        plan.process
            .environment
            .insert(FONT_CONFIG_DIGEST_ENV.into(), sha256_file(&config).unwrap());
        verify_pinned_font_config(&plan).unwrap();
        std::fs::write(&config, b"tampered").unwrap();
        assert!(matches!(
            verify_pinned_font_config(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("font configuration"))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_a_pinned_bottle_font_and_rejects_incomplete_or_tampered_evidence() {
        let root = std::env::temp_dir().join(format!("compatforge-bottle-font-evidence-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let font = root.join("font.ttc");
        std::fs::write(&font, b"font bytes").unwrap();
        let mut plan = fixture_plan();
        plan.process
            .environment
            .insert(BOTTLE_FONT_FILE_ENV.into(), font.to_string_lossy().into_owned());
        assert!(matches!(
            verify_pinned_bottle_font(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("incomplete Bottle font evidence"))
        ));
        plan.process
            .environment
            .insert(BOTTLE_FONT_DIGEST_ENV.into(), sha256_file(&font).unwrap());
        verify_pinned_bottle_font(&plan).unwrap();
        std::fs::write(&font, b"tampered").unwrap();
        assert!(matches!(
            verify_pinned_bottle_font(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("Bottle font"))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn helper_plan() -> LaunchPlan {
        let mut plan = fixture_plan();
        plan.process.arguments = vec![
            "--exact".into(),
            "tests::supervisor_helper".into(),
            "--nocapture".into(),
        ];
        plan.process
            .environment
            .insert("COMPATFORGE_PROCESS_TEST_HELPER".into(), "sleep".into());
        plan
    }

    struct FakeNaturalIdleCommand {
        polls: usize,
        poll_error: bool,
        interrupted: Arc<AtomicBool>,
        reaped: bool,
    }

    impl NaturalIdleCommand for FakeNaturalIdleCommand {
        fn try_wait_success(&mut self) -> io::Result<Option<bool>> {
            self.polls += 1;
            if self.poll_error {
                Err(io::Error::other("natural idle poll failed"))
            } else {
                Ok(None)
            }
        }

        fn interrupt_and_reap(&mut self) -> io::Result<()> {
            self.interrupted.store(true, Ordering::Release);
            self.reaped = true;
            Ok(())
        }
    }

    #[test]
    fn ordinary_and_pinned_gui_idle_waits_outlive_five_virtual_seconds_until_termination() {
        let mut ordinary = fixture_plan();
        ordinary.guest_artifact = Some(GuestArtifactBinding {
            digest: format!("sha256:{}", "1".repeat(64)),
            size_bytes: 3,
            stored_path: "C:\\managed\\gui.exe".into(),
            original_name: "gui.exe".into(),
            architecture: CpuArchitecture::X86_64,
            image_kind: "executable".into(),
            subsystem: "windowsGui".into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        });
        let (pinned, _) = pinned_fixture_plan();

        for plan in [&ordinary, &pinned] {
            assert!(managed_wine_gui_requires_idle_wait(plan));
            let termination_started = AtomicBool::new(false);
            let virtual_elapsed_seconds = std::cell::Cell::new(0_u64);
            let interrupted = Arc::new(AtomicBool::new(false));
            let mut command = FakeNaturalIdleCommand {
                polls: 0,
                poll_error: false,
                interrupted: Arc::clone(&interrupted),
                reaped: false,
            };

            wait_for_natural_idle_command(&mut command, &termination_started, || {
                let elapsed = virtual_elapsed_seconds.get() + 1;
                virtual_elapsed_seconds.set(elapsed);
                if elapsed == 6 {
                    assert!(!interrupted.load(Ordering::Acquire));
                    termination_started.store(true, Ordering::Release);
                }
            })
            .unwrap();

            assert_eq!(virtual_elapsed_seconds.get(), 6);
            assert_eq!(command.polls, 6);
            assert!(command.interrupted.load(Ordering::Acquire));
            assert!(command.reaped);
        }
    }

    #[test]
    fn natural_idle_poll_failure_interrupts_and_reaps_before_returning() {
        let interrupted = Arc::new(AtomicBool::new(false));
        let mut command = FakeNaturalIdleCommand {
            polls: 0,
            poll_error: true,
            interrupted: Arc::clone(&interrupted),
            reaped: false,
        };

        assert!(
            wait_for_natural_idle_command(&mut command, &AtomicBool::new(false), || {
                panic!("a failed poll must not wait again");
            })
            .is_err()
        );

        assert_eq!(command.polls, 1);
        assert!(interrupted.load(Ordering::Acquire));
        assert!(command.reaped);
    }

    #[derive(Clone, Copy)]
    enum CleanupPoll {
        Running,
        Exited,
        Error(&'static str),
    }

    struct FakeNaturalIdleCleanupSteps {
        poll: CleanupPoll,
        kill_error: Option<&'static str>,
        wait_error: Option<&'static str>,
        poll_calls: usize,
        kill_calls: usize,
        wait_calls: usize,
    }

    impl NaturalIdleCleanupSteps for FakeNaturalIdleCleanupSteps {
        fn poll_for_exit(&mut self) -> io::Result<bool> {
            self.poll_calls += 1;
            match self.poll {
                CleanupPoll::Running => Ok(false),
                CleanupPoll::Exited => Ok(true),
                CleanupPoll::Error(message) => Err(io::Error::other(message)),
            }
        }

        fn kill_for_cleanup(&mut self) -> io::Result<()> {
            self.kill_calls += 1;
            self.kill_error.map_or(Ok(()), |message| Err(io::Error::other(message)))
        }

        fn wait_for_reap_bounded(&mut self) -> io::Result<()> {
            self.wait_calls += 1;
            self.wait_error.map_or(Ok(()), |message| Err(io::Error::other(message)))
        }
    }

    fn cleanup_steps(
        poll: CleanupPoll,
        kill_error: Option<&'static str>,
        wait_error: Option<&'static str>,
    ) -> FakeNaturalIdleCleanupSteps {
        FakeNaturalIdleCleanupSteps {
            poll,
            kill_error,
            wait_error,
            poll_calls: 0,
            kill_calls: 0,
            wait_calls: 0,
        }
    }

    #[test]
    fn natural_idle_cleanup_does_not_kill_or_wait_an_already_reaped_child() {
        let mut steps = cleanup_steps(CleanupPoll::Exited, None, None);

        interrupt_and_reap_natural_idle(&mut steps).unwrap();

        assert_eq!((steps.poll_calls, steps.kill_calls, steps.wait_calls), (1, 0, 0));
    }

    #[test]
    fn natural_idle_cleanup_waits_once_after_kill_failure() {
        let mut steps = cleanup_steps(CleanupPoll::Running, Some("kill failed"), None);

        let error = interrupt_and_reap_natural_idle(&mut steps).unwrap_err();

        assert_eq!(error.to_string(), "kill failed");
        assert_eq!((steps.poll_calls, steps.kill_calls, steps.wait_calls), (1, 1, 1));
    }

    #[test]
    fn natural_idle_cleanup_wait_failure_has_best_effort_precedence() {
        let mut steps = cleanup_steps(CleanupPoll::Running, Some("kill failed"), Some("wait failed"));

        let error = interrupt_and_reap_natural_idle(&mut steps).unwrap_err();

        assert_eq!(error.to_string(), "wait failed");
        assert_eq!((steps.poll_calls, steps.kill_calls, steps.wait_calls), (1, 1, 1));
    }

    struct PersistentPollFailureCommand {
        outer_poll_calls: usize,
        cleanup: FakeNaturalIdleCleanupSteps,
    }

    impl NaturalIdleCommand for PersistentPollFailureCommand {
        fn try_wait_success(&mut self) -> io::Result<Option<bool>> {
            self.outer_poll_calls += 1;
            Err(io::Error::other("outer poll failed"))
        }

        fn interrupt_and_reap(&mut self) -> io::Result<()> {
            interrupt_and_reap_natural_idle(&mut self.cleanup)
        }
    }

    #[test]
    fn persistent_natural_idle_poll_error_still_attempts_kill_and_bounded_wait() {
        let mut command = PersistentPollFailureCommand {
            outer_poll_calls: 0,
            cleanup: cleanup_steps(CleanupPoll::Error("cleanup poll failed"), None, None),
        };

        let error = wait_for_natural_idle_command(&mut command, &AtomicBool::new(false), || {
            panic!("persistent poll failure must enter cleanup immediately");
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "cleanup poll failed");
        assert_eq!(command.outer_poll_calls, 1);
        assert_eq!(
            (
                command.cleanup.poll_calls,
                command.cleanup.kill_calls,
                command.cleanup.wait_calls,
            ),
            (1, 1, 1)
        );
    }

    fn collect_until_exit(handle: &LaunchHandle, deadline: Instant) -> Vec<RuntimeEvent> {
        let mut events = Vec::new();
        while Instant::now() < deadline {
            if let EventPoll::Event(event) = handle.next_event(Duration::from_millis(250)) {
                let exited = event.kind == RuntimeEventKind::Exited;
                events.push(event);
                if exited {
                    break;
                }
            }
        }
        events
    }

    #[test]
    fn emits_started_output_and_exit_in_sequence() {
        let handle = ProcessSupervisor::start(&fixture_plan()).unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));

        assert_eq!(events.first().map(|event| event.kind), Some(RuntimeEventKind::Started));
        assert!(events.iter().any(|event| event.kind == RuntimeEventKind::Output));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
        assert!(events.last().and_then(|event| event.exit.as_ref()).unwrap().success);
        assert!(events.windows(2).all(|pair| pair[0].sequence < pair[1].sequence));
    }

    #[cfg(unix)]
    fn complete_managed_runtime_environment(plan: &mut LaunchPlan) {
        let lifecycle = plan.lifecycle.wineserver.as_ref().unwrap();
        for (key, value) in [
            ("COMPATFORGE_RUNTIME_PACK", &plan.runtime.pack_id),
            ("COMPATFORGE_RUNTIME_PACK_DIGEST", &plan.runtime.pack_digest),
            ("WINESERVER", &lifecycle.executable),
            ("WINEPREFIX", &lifecycle.prefix),
        ] {
            plan.process.environment.insert(key.into(), value.clone());
        }
    }

    #[cfg(unix)]
    #[test]
    fn gui_launch_reaches_exit_after_wineserver_becomes_idle_without_termination() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("compatforge-gui-idle-{}-{nonce}", std::process::id()));
        let prefix = directory.join("prefix");
        let system32 = prefix.join("drive_c/windows/system32");
        std::fs::create_dir_all(&system32).unwrap();
        std::fs::write(system32.join("ntdll.dll"), b"marker").unwrap();
        let runtime = directory.join("wine");
        let wineserver = directory.join("wineserver");
        for (path, source) in [
            (&runtime, b"#!/bin/sh\nexit 0\n".as_slice()),
            (&wineserver, b"#!/bin/sh\nexit 0\n".as_slice()),
        ] {
            let mut file = std::fs::File::create(path).unwrap();
            file.write_all(source).unwrap();
            file.sync_all().unwrap();
            drop(file);
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        let guest = directory.join("guest.exe");
        std::fs::write(&guest, b"gui").unwrap();
        let guest_digest = sha256_file(&guest).unwrap();

        let mut plan = fixture_plan();
        plan.process.executable = runtime.to_string_lossy().into_owned();
        plan.process.arguments = vec![guest.to_string_lossy().into_owned()];
        plan.process.working_directory = directory.to_string_lossy().into_owned();
        plan.process
            .environment
            .insert("WINEPREFIX".into(), prefix.to_string_lossy().into_owned());
        plan.process
            .environment
            .insert(RUNTIME_EXECUTABLE_DIGEST_ENV.into(), sha256_file(&runtime).unwrap());
        plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(&wineserver).unwrap(),
        );
        plan.guest_artifact = Some(GuestArtifactBinding {
            digest: guest_digest,
            size_bytes: 3,
            stored_path: guest.to_string_lossy().into_owned(),
            original_name: "guest.exe".into(),
            architecture: CpuArchitecture::X86_64,
            image_kind: "executable".into(),
            subsystem: "windowsGui".into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        });
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: wineserver.to_string_lossy().into_owned(),
            prefix: prefix.to_string_lossy().into_owned(),
        });
        complete_managed_runtime_environment(&mut plan);

        let handle = ProcessSupervisor::start(&plan).unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));

        assert!(!events
            .iter()
            .any(|event| event.kind == RuntimeEventKind::TerminateRequested));
        assert!(events
            .iter()
            .any(|event| event.kind == RuntimeEventKind::WineServerStopRequested));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn gui_launch_does_not_fail_or_stop_a_live_wineserver_before_caller_termination() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("compatforge-gui-live-{}-{nonce}", std::process::id()));
        let prefix = directory.join("prefix");
        let system32 = prefix.join("drive_c/windows/system32");
        std::fs::create_dir_all(&system32).unwrap();
        std::fs::write(system32.join("ntdll.dll"), b"marker").unwrap();
        let runtime = directory.join("wine");
        let wineserver = directory.join("wineserver");
        let release = directory.join("release");
        let started = directory.join("started");
        let gate = directory.join("gate");
        assert!(Command::new("/usr/bin/mkfifo").arg(&gate).status().unwrap().success());
        let mut runtime_file = std::fs::File::create(&runtime).unwrap();
        runtime_file.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        runtime_file.sync_all().unwrap();
        drop(runtime_file);
        let mut wineserver_file = std::fs::File::create(&wineserver).unwrap();
        wineserver_file
            .write_all(
                b"#!/bin/sh\nif [ \"$1\" = \"-k\" ]; then\n  : > \"$COMPATFORGE_WINESERVER_RELEASE\"\nelif [ \"$1\" = \"-w\" ] && [ ! -e \"$COMPATFORGE_WINESERVER_RELEASE\" ]; then\n  : > \"$COMPATFORGE_WINESERVER_STARTED\"\n  read ignored < \"$COMPATFORGE_WINESERVER_GATE\"\nfi\n",
            )
            .unwrap();
        wineserver_file.sync_all().unwrap();
        drop(wineserver_file);
        for path in [&runtime, &wineserver] {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        let guest = directory.join("guest.exe");
        std::fs::write(&guest, b"gui").unwrap();

        let mut plan = fixture_plan();
        plan.process.executable = runtime.to_string_lossy().into_owned();
        plan.process.arguments = vec![guest.to_string_lossy().into_owned()];
        plan.process.working_directory = directory.to_string_lossy().into_owned();
        plan.process
            .environment
            .insert("WINEPREFIX".into(), prefix.to_string_lossy().into_owned());
        plan.process.environment.insert(
            "COMPATFORGE_WINESERVER_RELEASE".into(),
            release.to_string_lossy().into_owned(),
        );
        plan.process.environment.insert(
            "COMPATFORGE_WINESERVER_STARTED".into(),
            started.to_string_lossy().into_owned(),
        );
        plan.process.environment.insert(
            "COMPATFORGE_WINESERVER_GATE".into(),
            gate.to_string_lossy().into_owned(),
        );
        plan.process
            .environment
            .insert(RUNTIME_EXECUTABLE_DIGEST_ENV.into(), sha256_file(&runtime).unwrap());
        plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(&wineserver).unwrap(),
        );
        plan.guest_artifact = Some(GuestArtifactBinding {
            digest: sha256_file(&guest).unwrap(),
            size_bytes: 3,
            stored_path: guest.to_string_lossy().into_owned(),
            original_name: "guest.exe".into(),
            architecture: CpuArchitecture::X86_64,
            image_kind: "executable".into(),
            subsystem: "windowsGui".into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        });
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: wineserver.to_string_lossy().into_owned(),
            prefix: prefix.to_string_lossy().into_owned(),
        });
        complete_managed_runtime_environment(&mut plan);

        let handle = ProcessSupervisor::start(&plan).unwrap();
        let start_deadline = Instant::now() + Duration::from_secs(5);
        let mut before_termination = Vec::new();
        while !started.exists() && Instant::now() < start_deadline {
            if let EventPoll::Event(event) = handle.next_event(PROCESS_POLL_INTERVAL) {
                before_termination.push(event);
            }
        }
        assert!(started.exists());
        thread::sleep(WINE_SERVER_COMMAND_TIMEOUT + Duration::from_millis(50));
        while let EventPoll::Event(event) = handle.next_event(Duration::ZERO) {
            before_termination.push(event);
        }
        assert!(!before_termination.iter().any(|event| {
            matches!(
                event.kind,
                RuntimeEventKind::Failed | RuntimeEventKind::WineServerStopRequested | RuntimeEventKind::Exited
            )
        }));

        handle.terminate().unwrap();
        let after_termination = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        handle.terminate_and_wait(Duration::from_secs(1)).unwrap();

        assert!(after_termination
            .iter()
            .any(|event| event.kind == RuntimeEventKind::WineServerStopRequested));
        assert!(!after_termination
            .iter()
            .any(|event| event.kind == RuntimeEventKind::Failed));
        assert_eq!(
            after_termination.last().map(|event| event.kind),
            Some(RuntimeEventKind::Exited)
        );
        assert_eq!(handle.controller.worker_count(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn explicit_termination_is_idempotent_and_reaches_exit() {
        let handle = ProcessSupervisor::start(&helper_plan()).unwrap();
        assert!(matches!(
            handle.next_event(Duration::from_secs(2)),
            EventPoll::Event(RuntimeEvent {
                kind: RuntimeEventKind::Started,
                ..
            })
        ));
        handle.terminate().unwrap();
        handle.terminate().unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));

        assert!(events
            .iter()
            .any(|event| event.kind == RuntimeEventKind::TerminateRequested));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
    }

    #[test]
    fn bounded_completion_joins_every_worker_after_terminal_exit() {
        let handle = ProcessSupervisor::start(&fixture_plan()).unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));

        handle.terminate_and_wait(Duration::from_secs(1)).unwrap();

        assert!(handle.is_finished());
        assert_eq!(handle.controller.worker_count(), 0);
    }

    #[test]
    fn bounded_completion_forces_reaps_and_joins_a_live_process() {
        let mut plan = helper_plan();
        plan.lifecycle.termination_grace_milliseconds = 20;
        let handle = ProcessSupervisor::start(&plan).unwrap();
        assert!(matches!(
            handle.next_event(Duration::from_secs(2)),
            EventPoll::Event(RuntimeEvent {
                kind: RuntimeEventKind::Started,
                ..
            })
        ));
        let started = Instant::now();

        handle.terminate_and_wait(Duration::from_millis(1)).unwrap();

        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(handle.is_finished());
        assert_eq!(handle.controller.worker_count(), 0);
    }

    #[test]
    fn bounded_completion_joins_timeout_and_escalation_workers() {
        let mut plan = helper_plan();
        plan.lifecycle.maximum_runtime_milliseconds = Some(20);
        plan.lifecycle.termination_grace_milliseconds = 20;
        let handle = ProcessSupervisor::start(&plan).unwrap();

        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        assert!(events.iter().any(|event| event.kind == RuntimeEventKind::TimedOut));

        handle.terminate_and_wait(Duration::from_secs(1)).unwrap();

        assert!(handle.is_finished());
        assert_eq!(handle.controller.worker_count(), 0);
    }

    #[test]
    fn bounded_completion_reports_worker_failure_after_joining_it() {
        let handle = ProcessSupervisor::start(&fixture_plan()).unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
        handle.controller.register_worker(thread::spawn(|| {
            panic!("supervisor worker failure fixture");
        }));

        assert!(handle.terminate_and_wait(Duration::from_secs(1)).is_err());

        assert!(handle.is_finished());
        assert_eq!(handle.controller.worker_count(), 0);
    }

    #[test]
    fn bounded_completion_joins_workers_registered_while_draining() {
        let handle = ProcessSupervisor::start(&fixture_plan()).unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
        let controller = Arc::clone(&handle.controller);
        handle.controller.register_worker(thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            controller.register_worker(thread::spawn(|| {}));
        }));

        handle.terminate_and_wait(Duration::from_secs(1)).unwrap();

        assert!(handle.is_finished());
        assert_eq!(handle.controller.worker_count(), 0);
    }

    #[test]
    fn concurrent_bounded_completion_waits_for_the_active_join() {
        let handle = Arc::new(ProcessSupervisor::start(&fixture_plan()).unwrap());
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
        let (release, released) = mpsc::channel();
        handle.controller.register_worker(thread::spawn(move || {
            released.recv().unwrap();
            thread::sleep(Duration::from_millis(200));
        }));
        let first_handle = Arc::clone(&handle);
        let first = thread::spawn(move || first_handle.terminate_and_wait(Duration::from_secs(1)));
        while handle.controller.worker_count() != 0 {
            thread::yield_now();
        }
        release.send(()).unwrap();

        let started = Instant::now();
        handle.terminate_and_wait(Duration::from_secs(1)).unwrap();

        assert!(started.elapsed() >= Duration::from_millis(100));
        first.join().unwrap().unwrap();
        assert_eq!(handle.controller.worker_count(), 0);
    }

    #[test]
    fn maximum_runtime_triggers_automatic_tree_termination() {
        let mut plan = helper_plan();
        plan.lifecycle.maximum_runtime_milliseconds = Some(100);
        plan.lifecycle.termination_grace_milliseconds = 100;
        let handle = ProcessSupervisor::start(&plan).unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));

        assert!(events.iter().any(|event| event.kind == RuntimeEventKind::TimedOut));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
    }

    #[test]
    fn termination_prevents_a_descendant_from_escaping_the_process_tree() {
        let marker = std::env::temp_dir().join(format!("compatforge-descendant-test-{}.marker", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut plan = helper_plan();
        plan.lifecycle.termination_grace_milliseconds = 100;
        plan.process
            .environment
            .insert("COMPATFORGE_PROCESS_TEST_HELPER".into(), "spawn-descendant".into());
        plan.process.environment.insert(
            "COMPATFORGE_DESCENDANT_MARKER".into(),
            marker.to_string_lossy().into_owned(),
        );
        let handle = ProcessSupervisor::start(&plan).unwrap();
        let ready_deadline = Instant::now() + Duration::from_secs(5);
        let mut ready = false;
        while Instant::now() < ready_deadline && !ready {
            if let EventPoll::Event(event) = handle.next_event(Duration::from_millis(250)) {
                ready = event
                    .output
                    .as_ref()
                    .is_some_and(|output| output.text.contains("descendant-ready"));
            }
        }
        assert!(ready);

        handle.terminate().unwrap();
        let events = collect_until_exit(&handle, Instant::now() + Duration::from_secs(10));
        assert_eq!(events.last().map(|event| event.kind), Some(RuntimeEventKind::Exited));
        thread::sleep(Duration::from_millis(1_500));
        assert!(!marker.exists(), "descendant escaped process-tree termination");
    }

    #[test]
    fn rejects_concurrent_launches_for_the_same_managed_wine_prefix() {
        let fixture = RuntimeEvidenceFixture::new();
        materialize_launch_directories(&fixture.plan).unwrap();
        let first = WineSession::acquire(&fixture.plan).unwrap().unwrap();
        assert!(matches!(
            WineSession::acquire(&fixture.plan),
            Err(ProcessError::WinePrefixBusy(_))
        ));
        assert_eq!(first.stop_core(None), StopOutcome::Complete);
        assert!(WineSession::acquire(&fixture.plan).unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn wineserver_cleanup_uses_pinned_executable_and_prefix() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory =
            std::env::temp_dir().join(format!("compatforge-wineserver-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let executable = directory.join("wineserver");
        let staged_executable = directory.join("wineserver.staged");
        let output = directory.join("calls.log");
        let mut executable_file = std::fs::File::create(&staged_executable).unwrap();
        executable_file
            .write_all(b"#!/bin/sh\nprintf '%s:%s\\n' \"$1\" \"$WINEPREFIX\" >> \"$COMPATFORGE_WINESERVER_LOG\"\n")
            .unwrap();
        executable_file.sync_all().unwrap();
        drop(executable_file);
        let mut permissions = std::fs::metadata(&staged_executable).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&staged_executable, permissions).unwrap();
        std::fs::rename(&staged_executable, &executable).unwrap();

        let mut plan = fixture_plan();
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: executable.to_string_lossy().into_owned(),
            prefix: directory.join("prefix").to_string_lossy().into_owned(),
        });
        plan.process.environment.insert(
            "COMPATFORGE_WINESERVER_LOG".into(),
            output.to_string_lossy().into_owned(),
        );
        plan.process.working_directory = directory.to_string_lossy().into_owned();
        std::fs::create_dir(&plan.lifecycle.wineserver.as_ref().unwrap().prefix).unwrap();
        plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(&executable).unwrap(),
        );
        let session = WineSession::acquire(&plan).unwrap().unwrap();
        let (sender, _receiver) = mpsc::channel();
        let emitter = EventEmitter::new("wine-cleanup-test".into(), sender);

        session.stop(&emitter).unwrap();

        let prefix = &session.lifecycle.prefix;
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            format!("-k:{prefix}\n-w:{prefix}\n")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn wineserver_idle_wait_uses_pinned_executable_and_releases_prefix() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "compatforge-wineserver-wait-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let executable = directory.join("wineserver");
        let output = directory.join("calls.log");
        let mut executable_file = std::fs::File::create(&executable).unwrap();
        executable_file
            .write_all(b"#!/bin/sh\nprintf '%s:%s\\n' \"$1\" \"$WINEPREFIX\" >> \"$COMPATFORGE_WINESERVER_LOG\"\n")
            .unwrap();
        executable_file.sync_all().unwrap();
        drop(executable_file);
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).unwrap();

        let mut plan = fixture_plan();
        let prefix = directory.join("prefix").to_string_lossy().into_owned();
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: executable.to_string_lossy().into_owned(),
            prefix: prefix.clone(),
        });
        plan.process.environment.insert(
            "COMPATFORGE_WINESERVER_LOG".into(),
            output.to_string_lossy().into_owned(),
        );
        plan.process.working_directory = directory.to_string_lossy().into_owned();
        std::fs::create_dir(&prefix).unwrap();
        plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            sha256_file(&executable).unwrap(),
        );
        let session = WineSession::acquire(&plan).unwrap().unwrap();

        session.wait_until_idle(&AtomicBool::new(false)).unwrap();

        let prefix = &session.lifecycle.prefix;
        assert_eq!(std::fs::read_to_string(output).unwrap(), format!("-w:{prefix}\n"));
        assert!(matches!(
            WineSession::acquire(&plan),
            Err(ProcessError::WinePrefixBusy(_))
        ));
        let (sender, _receiver) = mpsc::channel();
        let emitter = EventEmitter::new("wine-idle-test".into(), sender);
        session.stop(&emitter).unwrap();
        assert!(WineSession::acquire(&plan).unwrap().is_some());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wine_prefix_cleanup_reaps_a_detached_client_holding_the_prefix_marker() {
        use std::io::Write;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "compatforge-wine-client-cleanup-test-{}-{nonce}",
            std::process::id()
        ));
        let system32 = directory.join("drive_c/windows/system32");
        std::fs::create_dir_all(&system32).unwrap();
        let marker = system32.join("ntdll.dll");
        let mut marker_file = std::fs::File::create(&marker).unwrap();
        marker_file.write_all(b"marker").unwrap();
        marker_file.sync_all().unwrap();
        drop(marker_file);

        let mut client = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::supervisor_helper", "--nocapture"])
            .env_clear()
            .env("COMPATFORGE_PROCESS_TEST_HELPER", "hold-prefix-marker")
            .env("COMPATFORGE_PREFIX_MARKER", &marker)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut observed = false;
        while Instant::now() < deadline {
            let output = Command::new("/usr/sbin/lsof")
                .args(["-t", "--"])
                .arg(&marker)
                .output()
                .unwrap();
            if String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.parse::<u32>().ok() == Some(client.id()))
            {
                observed = true;
                break;
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        assert!(observed, "detached Wine client did not open the prefix marker");

        platform::force_kill_wine_prefix_clients(&directory).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = client.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "detached Wine client was not reaped");
            thread::sleep(PROCESS_POLL_INTERVAL);
        };
        assert!(!status.success());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wine_prefix_cleanup_reaps_a_detached_client_holding_the_system32_directory() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "compatforge-wine-directory-cleanup-test-{}-{nonce}",
            std::process::id()
        ));
        let system32 = directory.join("drive_c/windows/system32");
        std::fs::create_dir_all(&system32).unwrap();
        std::fs::write(system32.join("ntdll.dll"), b"marker").unwrap();

        let mut client = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::supervisor_helper", "--nocapture"])
            .current_dir(&system32)
            .env_clear()
            .env("COMPATFORGE_PROCESS_TEST_HELPER", "sleep")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut observed = false;
        while Instant::now() < deadline {
            let output = Command::new("/usr/sbin/lsof")
                .args(["-t", "--"])
                .arg(&system32)
                .output()
                .unwrap();
            if String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.parse::<u32>().ok() == Some(client.id()))
            {
                observed = true;
                break;
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        assert!(observed, "detached Wine client did not retain the system32 directory");

        platform::force_kill_wine_prefix_clients(&directory).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = client.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "detached Wine client was not reaped");
            thread::sleep(PROCESS_POLL_INTERVAL);
        };
        assert!(!status.success());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn runtime_events_round_trip_as_versioned_json() {
        let event = RuntimeEvent {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: "round-trip".into(),
            sequence: 0,
            elapsed_milliseconds: 1,
            kind: RuntimeEventKind::Output,
            process_id: None,
            output: Some(ProcessOutput {
                stream: OutputStream::Stdout,
                text: "ready\n".into(),
            }),
            exit: None,
            message: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: RuntimeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, event);
    }

    #[test]
    fn supervisor_helper() {
        match std::env::var("COMPATFORGE_PROCESS_TEST_HELPER").as_deref() {
            Ok("sleep") => {
                println!("helper-ready");
                thread::sleep(Duration::from_secs(30));
            }
            Ok("spawn-descendant") => {
                let marker = std::env::var("COMPATFORGE_DESCENDANT_MARKER").unwrap();
                let mut descendant = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "tests::supervisor_helper", "--nocapture"])
                    .env_clear()
                    .env("COMPATFORGE_PROCESS_TEST_HELPER", "write-marker")
                    .env("COMPATFORGE_DESCENDANT_MARKER", marker)
                    .spawn()
                    .unwrap();
                println!("descendant-ready");
                thread::sleep(Duration::from_secs(30));
                let _ = descendant.kill();
                let _ = descendant.wait();
            }
            Ok("write-marker") => {
                thread::sleep(Duration::from_secs(1));
                std::fs::write(std::env::var("COMPATFORGE_DESCENDANT_MARKER").unwrap(), "escaped").unwrap();
                thread::sleep(Duration::from_secs(30));
            }
            Ok("hold-prefix-marker") => {
                let marker = std::fs::File::open(std::env::var("COMPATFORGE_PREFIX_MARKER").unwrap()).unwrap();
                std::hint::black_box(&marker);
                thread::sleep(Duration::from_secs(30));
            }
            _ => {}
        }
    }
}
