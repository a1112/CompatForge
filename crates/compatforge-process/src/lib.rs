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
const WINE_SERVER_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const WINE_PREFIX_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(90);
const EXECUTABLE_BUSY_RETRY_LIMIT: usize = 20;
const EXECUTABLE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);
const RUNTIME_EXECUTABLE_DIGEST_ENV: &str = "COMPATFORGE_RUNTIME_EXECUTABLE_SHA256";
const WINESERVER_EXECUTABLE_DIGEST_ENV: &str = "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256";

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
        }
    }
}

impl std::error::Error for ProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPlan(error) => Some(error),
            Self::InvalidGuestArtifact(error) => Some(error),
            Self::Isolation(error) | Self::Spawn(error) | Self::Terminate(error) => Some(error),
            Self::InvalidRuntimeEvidence(_) | Self::UnsafeDirectory(_) | Self::WinePrefixBusy(_) => None,
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
        plan.validate().map_err(ProcessError::InvalidPlan)?;
        if let Some(binding) = &plan.guest_artifact {
            verify_binding_contents(binding).map_err(ProcessError::InvalidGuestArtifact)?;
        }
        if let Some(binding) = &plan.bottle_executable {
            verify_in_place_binding_contents(binding).map_err(ProcessError::InvalidGuestArtifact)?;
        }
        verify_pinned_runtime(plan)?;
        materialize_launch_directories(plan)?;
        let wine_session = WineSession::acquire(plan)?;
        initialize_wine_prefix(plan)?;
        let guest_execution_alias = prepare_guest_execution_alias(plan)?;
        let keep_alive_after_root_exit = plan.bottle_executable.is_some()
            || plan
                .guest_artifact
                .as_ref()
                .is_some_and(|binding| binding.subsystem == "windowsGui");

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

        supervise_command(plan, command, wine_session, keep_alive_after_root_exit, ())
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
        arguments: vec!["start.exe".into(), "/unix".into(), format!("/dev/fd/{descriptor}")],
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
    let execution = ProcessOwnedPinnedExecution::duplicate(pinned)?;
    let command_spec = pinned_command_spec(plan, pinned.binding(), execution.descriptor())?;
    let keep_alive_after_root_exit = true;

    let mut command = Command::new(command_spec.executable);
    command
        .args(command_spec.arguments)
        .current_dir(command_spec.current_dir)
        .env_clear()
        .envs(command_spec.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    supervise_command(plan, command, wine_session, keep_alive_after_root_exit, execution)
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

#[cfg(any(test, target_os = "macos"))]
fn invalid_pinned_launch() -> ProcessError {
    ProcessError::InvalidGuestArtifact(GuestArtifactError::InvalidPinnedContract)
}

#[cfg(any(test, target_os = "macos"))]
fn pinned_launch_failed() -> ProcessError {
    ProcessError::InvalidGuestArtifact(GuestArtifactError::PinnedCaptureFailed)
}

#[cfg(any(test, target_os = "macos"))]
fn sanitize_pinned_launch_error(_error: ProcessError) -> ProcessError {
    pinned_launch_failed()
}

fn release_parent_duplicate_after_spawn_attempt<G, T, E>(
    guard: G,
    spawn: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let result = spawn();
    drop(guard);
    result
}

fn supervise_command<G>(
    plan: &LaunchPlan,
    mut command: Command,
    wine_session: Option<Arc<WineSession>>,
    keep_alive_after_root_exit: bool,
    parent_execution_guard: G,
) -> Result<LaunchHandle, ProcessError> {
    let prepared_tree = platform::PreparedProcessTree::prepare(&mut command).map_err(ProcessError::Isolation)?;
    let mut child = release_parent_duplicate_after_spawn_attempt(parent_execution_guard, || command.spawn())
        .map_err(ProcessError::Spawn)?;
    let process_tree = match prepared_tree.attach(&child) {
        Ok(process_tree) => Arc::new(process_tree),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProcessError::Isolation(error));
        }
    };

    let process_id = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(child));
    let root_exited = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));
    let termination_started = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    let emitter = Arc::new(EventEmitter::new(plan.request_id.clone(), sender));
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
    });

    emitter.emit(RuntimeEventKind::Started, Some(process_id), None, None, None);
    let mut output_readers = Vec::new();
    if let Some(pipe) = stdout {
        output_readers.push(spawn_output_reader(pipe, OutputStream::Stdout, Arc::clone(&emitter)));
    }
    if let Some(pipe) = stderr {
        output_readers.push(spawn_output_reader(pipe, OutputStream::Stderr, Arc::clone(&emitter)));
    }
    spawn_exit_watcher(
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
        },
    );
    if let Some(maximum_runtime) = plan.lifecycle.maximum_runtime_milliseconds {
        spawn_timeout_watcher(
            Arc::downgrade(&controller),
            root_exited,
            keep_alive_after_root_exit,
            Duration::from_millis(maximum_runtime),
        );
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
    let mut child = command.spawn().map_err(ProcessError::Spawn)?;
    let deadline = Instant::now() + WINE_PREFIX_BOOTSTRAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(exit)) if exit.success() => {
                let metadata = std::fs::symlink_metadata(&marker)
                    .map_err(|_| ProcessError::UnsafeDirectory("Wine prefix marker"))?;
                if metadata.is_file() && !metadata.file_type().is_symlink() {
                    return Ok(());
                }
                return Err(ProcessError::UnsafeDirectory("Wine prefix marker"));
            }
            Ok(Some(exit)) => {
                return Err(ProcessError::Spawn(io::Error::other(format!(
                    "wineboot exited with {exit}"
                ))));
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProcessError::Spawn(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "wineboot did not initialize the prefix within 90 seconds",
                )));
            }
            Err(error) => return Err(ProcessError::Spawn(error)),
        }
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
    let runtime_digest = plan.process.environment.get(RUNTIME_EXECUTABLE_DIGEST_ENV);
    let wineserver_digest = plan.process.environment.get(WINESERVER_EXECUTABLE_DIGEST_ENV);
    match (runtime_digest, wineserver_digest) {
        (None, None) => return Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            return Err(ProcessError::InvalidRuntimeEvidence("incomplete Runtime evidence"));
        }
        (Some(runtime_digest), Some(wineserver_digest)) => {
            verify_pinned_executable(
                Path::new(&plan.process.executable),
                runtime_digest,
                "runtime executable",
            )?;
            let lifecycle = plan
                .lifecycle
                .wineserver
                .as_ref()
                .ok_or(ProcessError::InvalidRuntimeEvidence("wineserver lifecycle"))?;
            verify_pinned_executable(
                Path::new(&lifecycle.executable),
                wineserver_digest,
                "wineserver executable",
            )?;
        }
    }
    Ok(())
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
        thread::spawn(move || controller.escalate_after_grace());
        Ok(())
    }

    fn escalate_after_grace(&self) {
        let deadline = Instant::now() + self.grace_period;
        while Instant::now() < deadline {
            if self.root_exited.load(Ordering::Acquire) && !self.keep_alive_after_root_exit {
                return;
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        if self.root_exited.load(Ordering::Acquire) && !self.keep_alive_after_root_exit {
            return;
        }

        self.emitter.emit(
            RuntimeEventKind::GracePeriodExpired,
            Some(self.process_id),
            None,
            None,
            Some("graceful termination period expired; forcing process tree shutdown".into()),
        );
        if let Some(wine_session) = &self.wine_session {
            if let Err(error) = wine_session.stop(&self.emitter) {
                self.emitter.emit(
                    RuntimeEventKind::Failed,
                    Some(self.process_id),
                    None,
                    None,
                    Some(format!("wineserver cleanup failed: {error}")),
                );
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
            let mut child = lock_recover(&self.child);
            let _ = child.kill();
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
}

fn spawn_exit_watcher(child: Arc<Mutex<Child>>, process_tree: Arc<platform::ProcessTree>, config: ExitWatcherConfig) {
    let ExitWatcherConfig {
        root_exited,
        completed,
        emitter,
        wine_session,
        output_readers,
        termination_started,
        keep_alive_after_root_exit,
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
                if let Err(error) = wine_session.wait_until_idle() {
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
                emitter.emit(
                    RuntimeEventKind::Failed,
                    None,
                    None,
                    None,
                    Some("output reader panicked".into()),
                );
            }
        }

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
        completed.store(true, Ordering::Release);
    });
}

fn spawn_timeout_watcher(
    controller: Weak<TerminationController>,
    root_exited: Arc<AtomicBool>,
    keep_alive_after_root_exit: bool,
    maximum_runtime: Duration,
) {
    thread::spawn(move || {
        let deadline = Instant::now() + maximum_runtime;
        while Instant::now() < deadline {
            if (root_exited.load(Ordering::Acquire) && !keep_alive_after_root_exit) || controller.strong_count() == 0 {
                return;
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        if let Some(controller) = controller.upgrade() {
            let _ = controller.request_termination(TerminationReason::Timeout);
        }
    });
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

struct WineSession {
    lifecycle: WineServerLifecycle,
    environment: Vec<(String, String)>,
    working_directory: String,
    stop_started: AtomicBool,
    stop_completed: AtomicBool,
    lease_released: AtomicBool,
}

impl WineSession {
    fn acquire(plan: &LaunchPlan) -> Result<Option<Arc<Self>>, ProcessError> {
        let Some(lifecycle) = plan.lifecycle.wineserver.clone() else {
            return Ok(None);
        };
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
            stop_started: AtomicBool::new(false),
            stop_completed: AtomicBool::new(false),
            lease_released: AtomicBool::new(false),
        })))
    }

    fn stop(&self, emitter: &EventEmitter) -> io::Result<()> {
        if self
            .stop_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            while !self.stop_completed.load(Ordering::Acquire) {
                thread::sleep(PROCESS_POLL_INTERVAL);
            }
            return Ok(());
        }
        emitter.emit(
            RuntimeEventKind::WineServerStopRequested,
            None,
            None,
            None,
            Some(format!("stopping wineserver for prefix {}", self.lifecycle.prefix)),
        );

        // A root/descendant may have already caused wineserver to exit. In
        // that case `-k` returns status 1, while the authoritative `-w`
        // rendezvous succeeds; cleanup is still complete and idempotent.
        let kill_result = self.run_command("-k");
        let wait_result = self.run_command("-w");
        let stop_result = match (kill_result, wait_result) {
            (_, Ok(())) => Ok(()),
            (Ok(()), Err(error)) | (Err(error), Err(_)) => Err(error),
        };
        self.release_lease();
        self.stop_completed.store(true, Ordering::Release);
        stop_result
    }

    /// Wait until the pinned Wine server reports that every process in the
    /// managed prefix has exited. Unlike `stop`, this does not terminate a
    /// normally closing GUI application; an explicit termination request may
    /// still run `stop` concurrently and wake this rendezvous.
    fn wait_until_idle(&self) -> io::Result<()> {
        let mut child = self.spawn_command("-w")?;
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("wineserver -w exited with {status}")))
        }
    }

    fn run_command(&self, argument: &str) -> io::Result<()> {
        let mut child = self.spawn_command(argument)?;
        let deadline = Instant::now() + WINE_SERVER_COMMAND_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!("wineserver {argument} exited with {status}")))
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("wineserver {argument} did not exit within 5 seconds"),
                ));
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }

    fn spawn_command(&self, argument: &str) -> io::Result<Child> {
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
        let mut attempts = 0;
        loop {
            match command.spawn() {
                Ok(child) => return Ok(child),
                Err(error) if is_executable_file_busy(&error) && attempts < EXECUTABLE_BUSY_RETRY_LIMIT => {
                    attempts += 1;
                    thread::sleep(EXECUTABLE_BUSY_RETRY_DELAY);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn release_lease(&self) {
        if !self.lease_released.swap(true, Ordering::AcqRel) {
            let _ = lock_recover(wine_prefix_leases()).remove(&self.lifecycle.prefix);
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
        self.release_lease();
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
    use std::process::{Child, Command};

    const SIGKILL: i32 = 9;
    const SIGTERM: i32 = 15;
    const ESRCH: i32 = 3;

    extern "C" {
        fn kill(process_id: i32, signal: i32) -> i32;
        fn setpgid(process_id: i32, process_group_id: i32) -> i32;
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

    impl ProcessTree {
        pub fn request_graceful(&self) -> io::Result<()> {
            self.send_signal(SIGTERM)
        }

        pub fn force_kill(&self) -> io::Result<()> {
            self.send_signal(SIGKILL)
        }

        fn send_signal(&self, signal: i32) -> io::Result<()> {
            // SAFETY: the negative id targets the process group created for this
            // launch. No Rust memory is shared with the operating system call.
            if unsafe { kill(-self.process_group_id, signal) } == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ESRCH) {
                    return Err(error);
                }
            }
            Ok(())
        }
    }

    impl Drop for ProcessTree {
        fn drop(&mut self) {
            let _ = self.force_kill();
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
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
    fn pinned_command_uses_only_reviewed_wine_start_unix_and_actual_descriptor() {
        let (plan, binding) = pinned_fixture_plan();
        let serialized_before = serde_json::to_string(&plan).unwrap();

        let command = pinned_command_spec(&plan, &binding, 41).unwrap();

        assert_eq!(command.executable, plan.process.executable);
        assert_eq!(command.arguments, ["start.exe", "/unix", "/dev/fd/41"]);
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
            b"#!/bin/sh\nwhile [ ! -f \"$COMPATFORGE_PINNED_GATE\" ]; do :; done\nprintf '%s\\n' \"$@\" > \"$COMPATFORGE_PINNED_ARGUMENTS\"\n/bin/cat \"$3\" > \"$COMPATFORGE_PINNED_OUTPUT\"\n",
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
        while (!output.exists() || !arguments.exists()) && Instant::now() < deadline {
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        let child_arguments = std::fs::read_to_string(&arguments).unwrap();
        let lines = child_arguments.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert_eq!(&lines[..2], ["start.exe", "/unix"]);
        let descriptor = lines[2].strip_prefix("/dev/fd/").unwrap().parse::<i32>().unwrap();
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
        let mut plan = fixture_plan();
        plan.process.environment.insert(
            RUNTIME_EXECUTABLE_DIGEST_ENV.into(),
            format!("sha256:{}", "0".repeat(64)),
        );
        plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            format!("sha256:{}", "0".repeat(64)),
        );
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: plan.process.executable.clone(),
            prefix: format!("runtime-evidence-prefix-{}", std::process::id()),
        });
        assert!(matches!(
            ProcessSupervisor::start(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("runtime executable"))
        ));
    }

    #[test]
    fn refuses_a_tampered_pinned_wineserver_before_spawning() {
        let mut plan = fixture_plan();
        let runtime_digest = sha256_file(Path::new(&plan.process.executable)).unwrap();
        plan.process
            .environment
            .insert(RUNTIME_EXECUTABLE_DIGEST_ENV.into(), runtime_digest);
        plan.process.environment.insert(
            WINESERVER_EXECUTABLE_DIGEST_ENV.into(),
            format!("sha256:{}", "0".repeat(64)),
        );
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: plan.process.executable.clone(),
            prefix: format!("runtime-evidence-prefix-{}", std::process::id()),
        });
        assert!(matches!(
            ProcessSupervisor::start(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("wineserver executable"))
        ));
    }

    #[test]
    fn accepts_complete_fresh_runtime_evidence_and_rejects_incomplete_evidence() {
        let mut plan = fixture_plan();
        let digest = sha256_file(Path::new(&plan.process.executable)).unwrap();
        plan.process
            .environment
            .insert(RUNTIME_EXECUTABLE_DIGEST_ENV.into(), digest.clone());
        assert!(matches!(
            verify_pinned_runtime(&plan),
            Err(ProcessError::InvalidRuntimeEvidence("incomplete Runtime evidence"))
        ));
        plan.process
            .environment
            .insert(WINESERVER_EXECUTABLE_DIGEST_ENV.into(), digest);
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: plan.process.executable.clone(),
            prefix: format!("runtime-evidence-prefix-{}", std::process::id()),
        });
        verify_pinned_runtime(&plan).unwrap();
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
        let mut plan = fixture_plan();
        let prefix = format!("test-prefix-{}", std::process::id());
        plan.lifecycle.wineserver = Some(WineServerLifecycle {
            executable: plan.process.executable.clone(),
            prefix,
        });
        let first = WineSession::acquire(&plan).unwrap().unwrap();
        assert!(matches!(
            WineSession::acquire(&plan),
            Err(ProcessError::WinePrefixBusy(_))
        ));
        drop(first);
        assert!(WineSession::acquire(&plan).unwrap().is_some());
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
        let session = WineSession::acquire(&plan).unwrap().unwrap();
        let (sender, _receiver) = mpsc::channel();
        let emitter = EventEmitter::new("wine-cleanup-test".into(), sender);

        session.stop(&emitter).unwrap();

        let prefix = plan.lifecycle.wineserver.unwrap().prefix;
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
        let session = WineSession::acquire(&plan).unwrap().unwrap();

        session.wait_until_idle().unwrap();

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
            _ => {}
        }
    }
}
