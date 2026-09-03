use crate::{
    valid_version, verify_entrypoint, EvidenceFailure, LinuxProviderConfig, LinuxProviderError, VerifiedEntrypoint,
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COMBINED_OUTPUT_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCommandSpec {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub deadline: Instant,
    pub combined_output_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCommandStatus {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCommandOutput {
    pub status: ProbeCommandStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCommandFailure {
    UnsupportedHost,
    Spawn,
    Deadline,
    OutputLimit,
    Read,
    Wait,
    Status,
    Cleanup,
}

pub trait ProbeCommand {
    /// Runs one exact probe transaction described by an absolute monotonic
    /// deadline and one shared output budget.
    fn run(&self, specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProbeCommand;

#[cfg(not(target_os = "linux"))]
impl ProbeCommand for SystemProbeCommand {
    fn run(&self, _specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
        Err(ProbeCommandFailure::UnsupportedHost)
    }
}

#[cfg(target_os = "linux")]
impl ProbeCommand for SystemProbeCommand {
    fn run(&self, specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
        linux_system_probe::run(specification)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProbeObservation {
    pub wine: PathBuf,
    pub wineserver: PathBuf,
    pub version: String,
}

trait EntrypointVerifier {
    fn verify(&self, materialized_root: &Path, entrypoint: &VerifiedEntrypoint) -> Result<PathBuf, EvidenceFailure>;
}

struct SystemEntrypointVerifier;

impl EntrypointVerifier for SystemEntrypointVerifier {
    fn verify(&self, materialized_root: &Path, entrypoint: &VerifiedEntrypoint) -> Result<PathBuf, EvidenceFailure> {
        verify_entrypoint(materialized_root, entrypoint)
    }
}

pub fn probe_runtime_with(
    config: &LinuxProviderConfig,
    command: &dyn ProbeCommand,
) -> Result<RuntimeProbeObservation, LinuxProviderError> {
    // Task 5 deliberately retains pathname-based Task 4 verification. Running
    // it before and after both commands detects persistent replacement, but it
    // does not claim descriptor-pinned execution or eliminate transient TOCTOU.
    probe_runtime_with_verifier(config, command, &SystemEntrypointVerifier)
}

fn probe_runtime_with_verifier(
    config: &LinuxProviderConfig,
    command: &dyn ProbeCommand,
    verifier: &dyn EntrypointVerifier,
) -> Result<RuntimeProbeObservation, LinuxProviderError> {
    config.validate()?;
    let runtime = &config.wine_runtime;
    let canonical_root =
        std::fs::canonicalize(Path::new(&runtime.materialized_root)).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    if !canonical_root
        .metadata()
        .map_err(|_| EvidenceFailure::MaterializedRoot)?
        .is_dir()
    {
        return Err(EvidenceFailure::MaterializedRoot.into());
    }

    let wine = verifier.verify(&canonical_root, &runtime.wine)?;
    let wineserver = verifier.verify(&canonical_root, &runtime.wineserver)?;

    let wine_output = run_version_command(command, &wine, &canonical_root)?;
    let wine_version = parse_wine_version(&wine_output.stdout, &wine_output.stderr, &runtime.version)?;
    let wineserver_output = run_version_command(command, &wineserver, &canonical_root)?;
    let wineserver_version =
        parse_wineserver_version(&wineserver_output.stdout, &wineserver_output.stderr, &runtime.version)?;
    if wine_version != wineserver_version {
        return Err(EvidenceFailure::Version.into());
    }

    let wine_after = verifier.verify(&canonical_root, &runtime.wine)?;
    let wineserver_after = verifier.verify(&canonical_root, &runtime.wineserver)?;
    if wine_after != wine || wineserver_after != wineserver {
        return Err(EvidenceFailure::Digest.into());
    }

    Ok(RuntimeProbeObservation {
        wine,
        wineserver,
        version: wine_version,
    })
}

fn run_version_command(
    command: &dyn ProbeCommand,
    executable: &Path,
    working_directory: &Path,
) -> Result<ProbeCommandOutput, LinuxProviderError> {
    if !executable.is_absolute() || !working_directory.is_absolute() || !executable.starts_with(working_directory) {
        return Err(EvidenceFailure::Command.into());
    }
    let specification = ProbeCommandSpec {
        executable: executable.to_owned(),
        arguments: vec![OsString::from("--version")],
        working_directory: working_directory.to_owned(),
        environment: BTreeMap::from([
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("WINEDEBUG"), OsString::from("-all")),
        ]),
        deadline: Instant::now() + PROBE_TIMEOUT,
        combined_output_limit: MAX_COMBINED_OUTPUT_BYTES,
    };
    let output = match command.run(&specification) {
        Ok(output) => output,
        Err(ProbeCommandFailure::UnsupportedHost) => return Err(LinuxProviderError::UnsupportedHost),
        Err(_) => return Err(EvidenceFailure::Command.into()),
    };
    if Instant::now() >= specification.deadline {
        return Err(EvidenceFailure::Command.into());
    }
    let output_too_large = match output.stdout.len().checked_add(output.stderr.len()) {
        Some(length) => length > specification.combined_output_limit,
        None => true,
    };
    if output.status != ProbeCommandStatus::Success || output_too_large {
        return Err(EvidenceFailure::Command.into());
    }
    Ok(output)
}

fn parse_wine_version(stdout: &[u8], stderr: &[u8], declared: &str) -> Result<String, EvidenceFailure> {
    parse_version_output(stdout, stderr, b"wine-", declared)
}

fn parse_wineserver_version(stdout: &[u8], stderr: &[u8], declared: &str) -> Result<String, EvidenceFailure> {
    parse_version_output(stderr, stdout, b"Wine ", declared)
}

fn parse_version_output(
    required_stream: &[u8],
    forbidden_stream: &[u8],
    prefix: &[u8],
    declared: &str,
) -> Result<String, EvidenceFailure> {
    if !forbidden_stream.is_empty() || !valid_version(declared) {
        return Err(EvidenceFailure::Version);
    }

    let content = required_stream
        .strip_suffix(b"\r\n")
        .or_else(|| required_stream.strip_suffix(b"\n"))
        .unwrap_or(required_stream);
    let mut expected = Vec::with_capacity(prefix.len() + declared.len());
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(declared.as_bytes());
    if content == expected {
        Ok(declared.to_owned())
    } else {
        Err(EvidenceFailure::Version)
    }
}

#[cfg(target_os = "linux")]
mod linux_system_probe {
    use super::*;
    use crate::unix_process_group::ProcessGroup;
    use std::{
        io::Read,
        process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
        sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
        thread::{self, JoinHandle},
    };

    const READ_CHUNK_BYTES: usize = 8 * 1024;
    const EVENT_QUEUE_DEPTH: usize = 4;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);
    const MAX_CLEANUP_RESERVE: Duration = Duration::from_millis(250);

    #[derive(Clone, Copy)]
    enum OutputStream {
        Stdout,
        Stderr,
    }

    enum ReaderEvent {
        Bytes(OutputStream, Vec<u8>),
        Finished(OutputStream),
        Failed(OutputStream),
    }

    struct Readers {
        handles: Vec<JoinHandle<()>>,
        receiver: Receiver<ReaderEvent>,
    }

    impl Readers {
        fn finished(&self) -> bool {
            self.handles.iter().all(JoinHandle::is_finished)
        }
    }

    struct Capture {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        stdout_finished: bool,
        stderr_finished: bool,
        total_observed: usize,
        limit: usize,
    }

    impl Capture {
        fn new(limit: usize) -> Self {
            Self {
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_finished: false,
                stderr_finished: false,
                total_observed: 0,
                limit,
            }
        }

        fn process(&mut self, event: ReaderEvent) -> Result<(), ProbeCommandFailure> {
            match event {
                ReaderEvent::Bytes(stream, bytes) => {
                    let detection_limit = self.limit.checked_add(1).ok_or(ProbeCommandFailure::OutputLimit)?;
                    let remaining = detection_limit.saturating_sub(self.total_observed);
                    let retained = remaining.min(bytes.len());
                    match stream {
                        OutputStream::Stdout => self.stdout.extend_from_slice(&bytes[..retained]),
                        OutputStream::Stderr => self.stderr.extend_from_slice(&bytes[..retained]),
                    }
                    self.total_observed += retained;
                    if retained < bytes.len() || self.total_observed > self.limit {
                        Err(ProbeCommandFailure::OutputLimit)
                    } else {
                        Ok(())
                    }
                }
                ReaderEvent::Finished(OutputStream::Stdout) => {
                    self.stdout_finished = true;
                    Ok(())
                }
                ReaderEvent::Finished(OutputStream::Stderr) => {
                    self.stderr_finished = true;
                    Ok(())
                }
                ReaderEvent::Failed(stream) => {
                    match stream {
                        OutputStream::Stdout => self.stdout_finished = true,
                        OutputStream::Stderr => self.stderr_finished = true,
                    }
                    Err(ProbeCommandFailure::Read)
                }
            }
        }

        fn finished(&self) -> bool {
            self.stdout_finished && self.stderr_finished
        }
    }

    pub(super) fn run(specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
        validate_specification(specification)?;
        let started_at = Instant::now();
        if started_at >= specification.deadline {
            return Err(ProbeCommandFailure::Deadline);
        }
        let available = specification.deadline.saturating_duration_since(started_at);
        // Cleanup is part of the caller's one absolute deadline. Reserving a
        // bounded tail lets SIGKILL, root reaping, pipe closure, and group
        // absence complete without resetting or extending that deadline.
        let cleanup_reserve = MAX_CLEANUP_RESERVE.min(available / 2);
        let operation_deadline = specification
            .deadline
            .checked_sub(cleanup_reserve)
            .unwrap_or(started_at);

        let mut command = Command::new(&specification.executable);
        command
            .args(&specification.arguments)
            .current_dir(&specification.working_directory)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &specification.environment {
            command.env(name, value);
        }
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);

        let mut child = command.spawn().map_err(|_| ProbeCommandFailure::Spawn)?;
        let group = match ProcessGroup::for_child(&child) {
            Ok(group) => group,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                return cleanup_without_readers(&mut child, &group, specification.deadline, ProbeCommandFailure::Read)
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                return cleanup_without_readers(&mut child, &group, specification.deadline, ProbeCommandFailure::Read)
            }
        };
        let (readers, startup_failed) = start_readers(stdout, stderr);
        if startup_failed {
            cleanup(&mut child, &group, &readers, specification.deadline)?;
            finish_readers(readers, specification.deadline)?;
            return Err(ProbeCommandFailure::Read);
        }
        supervise(
            &mut child,
            &group,
            readers,
            Capture::new(specification.combined_output_limit),
            operation_deadline,
            specification.deadline,
        )
    }

    fn validate_specification(specification: &ProbeCommandSpec) -> Result<(), ProbeCommandFailure> {
        let expected_environment = BTreeMap::from([
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("WINEDEBUG"), OsString::from("-all")),
        ]);
        if !specification.executable.is_absolute()
            || !specification.working_directory.is_absolute()
            || specification.arguments != [OsString::from("--version")]
            || specification.environment != expected_environment
            || specification.combined_output_limit != MAX_COMBINED_OUTPUT_BYTES
        {
            return Err(ProbeCommandFailure::Spawn);
        }
        let executable = std::fs::canonicalize(&specification.executable).map_err(|_| ProbeCommandFailure::Spawn)?;
        let working_directory =
            std::fs::canonicalize(&specification.working_directory).map_err(|_| ProbeCommandFailure::Spawn)?;
        if executable != specification.executable
            || working_directory != specification.working_directory
            || !executable.starts_with(&working_directory)
            || !executable.metadata().map_err(|_| ProbeCommandFailure::Spawn)?.is_file()
            || !working_directory
                .metadata()
                .map_err(|_| ProbeCommandFailure::Spawn)?
                .is_dir()
        {
            return Err(ProbeCommandFailure::Spawn);
        }
        Ok(())
    }

    fn start_readers(stdout: ChildStdout, stderr: ChildStderr) -> (Readers, bool) {
        // Two fixed-size reader buffers plus this bounded queue cap transient
        // allocations. Capture itself retains no more than limit + 1 bytes.
        let (sender, receiver) = mpsc::sync_channel(EVENT_QUEUE_DEPTH);
        let stdout_sender = sender.clone();
        let stdout = thread::Builder::new()
            .name("compatforge-probe-stdout".into())
            .spawn(move || read_pipe(stdout, OutputStream::Stdout, stdout_sender));
        let stderr = thread::Builder::new()
            .name("compatforge-probe-stderr".into())
            .spawn(move || read_pipe(stderr, OutputStream::Stderr, sender));
        let startup_failed = stdout.is_err() || stderr.is_err();
        let handles = stdout.into_iter().chain(stderr).collect();
        (Readers { handles, receiver }, startup_failed)
    }

    fn read_pipe(mut pipe: impl Read, stream: OutputStream, sender: SyncSender<ReaderEvent>) {
        let mut buffer = [0_u8; READ_CHUNK_BYTES];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(ReaderEvent::Finished(stream));
                    return;
                }
                Ok(read) => {
                    if sender
                        .send(ReaderEvent::Bytes(stream, buffer[..read].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = sender.send(ReaderEvent::Failed(stream));
                    return;
                }
            }
        }
    }

    fn supervise(
        child: &mut Child,
        group: &ProcessGroup,
        readers: Readers,
        mut capture: Capture,
        operation_deadline: Instant,
        absolute_deadline: Instant,
    ) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
        let mut status: Option<ExitStatus> = None;
        let primary_failure = loop {
            if let Err(error) = drain_available_events(&readers.receiver, &mut capture) {
                break error;
            }
            if status.is_none() {
                status = match child.try_wait() {
                    Ok(status) => status,
                    Err(_) => break ProbeCommandFailure::Wait,
                };
                if status.as_ref().is_some_and(|status| !status.success()) {
                    break ProbeCommandFailure::Status;
                }
            }
            if status.is_some() && capture.finished() {
                if Instant::now() >= absolute_deadline {
                    break ProbeCommandFailure::Deadline;
                }
                let group_absent = match group.is_absent() {
                    Ok(absent) => absent,
                    Err(_) => break ProbeCommandFailure::Cleanup,
                };
                if group_absent {
                    finish_readers(readers, absolute_deadline)?;
                    if Instant::now() >= absolute_deadline {
                        return Err(ProbeCommandFailure::Deadline);
                    }
                    return Ok(ProbeCommandOutput {
                        status: ProbeCommandStatus::Success,
                        stdout: capture.stdout,
                        stderr: capture.stderr,
                    });
                }
                break ProbeCommandFailure::Cleanup;
            }
            if Instant::now() >= operation_deadline {
                break ProbeCommandFailure::Deadline;
            }
            match readers.receiver.recv_timeout(wait_interval(operation_deadline)) {
                Ok(event) => {
                    if let Err(error) = capture.process(event) {
                        break error;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) if !capture.finished() => {
                    break ProbeCommandFailure::Read;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {}
            }
        };

        cleanup(child, group, &readers, absolute_deadline)?;
        finish_readers(readers, absolute_deadline)?;
        Err(primary_failure)
    }

    fn drain_available_events(
        receiver: &Receiver<ReaderEvent>,
        capture: &mut Capture,
    ) -> Result<(), ProbeCommandFailure> {
        loop {
            match receiver.try_recv() {
                Ok(event) => capture.process(event)?,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) if capture.finished() => return Ok(()),
                Err(TryRecvError::Disconnected) => return Err(ProbeCommandFailure::Read),
            }
        }
    }

    fn cleanup(
        child: &mut Child,
        group: &ProcessGroup,
        readers: &Readers,
        deadline: Instant,
    ) -> Result<(), ProbeCommandFailure> {
        let group_signal_succeeded = group.force_kill().is_ok();
        if !group_signal_succeeded {
            let _ = child.kill();
        }
        let mut root_reaped = false;
        loop {
            for _ in 0..(EVENT_QUEUE_DEPTH * 2) {
                if readers.receiver.try_recv().is_err() {
                    break;
                }
            }
            if !root_reaped {
                if let Ok(status) = child.try_wait() {
                    root_reaped = status.is_some();
                }
            }
            let group_absent = group.is_absent().unwrap_or(false);
            if root_reaped && group_absent && readers.finished() {
                return if group_signal_succeeded {
                    Ok(())
                } else {
                    Err(ProbeCommandFailure::Cleanup)
                };
            }
            if Instant::now() >= deadline {
                return Err(ProbeCommandFailure::Cleanup);
            }
            thread::sleep(wait_interval(deadline));
        }
    }

    fn cleanup_without_readers(
        child: &mut Child,
        group: &ProcessGroup,
        deadline: Instant,
        primary_failure: ProbeCommandFailure,
    ) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
        let group_signal_succeeded = group.force_kill().is_ok();
        if !group_signal_succeeded {
            let _ = child.kill();
        }
        loop {
            let root_reaped = child.try_wait().ok().flatten().is_some();
            let group_absent = group.is_absent().unwrap_or(false);
            if root_reaped && group_absent {
                return if group_signal_succeeded {
                    Err(primary_failure)
                } else {
                    Err(ProbeCommandFailure::Cleanup)
                };
            }
            if Instant::now() >= deadline {
                return Err(ProbeCommandFailure::Cleanup);
            }
            thread::sleep(wait_interval(deadline));
        }
    }

    fn finish_readers(readers: Readers, deadline: Instant) -> Result<(), ProbeCommandFailure> {
        while !readers.finished() && Instant::now() < deadline {
            thread::sleep(wait_interval(deadline));
        }
        if !readers.finished() {
            return Err(ProbeCommandFailure::Cleanup);
        }
        for handle in readers.handles {
            handle.join().map_err(|_| ProbeCommandFailure::Read)?;
        }
        Ok(())
    }

    fn wait_interval(deadline: Instant) -> Duration {
        POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VerifiedEntrypoint, WineRuntimeConfig};
    use compatforge_domain::CpuArchitecture;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::Path,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex,
        },
    };

    static NEXT_PROBE_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[cfg(windows)]
    fn windows_volume(path: &Path) -> Option<u8> {
        use std::path::{Component, Prefix};

        match path.components().next()? {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => Some(drive.to_ascii_uppercase()),
                _ => None,
            },
            _ => None,
        }
    }

    #[cfg(windows)]
    fn windows_probe_fixture_candidates_for_base(
        target_directory: Option<&std::ffi::OsStr>,
        test_executable: &Path,
        resolution_base: &Path,
        unique_name: &str,
    ) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        let resolution_volume =
            windows_volume(resolution_base).expect("Windows serialized-path resolution base must have a disk volume");
        if let Some(target_directory) = target_directory {
            let target_directory = PathBuf::from(target_directory);
            if target_directory.is_absolute()
                && target_directory.parent().is_some()
                && windows_volume(&target_directory) == Some(resolution_volume)
            {
                candidates.push(target_directory.join("test-fixtures").join(unique_name));
            }
        }
        if windows_volume(test_executable) == Some(resolution_volume) {
            let executable_fallback = test_executable
                .parent()
                .expect("current test executable must have a parent")
                .join("compatforge-test-fixtures")
                .join(unique_name);
            if !candidates.contains(&executable_fallback) {
                candidates.push(executable_fallback);
            }
        } else {
            let workspace_fallback = resolution_base
                .parent()
                .expect("Windows serialized-path resolution base must not be a drive root")
                .join(".compatforge-test-fixtures")
                .join(unique_name);
            candidates.push(workspace_fallback);
        }
        candidates
    }

    #[cfg(windows)]
    fn create_windows_probe_fixture_base(
        target_directory: Option<&std::ffi::OsStr>,
        test_executable: &Path,
        resolution_base: &Path,
        unique_name: &str,
    ) -> PathBuf {
        windows_probe_fixture_candidates_for_base(target_directory, test_executable, resolution_base, unique_name)
            .into_iter()
            .find(|candidate| fs::create_dir_all(candidate).is_ok())
            .expect("create probe fixture in target or same-drive fallback")
    }

    fn system_probe_helper_paths(working_directory: &Path, name: &str) -> (PathBuf, PathBuf) {
        (
            working_directory.join(format!("{name}.c")),
            working_directory.join(name),
        )
    }

    #[derive(Clone, Copy)]
    enum Parser {
        Wine,
        Wineserver,
    }

    struct VersionOutput {
        name: &'static str,
        parser: Parser,
        stdout: &'static [u8],
        stderr: &'static [u8],
        declared: &'static str,
    }

    impl VersionOutput {
        fn parse(&self) -> Result<String, super::super::EvidenceFailure> {
            match self.parser {
                Parser::Wine => parse_wine_version(self.stdout, self.stderr, self.declared),
                Parser::Wineserver => parse_wineserver_version(self.stdout, self.stderr, self.declared),
            }
        }
    }

    fn invalid_version_outputs() -> Vec<VersionOutput> {
        vec![
            VersionOutput {
                name: "wine output on stderr",
                parser: Parser::Wine,
                stdout: b"",
                stderr: b"wine-11.0\n",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver output on stdout",
                parser: Parser::Wineserver,
                stdout: b"Wine 11.0\n",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine extra blank line",
                parser: Parser::Wine,
                stdout: b"wine-11.0\n\n",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver extra nonblank line",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"Wine 11.0\nextra",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine leading space",
                parser: Parser::Wine,
                stdout: b" wine-11.0\n",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver trailing space",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"Wine 11.0 \n",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine ambiguous prefix case",
                parser: Parser::Wine,
                stdout: b"Wine-11.0\n",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver ambiguous prefix case",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"wine 11.0\n",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine valid but different declared version",
                parser: Parser::Wine,
                stdout: b"wine-11.1\n",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver valid but different declared version",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"Wine 10.0\n",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine invalid utf-8",
                parser: Parser::Wine,
                stdout: b"wine-11.0\xff",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver invalid utf-8",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"Wine 11.0\xff",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine embedded nul",
                parser: Parser::Wine,
                stdout: b"wine-11\0.0",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver embedded nul",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"Wine 11\0.0",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine more than one terminal newline",
                parser: Parser::Wine,
                stdout: b"wine-11.0\r\n\n",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver more than one terminal newline",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"Wine 11.0\r\n\r\n",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine output in both streams",
                parser: Parser::Wine,
                stdout: b"wine-11.0\n",
                stderr: b"diagnostic",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver output in both streams",
                parser: Parser::Wineserver,
                stdout: b"diagnostic",
                stderr: b"Wine 11.0\n",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine required stream empty",
                parser: Parser::Wine,
                stdout: b"",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver required stream empty",
                parser: Parser::Wineserver,
                stdout: b"",
                stderr: b"",
                declared: "11.0",
            },
            VersionOutput {
                name: "wine forbidden stream nonempty",
                parser: Parser::Wine,
                stdout: b"wine-11.0",
                stderr: b" ",
                declared: "11.0",
            },
            VersionOutput {
                name: "wineserver forbidden stream nonempty",
                parser: Parser::Wineserver,
                stdout: b" ",
                stderr: b"Wine 11.0",
                declared: "11.0",
            },
        ]
    }

    struct ProbeFixture {
        base: PathBuf,
        root: PathBuf,
        config: LinuxProviderConfig,
    }

    impl ProbeFixture {
        fn new() -> Self {
            let sequence = NEXT_PROBE_FIXTURE.fetch_add(1, Ordering::Relaxed);
            #[cfg(windows)]
            let base = {
                let unique_name = format!("compatforge-linux-probe-{}-{sequence}", std::process::id());
                let executable = std::env::current_exe().expect("resolve current probe test executable");
                let resolution_base = std::env::current_dir().expect("resolve Windows serialized-path base");
                create_windows_probe_fixture_base(
                    std::env::var_os("CARGO_TARGET_DIR").as_deref(),
                    &executable,
                    &resolution_base,
                    &unique_name,
                )
            };
            #[cfg(not(windows))]
            let base = std::env::temp_dir().join(format!("compatforge-linux-probe-{}-{sequence}", std::process::id()));
            let root = base.join("runtime");
            fs::create_dir_all(root.join("bin")).expect("create probe fixture");
            let wine = write_test_entrypoint(&root.join("bin/wine"), 2);
            let wineserver = write_test_entrypoint(&root.join("bin/wineserver"), 3);
            let materialized_root = serialized_linux_test_path(&root);
            Self {
                base,
                root,
                config: LinuxProviderConfig {
                    schema_version: "1".into(),
                    runtime_store_root: "/runtime-store".into(),
                    wine_runtime: WineRuntimeConfig {
                        provider_id: "linux-wine".into(),
                        pack_id: "wine-linux-x86_64".into(),
                        pack_digest: format!("sha256:{}", "a".repeat(64)),
                        version: "11.0".into(),
                        architecture: CpuArchitecture::X86_64,
                        materialized_root,
                        wine: VerifiedEntrypoint {
                            path: "bin/wine".into(),
                            digest: wine,
                        },
                        wineserver: VerifiedEntrypoint {
                            path: "bin/wineserver".into(),
                            digest: wineserver,
                        },
                        capabilities: vec!["guest-x86_64".into()],
                        wined3d_capabilities: vec!["opengl".into()],
                    },
                },
            }
        }
    }

    impl Drop for ProbeFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.base).expect("remove probe fixture");
        }
    }

    fn serialized_linux_test_path(path: &Path) -> String {
        let value = path.to_string_lossy().replace('\\', "/");
        #[cfg(windows)]
        let value = {
            let bytes = value.as_bytes();
            assert!(bytes.get(1) == Some(&b':'), "Windows fixture must have a drive prefix");
            value[2..].to_owned()
        };
        value
    }

    fn write_test_entrypoint(path: &Path, object_type: u16) -> String {
        let mut bytes = [0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&object_type.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        fs::write(path, bytes).expect("write probe fixture entrypoint");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(path).expect("probe entrypoint metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("make probe entrypoint executable");
        }
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    #[derive(Debug, Clone, Copy)]
    enum ScriptedBehavior {
        Success,
        CommandError,
        UnsupportedHost,
        LateSuccess,
        NonZero,
        InvalidWineStream,
        InvalidWineserverStream,
        WineVersionMismatch,
        WineserverVersionMismatch,
    }

    #[derive(Debug, Clone)]
    struct RecordedCall {
        specification: ProbeCommandSpec,
        observed_at: Instant,
    }

    struct RecordingProbeCommand {
        behavior: ScriptedBehavior,
        mutate_after_first: Option<PathBuf>,
        calls: Mutex<Vec<RecordedCall>>,
    }

    impl RecordingProbeCommand {
        fn successful() -> Self {
            Self {
                behavior: ScriptedBehavior::Success,
                mutate_after_first: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn scripted(behavior: ScriptedBehavior) -> Self {
            Self {
                behavior,
                mutate_after_first: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn mutating(path: PathBuf) -> Self {
            Self {
                behavior: ScriptedBehavior::Success,
                mutate_after_first: Some(path),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<RecordedCall> {
            self.calls.lock().expect("recording command lock").clone()
        }
    }

    impl ProbeCommand for RecordingProbeCommand {
        fn run(&self, specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
            let mut calls = self.calls.lock().expect("recording command lock");
            let call_index = calls.len();
            calls.push(RecordedCall {
                specification: specification.clone(),
                observed_at: Instant::now(),
            });
            if call_index == 0 {
                if let Some(path) = &self.mutate_after_first {
                    use std::io::Write as _;

                    let mut file = fs::OpenOptions::new()
                        .append(true)
                        .open(path)
                        .expect("open entrypoint for persistent mutation");
                    file.write_all(b"persistent-mutation")
                        .expect("persistently mutate entrypoint");
                }
            }
            if matches!(self.behavior, ScriptedBehavior::CommandError) {
                return Err(ProbeCommandFailure::Spawn);
            }
            if matches!(self.behavior, ScriptedBehavior::UnsupportedHost) {
                return Err(ProbeCommandFailure::UnsupportedHost);
            }
            if matches!(self.behavior, ScriptedBehavior::LateSuccess) && call_index == 0 {
                std::thread::sleep(
                    specification.deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(20),
                );
            }

            let status = if matches!(self.behavior, ScriptedBehavior::NonZero) {
                ProbeCommandStatus::Failure
            } else {
                ProbeCommandStatus::Success
            };
            let (stdout, stderr) = match call_index {
                0 if matches!(self.behavior, ScriptedBehavior::InvalidWineStream) => {
                    (b"wine-11.0\n".to_vec(), b"unexpected".to_vec())
                }
                0 if matches!(self.behavior, ScriptedBehavior::WineVersionMismatch) => {
                    (b"wine-10.0\n".to_vec(), Vec::new())
                }
                0 => (b"wine-11.0\n".to_vec(), Vec::new()),
                1 if matches!(self.behavior, ScriptedBehavior::InvalidWineserverStream) => {
                    (b"unexpected".to_vec(), b"Wine 11.0\n".to_vec())
                }
                1 if matches!(self.behavior, ScriptedBehavior::WineserverVersionMismatch) => {
                    (Vec::new(), b"Wine 10.0\n".to_vec())
                }
                1 => (Vec::new(), b"Wine 11.0\n".to_vec()),
                _ => panic!("unexpected extra probe command"),
            };
            Ok(ProbeCommandOutput { status, stdout, stderr })
        }
    }

    struct RecordingEntrypointVerifier {
        calls: Mutex<Vec<(PathBuf, String)>>,
    }

    impl RecordingEntrypointVerifier {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl EntrypointVerifier for RecordingEntrypointVerifier {
        fn verify(
            &self,
            materialized_root: &Path,
            entrypoint: &VerifiedEntrypoint,
        ) -> Result<PathBuf, EvidenceFailure> {
            self.calls
                .lock()
                .expect("recording verifier lock")
                .push((materialized_root.to_owned(), entrypoint.path.clone()));
            verify_entrypoint(materialized_root, entrypoint)
        }
    }

    #[test]
    fn release_version_streams_are_exact_and_distinct() {
        for terminator in [b"".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
            let mut wine = b"wine-11.0".to_vec();
            wine.extend_from_slice(terminator);
            assert_eq!(parse_wine_version(&wine, b"", "11.0").unwrap(), "11.0");

            let mut wineserver = b"Wine 11.0".to_vec();
            wineserver.extend_from_slice(terminator);
            assert_eq!(parse_wineserver_version(b"", &wineserver, "11.0").unwrap(), "11.0");
        }

        for output in invalid_version_outputs() {
            assert!(output.parse().is_err(), "{}", output.name);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_probe_fixture_fallback_tracks_the_resolution_volume() {
        let resolution_base = Path::new(r"L:\project\FOS\.worktrees\provider-preview");
        let unique = "missing-target-env";

        let same_volume = windows_probe_fixture_candidates_for_base(
            None,
            Path::new(r"L:\cargo-target\debug\deps\probe-tests.exe"),
            resolution_base,
            unique,
        );
        assert_eq!(
            same_volume,
            [PathBuf::from(
                r"L:\cargo-target\debug\deps\compatforge-test-fixtures\missing-target-env"
            )]
        );
        for rejected_target in [r"relative\target", r"L:\"] {
            assert_eq!(
                windows_probe_fixture_candidates_for_base(
                    Some(std::ffi::OsStr::new(rejected_target)),
                    Path::new(r"L:\cargo-target\debug\deps\probe-tests.exe"),
                    resolution_base,
                    unique,
                ),
                same_volume,
                "reject unsafe target candidate {rejected_target}"
            );
        }

        let cross_volume = windows_probe_fixture_candidates_for_base(
            None,
            Path::new(r"G:\cargo-target\debug\deps\probe-tests.exe"),
            resolution_base,
            unique,
        );
        assert_eq!(
            cross_volume,
            [PathBuf::from(
                r"L:\project\FOS\.worktrees\.compatforge-test-fixtures\missing-target-env"
            )]
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_probe_fixture_falls_back_when_target_directory_is_unusable() {
        let executable = std::env::current_exe().expect("resolve current test executable");
        let holder = executable.parent().expect("test executable parent").join(format!(
            "compatforge-fixture-selection-{}-{}",
            std::process::id(),
            NEXT_PROBE_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&holder).expect("create fixture selection holder");
        let blocked_target = holder.join("blocked-target");
        fs::write(&blocked_target, b"not a directory").expect("create unusable target marker");
        let fake_executable = holder.join("probe-tests.exe");
        let selected = create_windows_probe_fixture_base(
            Some(blocked_target.as_os_str()),
            &fake_executable,
            &holder,
            "fallback-case",
        );
        assert_eq!(selected, holder.join("compatforge-test-fixtures").join("fallback-case"));
        fs::remove_dir_all(&holder).expect("remove fixture selection holder");
    }

    #[cfg(windows)]
    #[test]
    fn windows_probe_fixture_rejects_cross_volume_target_and_executable() {
        let candidates = windows_probe_fixture_candidates_for_base(
            Some(std::ffi::OsStr::new(r"G:\compatforge-task05-cross-drive-review")),
            Path::new(r"G:\cargo-target\debug\deps\probe-tests.exe"),
            Path::new(r"L:\project\FOS\.worktrees\provider-preview"),
            "cross-volume-case",
        );
        assert_eq!(
            candidates,
            [PathBuf::from(
                r"L:\project\FOS\.worktrees\.compatforge-test-fixtures\cross-volume-case"
            )]
        );
    }

    #[test]
    fn system_probe_helper_paths_are_inside_the_working_directory() {
        let working_directory = Path::new("canonical-runtime-root");
        let (source, executable) = system_probe_helper_paths(working_directory, "wine-helper");
        assert_eq!(source, working_directory.join("wine-helper.c"));
        assert_eq!(executable, working_directory.join("wine-helper"));
        assert!(source.starts_with(working_directory));
        assert!(executable.starts_with(working_directory));
    }

    #[test]
    fn probe_command_is_exact_bounded_and_rehashed() {
        let fixture = ProbeFixture::new();
        let command = RecordingProbeCommand::successful();
        let observation = probe_runtime_with(&fixture.config, &command).expect("valid exact probes");
        let canonical_root = fs::canonicalize(&fixture.root).expect("canonical fixture root");
        assert_eq!(observation.wine, canonical_root.join("bin/wine"));
        assert_eq!(observation.wineserver, canonical_root.join("bin/wineserver"));
        assert_eq!(observation.version, "11.0");

        let calls = command.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].specification.executable, canonical_root.join("bin/wine"));
        assert_eq!(calls[1].specification.executable, canonical_root.join("bin/wineserver"));
        let expected_arguments = vec![OsString::from("--version")];
        let expected_environment = BTreeMap::from([
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("WINEDEBUG"), OsString::from("-all")),
        ]);
        for call in &calls {
            assert_eq!(call.specification.arguments, expected_arguments);
            assert_eq!(call.specification.working_directory, canonical_root);
            assert_eq!(call.specification.environment, expected_environment);
            assert_eq!(call.specification.combined_output_limit, 65_536);
            assert!(
                call.specification
                    .executable
                    .starts_with(&call.specification.working_directory),
                "canonical executable must remain inside canonical cwd"
            );
            let remaining = call.specification.deadline.saturating_duration_since(call.observed_at);
            assert!(
                remaining > Duration::from_secs(4),
                "deadline was not five seconds ahead"
            );
            assert!(remaining <= Duration::from_secs(5), "deadline exceeded five seconds");
        }
        assert!(calls[1].specification.deadline >= calls[0].specification.deadline);

        let verifying_command = RecordingProbeCommand::successful();
        let verifier = RecordingEntrypointVerifier::new();
        probe_runtime_with_verifier(&fixture.config, &verifying_command, &verifier)
            .expect("four digest-bound verifications");
        assert_eq!(
            *verifier.calls.lock().expect("recording verifier lock"),
            [
                (canonical_root.clone(), "bin/wine".into()),
                (canonical_root.clone(), "bin/wineserver".into()),
                (canonical_root.clone(), "bin/wine".into()),
                (canonical_root.clone(), "bin/wineserver".into()),
            ]
        );

        for relative in ["bin/wine", "bin/wineserver"] {
            let mutated = ProbeFixture::new();
            let command = RecordingProbeCommand::mutating(mutated.root.join(relative));
            let error = probe_runtime_with(&mutated.config, &command).unwrap_err();
            assert_eq!(error, LinuxProviderError::Evidence(EvidenceFailure::Digest));
            assert_eq!(command.calls().len(), 2, "mutation must be detected after both probes");
        }

        for (behavior, expected) in [
            (
                ScriptedBehavior::CommandError,
                LinuxProviderError::Evidence(EvidenceFailure::Command),
            ),
            (
                ScriptedBehavior::NonZero,
                LinuxProviderError::Evidence(EvidenceFailure::Command),
            ),
            (
                ScriptedBehavior::InvalidWineStream,
                LinuxProviderError::Evidence(EvidenceFailure::Version),
            ),
            (
                ScriptedBehavior::InvalidWineserverStream,
                LinuxProviderError::Evidence(EvidenceFailure::Version),
            ),
            (
                ScriptedBehavior::WineVersionMismatch,
                LinuxProviderError::Evidence(EvidenceFailure::Version),
            ),
            (
                ScriptedBehavior::WineserverVersionMismatch,
                LinuxProviderError::Evidence(EvidenceFailure::Version),
            ),
        ] {
            let rejected = ProbeFixture::new();
            let command = RecordingProbeCommand::scripted(behavior);
            let error = probe_runtime_with(&rejected.config, &command).unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("persistent-mutation"));
            assert!(!error.to_string().contains(&rejected.root.to_string_lossy().to_string()));
        }
    }

    #[test]
    fn injected_probe_rejects_success_returned_after_its_absolute_deadline() {
        let fixture = ProbeFixture::new();
        let command = RecordingProbeCommand::scripted(ScriptedBehavior::LateSuccess);
        assert_eq!(
            probe_runtime_with(&fixture.config, &command),
            Err(LinuxProviderError::Evidence(EvidenceFailure::Command))
        );
        assert_eq!(command.calls().len(), 1, "late first probe must stop the transaction");
    }

    #[test]
    fn injected_unsupported_host_preserves_the_provider_error_category() {
        let fixture = ProbeFixture::new();
        let command = RecordingProbeCommand::scripted(ScriptedBehavior::UnsupportedHost);
        assert_eq!(
            probe_runtime_with(&fixture.config, &command),
            Err(LinuxProviderError::UnsupportedHost)
        );
        assert_eq!(command.calls().len(), 1);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn system_probe_command_is_unsupported_before_spawn_off_linux() {
        let specification = ProbeCommandSpec {
            executable: PathBuf::from("definitely-not-a-real-executable"),
            arguments: vec![OsString::from("--version")],
            working_directory: PathBuf::from("definitely-not-a-real-directory"),
            environment: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(5),
            combined_output_limit: 65_536,
        };
        assert_eq!(
            SystemProbeCommand.run(&specification),
            Err(ProbeCommandFailure::UnsupportedHost)
        );
    }

    #[cfg(target_os = "linux")]
    mod system_tests {
        use super::*;
        use std::{
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        struct LinuxSystemFixture {
            base: PathBuf,
            working_directory: PathBuf,
        }

        impl LinuxSystemFixture {
            fn new(name: &str) -> Self {
                let sequence = NEXT_PROBE_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let base = std::env::temp_dir().join(format!(
                    "compatforge-linux-system-probe-{name}-{}-{sequence}",
                    std::process::id()
                ));
                let working_directory = base.join("cwd");
                fs::create_dir_all(&working_directory).expect("create Linux system probe fixture");
                let base = fs::canonicalize(base).expect("canonical Linux system probe fixture");
                let working_directory = base.join("cwd");
                Self {
                    base,
                    working_directory,
                }
            }

            fn compile(&self, name: &str, body: &str) -> PathBuf {
                let (source, executable) = system_probe_helper_paths(&self.working_directory, name);
                assert!(source.starts_with(&self.working_directory));
                assert!(executable.starts_with(&self.working_directory));
                fs::write(&source, body).expect("write controlled Linux probe helper source");
                let status = Command::new("/usr/bin/cc")
                    .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-o"])
                    .arg(&executable)
                    .arg(&source)
                    .env_clear()
                    .env("LANG", "C")
                    .env("LC_ALL", "C")
                    .status()
                    .expect("run explicit system C compiler");
                assert!(status.success(), "controlled Linux probe helper must compile");
                executable
            }

            fn marker(&self, name: &str) -> PathBuf {
                self.base.join(name)
            }
        }

        impl Drop for LinuxSystemFixture {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.base).expect("remove Linux system probe fixture");
            }
        }

        fn c_literal(path: &Path) -> String {
            path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
        }

        fn system_specification(
            executable: PathBuf,
            working_directory: &Path,
            lifetime: Duration,
            limit: usize,
        ) -> ProbeCommandSpec {
            ProbeCommandSpec {
                executable,
                arguments: vec![OsString::from("--version")],
                working_directory: working_directory.to_owned(),
                environment: BTreeMap::from([
                    (OsString::from("LANG"), OsString::from("C")),
                    (OsString::from("LC_ALL"), OsString::from("C")),
                    (OsString::from("WINEDEBUG"), OsString::from("-all")),
                ]),
                deadline: Instant::now() + lifetime,
                combined_output_limit: limit,
            }
        }

        fn output_helper_source(stdout_bytes: usize, stderr_bytes: usize) -> String {
            format!(
                r#"#include <stdio.h>
int main(int argc, char **argv) {{
    (void)argc;
    (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    for (size_t index = 0; index < {stdout_bytes}; ++index) {{ fputc('o', stdout); }}
    for (size_t index = 0; index < {stderr_bytes}; ++index) {{ fputc('e', stderr); }}
    return 0;
}}
"#
            )
        }

        fn process_tree_source(marker: &Path, parent_exits: bool, flood: bool) -> String {
            let parent_action = if parent_exits {
                "return 0;"
            } else {
                "for (;;) { pause(); }"
            };
            let flood_action = if flood {
                "char bytes[4096] = {0}; for (;;) { (void)write(1, bytes, sizeof(bytes)); }"
            } else {
                parent_action
            };
            format!(
                r#"#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char **argv) {{
    (void)argc;
    (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t root = getpid();
    pid_t descendant = fork();
    if (descendant < 0) {{ return 91; }}
    if (descendant == 0) {{ for (;;) {{ pause(); }} }}
    FILE *marker = fopen("{}", "w");
    if (marker == NULL) {{ return 92; }}
    fprintf(marker, "%ld\n%ld\n", (long)root, (long)descendant);
    if (fclose(marker) != 0) {{ return 93; }}
    {flood_action}
}}
"#,
                c_literal(marker)
            )
        }

        fn read_process_ids(marker: &Path) -> (i32, i32) {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(contents) = fs::read_to_string(marker) {
                    let mut lines = contents.lines();
                    let root = lines
                        .next()
                        .expect("root pid")
                        .parse::<i32>()
                        .expect("numeric root pid");
                    let descendant = lines
                        .next()
                        .expect("descendant pid")
                        .parse::<i32>()
                        .expect("numeric descendant pid");
                    return (root, descendant);
                }
                assert!(Instant::now() < deadline, "controlled helper did not write pid marker");
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn assert_tree_absent(root: i32, descendant: i32) {
            assert!(
                !Path::new(&format!("/proc/{root}")).exists(),
                "root child was not reaped"
            );
            assert!(
                !Path::new(&format!("/proc/{descendant}")).exists(),
                "probe descendant survived cleanup"
            );
            assert!(
                crate::unix_process_group::group_is_absent(root).expect("query controlled process group"),
                "controlled probe process group survived cleanup"
            );
        }

        #[test]
        fn system_probe_enforces_exact_argv_cwd_and_environment() {
            let fixture = LinuxSystemFixture::new("exact-contract");
            let source = format!(
                r#"#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv) {{
    if (argc != 2 || strcmp(argv[1], "--version") != 0) {{ return 41; }}
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "{}") != 0) {{ return 42; }}
    int count = 0;
    while (environ[count] != NULL) {{ ++count; }}
    if (count != 3) {{ return 43; }}
    if (getenv("LANG") == NULL || strcmp(getenv("LANG"), "C") != 0) {{ return 44; }}
    if (getenv("LC_ALL") == NULL || strcmp(getenv("LC_ALL"), "C") != 0) {{ return 45; }}
    if (getenv("WINEDEBUG") == NULL || strcmp(getenv("WINEDEBUG"), "-all") != 0) {{ return 46; }}
    fputs("wine-11.0\n", stdout);
    return 0;
}}
"#,
                c_literal(&fixture.working_directory)
            );
            let executable = fixture.compile("exact-contract", &source);
            let output = SystemProbeCommand
                .run(&system_specification(
                    executable,
                    &fixture.working_directory,
                    Duration::from_secs(2),
                    65_536,
                ))
                .expect("exact controlled command must pass");
            assert_eq!(output.status, ProbeCommandStatus::Success);
            assert_eq!(output.stdout, b"wine-11.0\n");
            assert!(output.stderr.is_empty());
        }

        #[test]
        fn system_probe_combines_streams_under_one_exact_output_budget() {
            let fixture = LinuxSystemFixture::new("shared-budget");
            let exact = fixture.compile("exact-budget", &output_helper_source(32_768, 32_768));
            let output = SystemProbeCommand
                .run(&system_specification(
                    exact,
                    &fixture.working_directory,
                    Duration::from_secs(2),
                    65_536,
                ))
                .expect("exact shared cap must succeed");
            assert_eq!(output.stdout.len() + output.stderr.len(), 65_536);

            let overflow = fixture.compile("over-budget", &output_helper_source(32_768, 32_769));
            assert_eq!(
                SystemProbeCommand.run(&system_specification(
                    overflow,
                    &fixture.working_directory,
                    Duration::from_secs(2),
                    65_536,
                )),
                Err(ProbeCommandFailure::OutputLimit)
            );
        }

        #[test]
        fn system_probe_rejects_a_no_newline_flood_at_cap_plus_one() {
            let fixture = LinuxSystemFixture::new("no-newline-flood");
            let executable = fixture.compile("no-newline-flood", &output_helper_source(65_537, 0));
            assert_eq!(
                SystemProbeCommand.run(&system_specification(
                    executable,
                    &fixture.working_directory,
                    Duration::from_secs(2),
                    65_536,
                )),
                Err(ProbeCommandFailure::OutputLimit)
            );
        }

        #[test]
        fn system_probe_kills_a_forked_pipe_holder_without_waiting_forever() {
            let fixture = LinuxSystemFixture::new("pipe-holder");
            let marker = fixture.marker("pids");
            let executable = fixture.compile("pipe-holder", &process_tree_source(&marker, true, false));
            let result = SystemProbeCommand.run(&system_specification(
                executable,
                &fixture.working_directory,
                Duration::from_secs(1),
                65_536,
            ));
            assert_eq!(result, Err(ProbeCommandFailure::Deadline));
            let (root, descendant) = read_process_ids(&marker);
            assert_tree_absent(root, descendant);
        }

        #[test]
        fn system_probe_timeout_kills_reaps_and_removes_the_process_group() {
            let fixture = LinuxSystemFixture::new("timeout-tree");
            let marker = fixture.marker("pids");
            let executable = fixture.compile("timeout-tree", &process_tree_source(&marker, false, false));
            let result = SystemProbeCommand.run(&system_specification(
                executable,
                &fixture.working_directory,
                Duration::from_secs(1),
                65_536,
            ));
            assert_eq!(result, Err(ProbeCommandFailure::Deadline));
            let (root, descendant) = read_process_ids(&marker);
            assert_tree_absent(root, descendant);
        }

        #[test]
        fn system_probe_overflow_kills_reaps_and_removes_the_process_group() {
            let fixture = LinuxSystemFixture::new("overflow-tree");
            let marker = fixture.marker("pids");
            let executable = fixture.compile("overflow-tree", &process_tree_source(&marker, false, true));
            let result = SystemProbeCommand.run(&system_specification(
                executable,
                &fixture.working_directory,
                Duration::from_secs(2),
                65_536,
            ));
            assert_eq!(result, Err(ProbeCommandFailure::OutputLimit));
            let (root, descendant) = read_process_ids(&marker);
            assert_tree_absent(root, descendant);
        }

        #[test]
        fn system_probe_rejects_nonzero_and_signalled_status_without_details() {
            let fixture = LinuxSystemFixture::new("status");
            let nonzero = fixture.compile("nonzero", "int main(void) { return 73; }\n");
            let signalled = fixture.compile(
                "signalled",
                "#include <signal.h>\nint main(void) { return raise(SIGTERM); }\n",
            );
            for executable in [nonzero, signalled] {
                let error = SystemProbeCommand
                    .run(&system_specification(
                        executable,
                        &fixture.working_directory,
                        Duration::from_secs(2),
                        65_536,
                    ))
                    .unwrap_err();
                assert_eq!(error, ProbeCommandFailure::Status);
                assert!(!format!("{error:?}").contains("73"));
                assert!(!format!("{error:?}").contains("SIGTERM"));
            }
        }
    }
}
