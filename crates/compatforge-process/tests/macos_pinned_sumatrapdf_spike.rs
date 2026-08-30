use std::io::Read;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

trait PhaseDriver {
    fn capture(&mut self) -> Result<(), &'static str>;
    fn prepare(&mut self) -> Result<(), &'static str>;
    fn authorize(&mut self) -> Result<(), &'static str>;
    fn start(&mut self) -> Result<(), &'static str>;
    fn mutate_source(&mut self) -> Result<(), &'static str>;
    fn observe_captured_window(&mut self) -> Result<(), &'static str>;
    fn revalidate_source(&mut self) -> Result<(), &'static str>;
    fn terminate_managed(&mut self) -> Result<(), &'static str>;
    fn require_clean(&mut self) -> Result<(), &'static str>;
}

trait WindowProbeProcess {
    fn try_wait_success(&mut self) -> Result<Option<bool>, &'static str>;
    fn kill(&mut self) -> Result<(), &'static str>;
    fn wait(&mut self) -> Result<(), &'static str>;
}

trait WindowProbeBudget {
    fn probe_time_remaining(&mut self) -> bool;
    fn cleanup_time_remaining(&mut self) -> bool;
    fn pause_probe(&mut self);
    fn pause_cleanup(&mut self);
}

fn supervise_window_probe(
    process: &mut impl WindowProbeProcess,
    budget: &mut impl WindowProbeBudget,
) -> Result<bool, &'static str> {
    supervise_window_probe_with_output_guard(process, budget, || Ok(()))
}

fn supervise_window_probe_with_output_guard(
    process: &mut impl WindowProbeProcess,
    budget: &mut impl WindowProbeBudget,
    mut output_guard: impl FnMut() -> Result<(), &'static str>,
) -> Result<bool, &'static str> {
    if let Err(failure) = output_guard() {
        return stop_window_probe(process, budget, failure, false);
    }
    if !budget.probe_time_remaining() {
        return stop_window_probe(process, budget, "window probe timed out", false);
    }
    loop {
        let poll = process.try_wait_success();
        if let Err(failure) = output_guard() {
            return stop_window_probe(process, budget, failure, matches!(poll, Ok(Some(_))));
        }
        if !budget.probe_time_remaining() {
            return stop_window_probe(process, budget, "window probe timed out", matches!(poll, Ok(Some(_))));
        }
        match poll {
            Ok(Some(success)) => return Ok(success),
            Ok(None) => {}
            Err(_) => return stop_window_probe(process, budget, "window probe failed", false),
        }
        budget.pause_probe();
        if !budget.probe_time_remaining() {
            return stop_window_probe(process, budget, "window probe timed out", false);
        }
    }
}

fn start_window_probe_output<T>(
    process: &mut impl WindowProbeProcess,
    budget: &mut impl WindowProbeBudget,
    start: impl FnOnce() -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    match start() {
        Ok(output) => Ok(output),
        Err(failure) => match stop_window_probe(process, budget, failure, false) {
            Err(cleanup_or_failure) => Err(cleanup_or_failure),
            Ok(_) => Err(failure),
        },
    }
}

impl WindowProbeProcess for Child {
    fn try_wait_success(&mut self) -> Result<Option<bool>, &'static str> {
        self.try_wait()
            .map(|status| status.map(|status| status.success()))
            .map_err(|_| "window probe failed")
    }

    fn kill(&mut self) -> Result<(), &'static str> {
        Child::kill(self).map_err(|_| "window probe cleanup failed")
    }

    fn wait(&mut self) -> Result<(), &'static str> {
        Child::wait(self).map(|_| ()).map_err(|_| "window probe cleanup failed")
    }
}

struct BoundedPipeCapture {
    receiver: Receiver<Result<Vec<u8>, &'static str>>,
    reader: Option<JoinHandle<()>>,
    result: Option<Result<Vec<u8>, &'static str>>,
    cancel: Arc<AtomicBool>,
}

impl BoundedPipeCapture {
    fn start(input: impl Read + Send + 'static, maximum: usize) -> Result<Self, &'static str> {
        Self::start_with_mode(input, maximum, false)
    }

    fn start_cancellable(input: impl Read + Send + 'static, maximum: usize) -> Result<Self, &'static str> {
        Self::start_with_mode(input, maximum, true)
    }

    #[cfg(target_os = "macos")]
    fn start_child_stdout(input: std::process::ChildStdout, maximum: usize) -> Result<Self, &'static str> {
        use std::os::fd::AsRawFd;

        let descriptor = input.as_raw_fd();
        // SAFETY: fcntl only queries and updates status flags on this live, owned pipe descriptor.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0 {
            return Err("window probe output is unavailable");
        }
        // SAFETY: the descriptor remains owned by input and O_NONBLOCK is a valid additive status flag.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err("window probe output is unavailable");
        }
        Self::start_cancellable(input, maximum)
    }

    fn start_with_mode(
        mut input: impl Read + Send + 'static,
        maximum: usize,
        cancellable: bool,
    ) -> Result<Self, &'static str> {
        let bound = maximum.checked_add(1).ok_or("window probe output is invalid")?;
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = Arc::clone(&cancel);
        let reader = thread::Builder::new()
            .name("compatforge-window-probe-output".to_owned())
            .spawn(move || {
                let result = (|| {
                    let mut bytes = Vec::new();
                    let mut buffer = [0_u8; 65_536];
                    loop {
                        if reader_cancel.load(Ordering::Acquire) {
                            return Err("window probe cleanup failed");
                        }
                        let remaining = bound - bytes.len();
                        let read_size = remaining.min(buffer.len());
                        match input.read(&mut buffer[..read_size]) {
                            Ok(0) => return Ok(bytes),
                            Ok(count) => {
                                bytes.extend_from_slice(&buffer[..count]);
                                if bytes.len() > maximum {
                                    return Err("window probe output is invalid");
                                }
                            }
                            Err(error) if cancellable && error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(std::time::Duration::from_millis(1));
                            }
                            Err(_) => return Err("window probe output is invalid"),
                        }
                    }
                })();
                let _send_result = sender.send(result);
            })
            .map_err(|_| "window probe output is unavailable")?;
        Ok(Self {
            receiver,
            reader: Some(reader),
            result: None,
            cancel,
        })
    }

    fn check(&mut self) -> Result<(), &'static str> {
        if self.result.is_none() {
            match self.receiver.try_recv() {
                Ok(result) => self.result = Some(result),
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    self.result = Some(Err("window probe cleanup failed"));
                }
            }
        }
        match self.result.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(failure)) => Err(*failure),
            None => Ok(()),
        }
    }

    fn finish_until(&mut self, deadline: Instant) -> Result<Vec<u8>, &'static str> {
        if self.result.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.receiver.recv_timeout(remaining) {
                Ok(result) => self.result = Some(result),
                Err(RecvTimeoutError::Timeout) => {
                    self.cancel.store(true, Ordering::Release);
                    if !self.join_reader() {
                        return Err("window probe cleanup failed");
                    }
                    return Err("window probe cleanup failed");
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.result = Some(Err("window probe cleanup failed"));
                }
            }
        }
        if !self.join_reader() {
            return Err("window probe cleanup failed");
        }
        self.result.take().ok_or("window probe cleanup failed")?
    }

    fn join_reader(&mut self) -> bool {
        match self.reader.take() {
            Some(reader) => reader.join().is_ok(),
            None => true,
        }
    }

    fn reader_joined(&self) -> bool {
        self.reader.is_none()
    }
}

impl Drop for BoundedPipeCapture {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        let _joined = self.join_reader();
    }
}

fn stop_window_probe(
    process: &mut impl WindowProbeProcess,
    budget: &mut impl WindowProbeBudget,
    failure: &'static str,
    already_ready: bool,
) -> Result<bool, &'static str> {
    if already_ready {
        return if process.wait().is_err() {
            Err("window probe cleanup failed")
        } else {
            Err(failure)
        };
    }

    let mut cleanup_failed = process.kill().is_err();
    if !budget.cleanup_time_remaining() {
        return Err("window probe cleanup failed");
    }
    loop {
        match process.try_wait_success() {
            Ok(Some(_)) => {
                cleanup_failed |= process.wait().is_err();
                return if cleanup_failed {
                    Err("window probe cleanup failed")
                } else {
                    Err(failure)
                };
            }
            Ok(None) => {}
            Err(_) => cleanup_failed = true,
        }
        if !budget.cleanup_time_remaining() {
            return Err("window probe cleanup failed");
        }
        budget.pause_cleanup();
        if !budget.cleanup_time_remaining() {
            return Err("window probe cleanup failed");
        }
    }
}

fn run_spike_phase(driver: &mut impl PhaseDriver, mutate_after_start: bool) -> Result<(), &'static str> {
    driver.capture()?;
    driver.prepare()?;
    driver.authorize()?;
    driver.start()?;

    let phase_result = (|| {
        if mutate_after_start {
            driver.mutate_source()?;
        }
        driver.observe_captured_window()?;
        match (mutate_after_start, driver.revalidate_source()) {
            (false, result) => result,
            (true, Err(_integrity_error)) => Ok(()),
            (true, Ok(())) => Err("source mutation was not rejected"),
        }
    })();
    let termination_result = driver.terminate_managed();
    let cleanup_result = driver.require_clean();
    cleanup_result.and(termination_result).and(phase_result)
}

#[cfg(target_os = "macos")]
mod real {
    use super::{
        run_spike_phase, start_window_probe_output, supervise_window_probe_with_output_guard, BoundedPipeCapture,
        PhaseDriver, WindowProbeBudget,
    };
    use compatforge_domain::{CoreConfig, CpuArchitecture, ExecutableMode, LaunchRequest};
    use compatforge_guest_artifact::{GuestArtifactStore, HeldExternalWorkRoot, PinnedBottleExecutable};
    use compatforge_orchestrator::PreparedLaunch;
    use compatforge_process::{LaunchHandle, ProcessSupervisor};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const INPUT_VARIABLE: &str = "COMPATFORGE_PINNED_SPIKE_INPUT";
    const MAX_INPUT_BYTES: u64 = 134_217_728;
    const MAX_MANIFEST_BYTES: u64 = 1_048_576;
    const WINDOW_TIMEOUT: Duration = Duration::from_secs(60);
    const WINDOW_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
    const WINDOW_PROBE_CLEANUP_RESERVE: Duration = Duration::from_secs(1);
    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);
    const MAX_WINDOW_OUTPUT_BYTES: u64 = 1_048_576;

    #[derive(Clone)]
    struct BoundFile {
        path: PathBuf,
        identity: (u64, u64),
        size: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
        digest: String,
        bytes: Vec<u8>,
    }

    #[derive(Clone)]
    struct FileReference {
        path: PathBuf,
        digest: String,
    }

    #[derive(Clone)]
    struct RuntimeRecord {
        config: FileReference,
        logical_executable: FileReference,
        mutation_payload: FileReference,
        request: FileReference,
        work_root: PathBuf,
    }

    struct Manifest {
        cli: FileReference,
        runtimes: Vec<RuntimeRecord>,
    }

    struct RealPhase {
        config: CoreConfig,
        request: LaunchRequest,
        source: BoundFile,
        mutation: BoundFile,
        work_path: PathBuf,
        raw_work_root: File,
        work_root: Option<HeldExternalWorkRoot>,
        pinned: Option<PinnedBottleExecutable>,
        prepared: Option<PreparedLaunch>,
        handle: Option<LaunchHandle>,
        mutated: bool,
    }

    impl RealPhase {
        fn new(record: &RuntimeRecord, files: &BTreeMap<PathBuf, BoundFile>) -> Result<Self, &'static str> {
            let config_file = files.get(&record.config.path).ok_or("config binding missing")?;
            let request_file = files.get(&record.request.path).ok_or("request binding missing")?;
            let source = files
                .get(&record.logical_executable.path)
                .ok_or("source binding missing")?
                .clone();
            let mutation = files
                .get(&record.mutation_payload.path)
                .ok_or("mutation binding missing")?
                .clone();
            let config: CoreConfig = serde_json::from_slice(&config_file.bytes).map_err(|_| "config is invalid")?;
            let request: LaunchRequest =
                serde_json::from_slice(&request_file.bytes).map_err(|_| "request is invalid")?;
            config.validate().map_err(|_| "config is invalid")?;
            request.validate().map_err(|_| "request is invalid")?;
            if request.request_id != "pinned-sumatrapdf"
                || request.bottle_id != "gui-sumatrapdf"
                || request.executable.mode != ExecutableMode::BottleInPlace
                || request.executable.architecture != CpuArchitecture::X86_64
                || Path::new(&request.executable.path) != source.path
                || !request.arguments.is_empty()
                || request.environment.contains_key("PATH")
                || config.runtime_bindings.len() != 1
                || config.runtime_bindings[0].environment.contains_key("PATH")
                || source.digest == mutation.digest
            {
                return Err("closed pinned contract is invalid");
            }
            let storage_root = closed_absolute(Path::new(&config.storage_root))?;
            let expected_source = storage_root
                .join("bottles")
                .join("gui-sumatrapdf")
                .join("prefix")
                .join("drive_c")
                .join("CompatForge")
                .join("SumatraPDF")
                .join("SumatraPDF.exe");
            if expected_source != source.path {
                return Err("fixed source path is invalid");
            }
            let work_path = canonical_directory(&record.work_root)?;
            let raw_work_root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&work_path)
                .map_err(|_| "work root could not be held")?;
            Ok(Self {
                config,
                request,
                source,
                mutation,
                work_path,
                raw_work_root,
                work_root: None,
                pinned: None,
                prepared: None,
                handle: None,
                mutated: false,
            })
        }

        fn pinned(&self) -> Result<&PinnedBottleExecutable, &'static str> {
            self.pinned.as_ref().ok_or("pinned lease missing")
        }

        fn prepared(&self) -> Result<&PreparedLaunch, &'static str> {
            self.prepared.as_ref().ok_or("prepared launch missing")
        }

        fn restore_source(&self) -> Result<(), &'static str> {
            let current = bind_file(&self.source.path, None, MAX_INPUT_BYTES)?;
            if current.identity != self.source.identity {
                return Err("mutated source identity changed");
            }
            overwrite_bound(&current, &self.source.bytes)?;
            let restored = bind_file(&self.source.path, Some(&self.source.digest), MAX_INPUT_BYTES)?;
            if restored.identity != self.source.identity {
                return Err("restored source identity changed");
            }
            Ok(())
        }
    }

    impl PhaseDriver for RealPhase {
        fn capture(&mut self) -> Result<(), &'static str> {
            self.source.revalidate()?;
            self.mutation.revalidate()?;
            let storage_root = PathBuf::from(&self.config.storage_root);
            let bottle_root = storage_root.join("bottles").join("gui-sumatrapdf");
            let mut forbidden = vec![
                storage_root,
                bottle_root,
                self.source.path.clone(),
                self.mutation.path.clone(),
            ];
            for binding in &self.config.runtime_bindings {
                forbidden.push(runtime_parent(&binding.executable)?);
                if let Some(wineserver) = &binding.wineserver_executable {
                    forbidden.push(runtime_parent(wineserver)?);
                }
                if let Some(working_directory) = &binding.working_directory {
                    forbidden.push(closed_absolute(Path::new(working_directory))?);
                }
                for value in binding.environment.values().chain(self.request.environment.values()) {
                    if value.starts_with('/') {
                        forbidden.push(closed_absolute(Path::new(value))?);
                    }
                }
            }
            forbidden.sort();
            forbidden.dedup();
            let references = forbidden.iter().map(PathBuf::as_path).collect::<Vec<_>>();
            let work_root =
                HeldExternalWorkRoot::duplicate_inherited(self.raw_work_root.as_raw_fd(), &self.work_path, &references)
                    .map_err(|_| "work root binding failed")?;
            let pinned = GuestArtifactStore::new(&self.config.storage_root)
                .pin_sumatra_bottle_executable("gui-sumatrapdf", &self.source.path, &work_root)
                .map_err(|_| "source capture failed")?;
            if pinned.binding().digest != self.source.digest {
                return Err("captured digest disagrees");
            }
            self.work_root = Some(work_root);
            self.pinned = Some(pinned);
            Ok(())
        }

        fn prepare(&mut self) -> Result<(), &'static str> {
            let prepared = PreparedLaunch::prepare_pinned_bottle(&self.config, &self.request, self.pinned()?)
                .map_err(|_| "pinned prepare failed")?;
            self.prepared = Some(prepared);
            Ok(())
        }

        fn authorize(&mut self) -> Result<(), &'static str> {
            self.prepared()?
                .authorize_pinned(&self.config, self.pinned()?)
                .map_err(|_| "pinned authorize failed")?;
            Ok(())
        }

        fn start(&mut self) -> Result<(), &'static str> {
            if window_visible(Instant::now() + WINDOW_PROBE_TIMEOUT)? {
                return Err("matching window already exists");
            }
            let handle = ProcessSupervisor::start_pinned_bottle(self.prepared()?.plan(), self.pinned()?)
                .map_err(|_| "pinned process start failed")?;
            self.handle = Some(handle);
            Ok(())
        }

        fn mutate_source(&mut self) -> Result<(), &'static str> {
            self.source.revalidate()?;
            self.mutated = true;
            overwrite_bound(&self.source, &self.mutation.bytes)?;
            let changed = bind_file(&self.source.path, Some(&self.mutation.digest), MAX_INPUT_BYTES)?;
            if changed.identity != self.source.identity {
                return Err("source mutation changed identity");
            }
            Ok(())
        }

        fn observe_captured_window(&mut self) -> Result<(), &'static str> {
            let handle = self.handle.as_ref().ok_or("managed handle missing")?;
            let deadline = Instant::now() + WINDOW_TIMEOUT;
            while Instant::now() < deadline {
                if handle.is_finished() {
                    return Err("managed process exited before window observation");
                }
                if window_visible(deadline)? {
                    return Ok(());
                }
                sleep_before(deadline, Duration::from_millis(250));
            }
            Err("SumatraPDF window was not observed")
        }

        fn revalidate_source(&mut self) -> Result<(), &'static str> {
            self.pinned()?.revalidate().map_err(|_| "source integrity changed")
        }

        fn terminate_managed(&mut self) -> Result<(), &'static str> {
            self.handle
                .as_ref()
                .ok_or("managed handle missing")?
                .terminate_and_wait(CLEANUP_TIMEOUT)
                .map_err(|_| "managed termination failed")
        }

        fn require_clean(&mut self) -> Result<(), &'static str> {
            let handle = self.handle.as_ref().ok_or("managed handle missing")?;
            handle
                .terminate_and_wait(CLEANUP_TIMEOUT)
                .map_err(|_| "managed cleanup failed")?;
            if !handle.is_finished() {
                return Err("managed process remains live");
            }
            let deadline = Instant::now() + CLEANUP_TIMEOUT;
            loop {
                if Instant::now() >= deadline {
                    return Err("SumatraPDF window remains after cleanup");
                }
                if !window_visible(deadline)? {
                    break;
                }
                sleep_before(deadline, Duration::from_millis(100));
            }
            if self.mutated {
                self.restore_source()?;
            } else {
                self.source.revalidate()?;
            }
            self.work_root
                .as_ref()
                .ok_or("work root missing")?
                .revalidate()
                .map_err(|_| "work root changed")
        }
    }

    impl BoundFile {
        fn revalidate(&self) -> Result<(), &'static str> {
            let current = bind_file(&self.path, Some(&self.digest), MAX_INPUT_BYTES)?;
            if current.identity != self.identity
                || current.size != self.size
                || current.modified_seconds != self.modified_seconds
                || current.modified_nanoseconds != self.modified_nanoseconds
                || current.changed_seconds != self.changed_seconds
                || current.changed_nanoseconds != self.changed_nanoseconds
            {
                return Err("bound input identity changed");
            }
            Ok(())
        }
    }

    pub(super) fn run() -> Result<(), &'static str> {
        let manifest_argument = std::env::var_os(INPUT_VARIABLE).ok_or("spike manifest variable is missing")?;
        let manifest_path = canonical_file(Path::new(&manifest_argument))?;
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("repository root is invalid")?
            .canonicalize()
            .map_err(|_| "repository root is invalid")?;
        if paths_overlap(&manifest_path, &repository_root) {
            return Err("spike manifest is not repository-external");
        }
        let manifest_binding = bind_file(&manifest_path, None, MAX_MANIFEST_BYTES)?;
        let manifest = parse_manifest(&manifest_binding.bytes)?;
        let mut references = vec![manifest.cli.clone()];
        for runtime in &manifest.runtimes {
            references.extend([
                runtime.config.clone(),
                runtime.logical_executable.clone(),
                runtime.mutation_payload.clone(),
                runtime.request.clone(),
            ]);
        }
        let mut files: BTreeMap<PathBuf, BoundFile> = BTreeMap::new();
        for reference in references {
            match files.get(&reference.path) {
                Some(existing) if existing.digest != reference.digest => {
                    return Err("duplicate input digest disagrees");
                }
                Some(_) => {}
                None => {
                    files.insert(
                        reference.path.clone(),
                        bind_file(&reference.path, Some(&reference.digest), MAX_INPUT_BYTES)?,
                    );
                }
            }
        }
        validate_roots(&manifest, &files, &repository_root)?;

        for runtime in &manifest.runtimes {
            let mut stable = RealPhase::new(runtime, &files)?;
            run_spike_phase(&mut stable, false)?;
            revalidate_non_source_inputs(&manifest_binding, &files, &runtime.logical_executable.path)?;

            let fresh_source = bind_file(
                &runtime.logical_executable.path,
                Some(&runtime.logical_executable.digest),
                MAX_INPUT_BYTES,
            )?;
            files.insert(runtime.logical_executable.path.clone(), fresh_source);
            let mut mutation = RealPhase::new(runtime, &files)?;
            run_spike_phase(&mut mutation, true)?;
            revalidate_non_source_inputs(&manifest_binding, &files, &runtime.logical_executable.path)?;
            let restored = bind_file(
                &runtime.logical_executable.path,
                Some(&runtime.logical_executable.digest),
                MAX_INPUT_BYTES,
            )?;
            files.insert(runtime.logical_executable.path.clone(), restored);
        }
        Ok(())
    }

    fn revalidate_non_source_inputs(
        manifest: &BoundFile,
        files: &BTreeMap<PathBuf, BoundFile>,
        source: &Path,
    ) -> Result<(), &'static str> {
        manifest.revalidate()?;
        for binding in files.values().filter(|binding| binding.path != source) {
            binding.revalidate()?;
        }
        Ok(())
    }

    fn validate_roots(
        manifest: &Manifest,
        files: &BTreeMap<PathBuf, BoundFile>,
        repository_root: &Path,
    ) -> Result<(), &'static str> {
        let mut work_roots: Vec<PathBuf> = Vec::new();
        for runtime in &manifest.runtimes {
            let work_root = canonical_directory(&runtime.work_root)?;
            if paths_overlap(&work_root, repository_root)
                || files.keys().any(|path| paths_overlap(&work_root, path))
                || work_roots.iter().any(|path| paths_overlap(&work_root, path))
            {
                return Err("work root overlap is invalid");
            }
            let config: CoreConfig =
                serde_json::from_slice(&files[&runtime.config.path].bytes).map_err(|_| "config is invalid")?;
            let mut protected = vec![PathBuf::from(&config.storage_root)];
            for binding in &config.runtime_bindings {
                protected.push(runtime_parent(&binding.executable)?);
                if let Some(wineserver) = &binding.wineserver_executable {
                    protected.push(runtime_parent(wineserver)?);
                }
            }
            if protected.iter().any(|path| paths_overlap(&work_root, path)) {
                return Err("work root overlaps Runtime or storage");
            }
            work_roots.push(work_root);
        }
        Ok(())
    }

    fn parse_manifest(bytes: &[u8]) -> Result<Manifest, &'static str> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "manifest JSON is invalid")?;
        if serde_json::to_vec(&value).map_err(|_| "manifest JSON is invalid")? != bytes {
            return Err("manifest JSON is not canonical");
        }
        let root = exact_object(
            &value,
            &[
                "cli",
                "runtimes",
                "schemaVersion",
                "timeoutMilliseconds",
                "windowTitleTokens",
            ],
        )?;
        if root["schemaVersion"] != 1
            || root["timeoutMilliseconds"] != 60_000
            || root["windowTitleTokens"] != serde_json::json!(["SumatraPDF"])
        {
            return Err("manifest constants are invalid");
        }
        let cli = parse_reference(&root["cli"])?;
        if cli.path.file_name().and_then(|name| name.to_str()) != Some("compatforge-cli") {
            return Err("CLI artifact is invalid");
        }
        let runtimes = root["runtimes"].as_array().ok_or("Runtime list is invalid")?;
        if runtimes.len() != 2 {
            return Err("Runtime list is invalid");
        }
        let mut parsed = Vec::new();
        for (index, expected) in ["crossover", "whisky"].iter().enumerate() {
            let record = exact_object(
                &runtimes[index],
                &[
                    "config",
                    "logicalExecutable",
                    "mutationPayload",
                    "request",
                    "runtimeId",
                    "workRoot",
                ],
            )?;
            if record["runtimeId"].as_str() != Some(expected) {
                return Err("Runtime order is invalid");
            }
            let logical_executable = parse_reference(&record["logicalExecutable"])?;
            let expected_suffix = Path::new("bottles")
                .join("gui-sumatrapdf")
                .join("prefix")
                .join("drive_c")
                .join("CompatForge")
                .join("SumatraPDF")
                .join("SumatraPDF.exe");
            if !logical_executable.path.ends_with(expected_suffix) {
                return Err("logical executable path is invalid");
            }
            parsed.push(RuntimeRecord {
                config: parse_reference(&record["config"])?,
                logical_executable,
                mutation_payload: parse_reference(&record["mutationPayload"])?,
                request: parse_reference(&record["request"])?,
                work_root: closed_absolute(Path::new(record["workRoot"].as_str().ok_or("work root is invalid")?))?,
            });
        }
        Ok(Manifest { cli, runtimes: parsed })
    }

    fn exact_object<'a>(
        value: &'a serde_json::Value,
        keys: &[&str],
    ) -> Result<&'a serde_json::Map<String, serde_json::Value>, &'static str> {
        let object = value.as_object().ok_or("manifest object is invalid")?;
        let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected = keys.iter().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            return Err("manifest object shape is invalid");
        }
        Ok(object)
    }

    fn parse_reference(value: &serde_json::Value) -> Result<FileReference, &'static str> {
        let reference = exact_object(value, &["path", "sha256"])?;
        let digest = reference["sha256"].as_str().ok_or("input digest is invalid")?;
        if digest.len() != 71
            || !digest.starts_with("sha256:")
            || !digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("input digest is invalid");
        }
        Ok(FileReference {
            path: closed_absolute(Path::new(reference["path"].as_str().ok_or("input path is invalid")?))?,
            digest: digest.to_owned(),
        })
    }

    fn bind_file(path: &Path, expected_digest: Option<&str>, maximum: u64) -> Result<BoundFile, &'static str> {
        let canonical = canonical_file(path)?;
        if canonical != path {
            return Err("input path is not canonical");
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "input open failed")?;
        let before = file.metadata().map_err(|_| "input metadata failed")?;
        let entry = path.symlink_metadata().map_err(|_| "input metadata failed")?;
        let identity = (before.dev(), before.ino());
        if !before.is_file()
            || before.file_type().is_symlink()
            || entry.file_type().is_symlink()
            || before.nlink() != 1
            || entry.nlink() != 1
            || identity != (entry.dev(), entry.ino())
            || before.len() == 0
            || before.len() > maximum
        {
            return Err("input identity is invalid");
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "input read failed")?;
        let after = file.metadata().map_err(|_| "input metadata failed")?;
        let current = path.symlink_metadata().map_err(|_| "input metadata failed")?;
        let digest = digest_bytes(&bytes);
        if bytes.len() as u64 != before.len()
            || (after.dev(), after.ino()) != identity
            || (current.dev(), current.ino()) != identity
            || after.len() != before.len()
            || current.len() != before.len()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
            || current.mtime() != before.mtime()
            || current.mtime_nsec() != before.mtime_nsec()
            || after.ctime() != before.ctime()
            || after.ctime_nsec() != before.ctime_nsec()
            || current.ctime() != before.ctime()
            || current.ctime_nsec() != before.ctime_nsec()
            || after.nlink() != 1
            || current.nlink() != 1
            || expected_digest.is_some_and(|expected| expected != digest)
        {
            return Err("input binding changed");
        }
        Ok(BoundFile {
            path: path.to_owned(),
            identity,
            size: before.len(),
            modified_seconds: before.mtime(),
            modified_nanoseconds: before.mtime_nsec(),
            changed_seconds: before.ctime(),
            changed_nanoseconds: before.ctime_nsec(),
            digest,
            bytes,
        })
    }

    fn overwrite_bound(binding: &BoundFile, bytes: &[u8]) -> Result<(), &'static str> {
        binding.revalidate()?;
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&binding.path)
            .map_err(|_| "source overwrite open failed")?;
        let opened = file.metadata().map_err(|_| "source overwrite metadata failed")?;
        if (opened.dev(), opened.ino()) != binding.identity || opened.nlink() != 1 {
            return Err("source overwrite identity changed");
        }
        file.set_len(0).map_err(|_| "source truncate failed")?;
        file.write_all(bytes).map_err(|_| "source overwrite failed")?;
        file.sync_all().map_err(|_| "source overwrite sync failed")
    }

    fn canonical_file(path: &Path) -> Result<PathBuf, &'static str> {
        let closed = closed_absolute(path)?;
        let canonical = closed.canonicalize().map_err(|_| "input path is unavailable")?;
        let metadata = closed.symlink_metadata().map_err(|_| "input path is unavailable")?;
        if canonical != closed || metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("input path is not a canonical regular file");
        }
        Ok(canonical)
    }

    fn canonical_directory(path: &Path) -> Result<PathBuf, &'static str> {
        let closed = closed_absolute(path)?;
        let canonical = closed.canonicalize().map_err(|_| "directory path is unavailable")?;
        let metadata = closed.symlink_metadata().map_err(|_| "directory path is unavailable")?;
        if canonical != closed || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("directory path is not canonical");
        }
        Ok(canonical)
    }

    fn closed_absolute(path: &Path) -> Result<PathBuf, &'static str> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err("path is not closed absolute");
        }
        Ok(path.to_owned())
    }

    fn runtime_parent(value: &str) -> Result<PathBuf, &'static str> {
        let path = closed_absolute(Path::new(value))?;
        let parent = path.parent().ok_or("Runtime parent is invalid")?;
        if parent == Path::new("/") {
            return Err("Runtime parent is invalid");
        }
        Ok(parent.to_owned())
    }

    fn paths_overlap(left: &Path, right: &Path) -> bool {
        left == right || left.starts_with(right) || right.starts_with(left)
    }

    fn digest_bytes(bytes: &[u8]) -> String {
        let mut digest = Sha256::new();
        digest.update(bytes);
        format!("sha256:{:x}", digest.finalize())
    }

    struct RealWindowProbeBudget {
        probe_deadline: Instant,
        total_deadline: Instant,
    }

    impl WindowProbeBudget for RealWindowProbeBudget {
        fn probe_time_remaining(&mut self) -> bool {
            Instant::now() < self.probe_deadline
        }

        fn cleanup_time_remaining(&mut self) -> bool {
            Instant::now() < self.total_deadline
        }

        fn pause_probe(&mut self) {
            sleep_before(self.probe_deadline, Duration::from_millis(25));
        }

        fn pause_cleanup(&mut self) {
            sleep_before(self.total_deadline, Duration::from_millis(25));
        }
    }

    fn sleep_before(deadline: Instant, interval: Duration) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            thread::sleep(interval.min(remaining));
        }
    }

    fn window_visible(deadline: Instant) -> Result<bool, &'static str> {
        let probe_deadline = deadline
            .checked_sub(WINDOW_PROBE_CLEANUP_RESERVE)
            .ok_or("window probe timed out")?;
        if Instant::now() >= probe_deadline {
            return Err("window probe timed out");
        }
        let script = r#"tell application "System Events"
set resultText to {}
repeat with p in (every application process whose background only is false)
repeat with w in (every window of p)
set t to title of w
if t is not missing value and t is not "" then set end of resultText to (t as text)
end repeat
end repeat
set AppleScript's text item delimiters to linefeed
return resultText as text
end tell"#;
        let mut child = Command::new("/usr/bin/osascript")
            .args(["-e", script])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "window probe failed")?;
        let mut budget = RealWindowProbeBudget {
            probe_deadline,
            total_deadline: deadline,
        };
        let stdout_result = child.stdout.take().ok_or("window probe output is unavailable");
        let stdout = start_window_probe_output(&mut child, &mut budget, || stdout_result)?;
        let output_result = BoundedPipeCapture::start_child_stdout(stdout, MAX_WINDOW_OUTPUT_BYTES as usize);
        let mut output = start_window_probe_output(&mut child, &mut budget, || output_result)?;
        let supervision = supervise_window_probe_with_output_guard(&mut child, &mut budget, || output.check());
        let captured = output.finish_until(deadline);
        let (success, bytes) = match (supervision, captured) {
            (Err("window probe cleanup failed"), _) | (_, Err("window probe cleanup failed")) => {
                return Err("window probe cleanup failed");
            }
            (Err(failure), _) => return Err(failure),
            (Ok(_), Err(failure)) => return Err(failure),
            (Ok(success), Ok(bytes)) => (success, bytes),
        };
        if !success {
            return Err("window probe failed");
        }
        if Instant::now() >= deadline {
            return Err("window probe timed out");
        }
        if Instant::now() >= deadline {
            return Err("window probe timed out");
        }
        let titles = String::from_utf8(bytes).map_err(|_| "window probe output is invalid")?;
        Ok(titles
            .lines()
            .any(|title| title.to_ascii_lowercase().contains("sumatrapdf")))
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires reviewed external CrossOver and Whisky spike inputs"]
fn real_apple_silicon_crossover_and_whisky_pinned_sumatrapdf_spike() {
    real::run().expect("the reviewed pinned SumatraPDF spike must pass for both Runtimes");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Error, ErrorKind, Read, Write};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const OUTPUT_HELPER_BYTE_COUNT: usize = 262_144;
    const OUTPUT_HELPER_MAX_BYTES: usize = 262_144;
    const OUTPUT_HELPER_CHUNK_BYTES: usize = 8_192;
    const _: () = assert!(OUTPUT_HELPER_BYTE_COUNT <= OUTPUT_HELPER_MAX_BYTES);
    const _: () = assert!(OUTPUT_HELPER_BYTE_COUNT % OUTPUT_HELPER_CHUNK_BYTES == 0);

    struct HostWindowProbeBudget {
        probe_deadline: Instant,
        cleanup_deadline: Instant,
    }

    impl HostWindowProbeBudget {
        fn new(probe: Duration, cleanup: Duration) -> Self {
            let now = Instant::now();
            Self {
                probe_deadline: now + probe,
                cleanup_deadline: now + cleanup,
            }
        }
    }

    impl WindowProbeBudget for HostWindowProbeBudget {
        fn probe_time_remaining(&mut self) -> bool {
            Instant::now() < self.probe_deadline
        }

        fn cleanup_time_remaining(&mut self) -> bool {
            Instant::now() < self.cleanup_deadline
        }

        fn pause_probe(&mut self) {
            thread::sleep(Duration::from_millis(1));
        }

        fn pause_cleanup(&mut self) {
            thread::sleep(Duration::from_millis(1));
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::other("secret reader failure"))
        }
    }

    struct WouldBlockReader;

    impl Read for WouldBlockReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::new(ErrorKind::WouldBlock, "not ready"))
        }
    }

    struct ScriptedWindowProbeBudget {
        probe_checks: Vec<bool>,
        probe_index: usize,
        cleanup_checks: Vec<bool>,
        cleanup_index: usize,
    }

    impl ScriptedWindowProbeBudget {
        fn new(probe_checks: &[bool], cleanup_checks: &[bool]) -> Self {
            Self {
                probe_checks: probe_checks.to_vec(),
                probe_index: 0,
                cleanup_checks: cleanup_checks.to_vec(),
                cleanup_index: 0,
            }
        }

        fn next(values: &[bool], index: &mut usize) -> bool {
            let value = values.get(*index).copied().unwrap_or(false);
            *index += 1;
            value
        }
    }

    impl WindowProbeBudget for ScriptedWindowProbeBudget {
        fn probe_time_remaining(&mut self) -> bool {
            Self::next(&self.probe_checks, &mut self.probe_index)
        }

        fn cleanup_time_remaining(&mut self) -> bool {
            Self::next(&self.cleanup_checks, &mut self.cleanup_index)
        }

        fn pause_probe(&mut self) {}

        fn pause_cleanup(&mut self) {}
    }

    struct HungWindowProbe {
        polls: usize,
        killed: bool,
        kill_calls: usize,
        wait_calls: usize,
    }

    impl WindowProbeProcess for HungWindowProbe {
        fn try_wait_success(&mut self) -> Result<Option<bool>, &'static str> {
            self.polls += 1;
            Ok(self.killed.then_some(false))
        }

        fn kill(&mut self) -> Result<(), &'static str> {
            self.killed = true;
            self.kill_calls += 1;
            Ok(())
        }

        fn wait(&mut self) -> Result<(), &'static str> {
            self.wait_calls += 1;
            Ok(())
        }
    }

    struct DeadlineRaceWindowProbe {
        polls: usize,
        kill_calls: usize,
        wait_calls: usize,
    }

    impl WindowProbeProcess for DeadlineRaceWindowProbe {
        fn try_wait_success(&mut self) -> Result<Option<bool>, &'static str> {
            self.polls += 1;
            Ok((self.polls == 2).then_some(true))
        }

        fn kill(&mut self) -> Result<(), &'static str> {
            self.kill_calls += 1;
            Ok(())
        }

        fn wait(&mut self) -> Result<(), &'static str> {
            self.wait_calls += 1;
            Ok(())
        }
    }

    struct CleanupWindowProbe {
        poll_results: Vec<Result<Option<bool>, &'static str>>,
        polls: usize,
        kill_fails: bool,
        kill_calls: usize,
        wait_fails: bool,
        wait_calls: usize,
    }

    impl WindowProbeProcess for CleanupWindowProbe {
        fn try_wait_success(&mut self) -> Result<Option<bool>, &'static str> {
            let result = self.poll_results.get(self.polls).copied().unwrap_or(Ok(None));
            self.polls += 1;
            result
        }

        fn kill(&mut self) -> Result<(), &'static str> {
            self.kill_calls += 1;
            if self.kill_fails {
                Err("injected kill failure")
            } else {
                Ok(())
            }
        }

        fn wait(&mut self) -> Result<(), &'static str> {
            self.wait_calls += 1;
            if self.wait_fails {
                Err("injected wait failure")
            } else {
                Ok(())
            }
        }
    }

    struct FakePhase {
        actions: Vec<&'static str>,
        source_digest: &'static str,
        captured_digest: Option<&'static str>,
        child_digest: Option<&'static str>,
        terminated: bool,
        clean: bool,
        observation_fails: bool,
    }

    impl FakePhase {
        fn new() -> Self {
            Self {
                actions: Vec::new(),
                source_digest: "captured",
                captured_digest: None,
                child_digest: None,
                terminated: false,
                clean: false,
                observation_fails: false,
            }
        }
    }

    impl PhaseDriver for FakePhase {
        fn capture(&mut self) -> Result<(), &'static str> {
            self.actions.push("capture");
            self.captured_digest = Some(self.source_digest);
            Ok(())
        }

        fn prepare(&mut self) -> Result<(), &'static str> {
            self.actions.push("prepare");
            Ok(())
        }

        fn authorize(&mut self) -> Result<(), &'static str> {
            self.actions.push("authorize");
            Ok(())
        }

        fn start(&mut self) -> Result<(), &'static str> {
            self.actions.push("start");
            self.child_digest = self.captured_digest;
            Ok(())
        }

        fn mutate_source(&mut self) -> Result<(), &'static str> {
            self.actions.push("mutate");
            self.source_digest = "mutated";
            Ok(())
        }

        fn observe_captured_window(&mut self) -> Result<(), &'static str> {
            self.actions.push("observe-captured-window");
            if self.observation_fails || self.child_digest != Some("captured") {
                return Err("captured window was not observed");
            }
            Ok(())
        }

        fn revalidate_source(&mut self) -> Result<(), &'static str> {
            self.actions.push("revalidate-source");
            if self.source_digest == self.captured_digest.unwrap_or("") {
                Ok(())
            } else {
                Err("source integrity changed")
            }
        }

        fn terminate_managed(&mut self) -> Result<(), &'static str> {
            self.actions.push("terminate-managed");
            self.terminated = true;
            Ok(())
        }

        fn require_clean(&mut self) -> Result<(), &'static str> {
            self.actions.push("require-clean");
            self.clean = self.terminated;
            self.clean.then_some(()).ok_or("residual process")
        }
    }

    #[test]
    fn hung_window_probe_is_killed_and_reaped_at_its_deadline() {
        let mut probe = HungWindowProbe {
            polls: 0,
            killed: false,
            kill_calls: 0,
            wait_calls: 0,
        };
        let mut budget = ScriptedWindowProbeBudget::new(&[true, true, false], &[true]);

        let result = supervise_window_probe(&mut probe, &mut budget);

        assert_eq!(result, Err("window probe timed out"));
        assert_eq!(probe.polls, 2);
        assert_eq!(probe.kill_calls, 1);
        assert_eq!(probe.wait_calls, 1);
    }

    #[test]
    fn bounded_window_output_capture_accepts_exact_and_rejects_cap_plus_one() {
        let exact = vec![b'x'; 131_072];
        let mut accepted = BoundedPipeCapture::start(Cursor::new(exact.clone()), exact.len())
            .expect("the exact-bound reader must start");
        assert_eq!(
            accepted.finish_until(Instant::now() + Duration::from_secs(1)),
            Ok(exact)
        );

        let mut rejected = BoundedPipeCapture::start(Cursor::new(vec![b'x'; 131_073]), 131_072)
            .expect("the cap-plus-one reader must start");
        assert_eq!(
            rejected.finish_until(Instant::now() + Duration::from_secs(1)),
            Err("window probe output is invalid")
        );

        let mut failed = BoundedPipeCapture::start(FailingReader, 131_072).expect("the injected reader must start");
        assert_eq!(
            failed.finish_until(Instant::now() + Duration::from_secs(1)),
            Err("window probe output is invalid")
        );
    }

    #[test]
    fn nonblocking_window_reader_is_cancelled_and_joined_at_its_deadline() {
        let mut capture = BoundedPipeCapture::start_cancellable(WouldBlockReader, 131_072)
            .expect("the nonblocking reader must start");

        assert_eq!(
            capture.finish_until(Instant::now() + Duration::from_millis(20)),
            Err("window probe cleanup failed")
        );
        assert!(capture.reader_joined());
    }

    #[test]
    fn output_failure_kills_and_reaps_the_window_probe_within_cleanup_budget() {
        let mut probe = HungWindowProbe {
            polls: 0,
            killed: false,
            kill_calls: 0,
            wait_calls: 0,
        };
        let mut budget = ScriptedWindowProbeBudget::new(&[true, true, true], &[true]);
        let mut checks = 0;

        let result = supervise_window_probe_with_output_guard(&mut probe, &mut budget, || {
            checks += 1;
            if checks == 2 {
                Err("window probe output is invalid")
            } else {
                Ok(())
            }
        });

        assert_eq!(result, Err("window probe output is invalid"));
        assert_eq!(probe.kill_calls, 1);
        assert_eq!(probe.wait_calls, 1);
    }

    #[test]
    fn output_capture_start_failure_kills_and_reaps_the_window_probe() {
        let mut probe = HungWindowProbe {
            polls: 0,
            killed: false,
            kill_calls: 0,
            wait_calls: 0,
        };
        let mut budget = ScriptedWindowProbeBudget::new(&[true], &[true]);

        let result: Result<(), _> =
            start_window_probe_output(&mut probe, &mut budget, || Err("window probe output is unavailable"));

        assert_eq!(result, Err("window probe output is unavailable"));
        assert_eq!(probe.kill_calls, 1);
        assert_eq!(probe.wait_calls, 1);
    }

    #[test]
    fn harness_reads_only_the_reviewed_manifest_environment_variable() {
        let source = include_str!("macos_pinned_sumatrapdf_spike.rs");
        let manifest_variable = concat!("COMPATFORGE_PINNED_", "SPIKE_INPUT");
        let forbidden_helper_variable = concat!("COMPATFORGE_WINDOW_", "OUTPUT_HELPER_BYTES");

        assert_eq!(source.matches(manifest_variable).count(), 1);
        assert!(!source.contains(forbidden_helper_variable));
    }

    #[test]
    #[ignore = "invoked explicitly by the bounded local pipe backpressure test"]
    fn window_probe_fixed_output_helper() {
        let chunk = [b'x'; OUTPUT_HELPER_CHUNK_BYTES];
        for _ in 0..OUTPUT_HELPER_BYTE_COUNT / OUTPUT_HELPER_CHUNK_BYTES {
            std::io::stdout()
                .write_all(&chunk)
                .expect("helper output must be writable");
        }
        std::io::stdout().flush().expect("helper output must flush");
    }

    #[test]
    fn real_local_probe_output_is_drained_concurrently_and_overflow_is_reaped() {
        fn spawn_helper() -> std::process::Child {
            Command::new(std::env::current_exe().expect("test executable must resolve"))
                .args([
                    "--ignored",
                    "--exact",
                    "tests::window_probe_fixed_output_helper",
                    "--nocapture",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("local output helper must spawn")
        }

        let mut accepted_child = spawn_helper();
        let accepted_stdout = accepted_child.stdout.take().expect("helper stdout must be piped");
        let mut accepted_capture = BoundedPipeCapture::start(accepted_stdout, 524_288).expect("capture must start");
        let mut accepted_budget = HostWindowProbeBudget::new(Duration::from_secs(5), Duration::from_secs(6));
        let accepted = supervise_window_probe_with_output_guard(&mut accepted_child, &mut accepted_budget, || {
            accepted_capture.check()
        });
        let accepted_output = accepted_capture
            .finish_until(Instant::now() + Duration::from_secs(1))
            .expect("bounded helper output must finish");
        assert_eq!(accepted, Ok(true));
        assert!(accepted_output.iter().filter(|byte| **byte == b'x').count() >= OUTPUT_HELPER_BYTE_COUNT);

        let mut rejected_child = spawn_helper();
        let rejected_stdout = rejected_child.stdout.take().expect("helper stdout must be piped");
        let mut rejected_capture = BoundedPipeCapture::start(rejected_stdout, 65_536).expect("capture must start");
        let mut rejected_budget = HostWindowProbeBudget::new(Duration::from_secs(5), Duration::from_secs(6));
        let rejected = supervise_window_probe_with_output_guard(&mut rejected_child, &mut rejected_budget, || {
            rejected_capture.check()
        });
        assert_eq!(rejected, Err("window probe output is invalid"));
        assert_eq!(
            rejected_capture.finish_until(Instant::now() + Duration::from_secs(1)),
            Err("window probe output is invalid")
        );
        assert!(rejected_child
            .try_wait()
            .expect("reap status must be readable")
            .is_some());
    }

    #[test]
    fn ready_probe_after_pause_crosses_deadline_is_timed_out_and_cleaned() {
        let mut probe = DeadlineRaceWindowProbe {
            polls: 0,
            kill_calls: 0,
            wait_calls: 0,
        };
        let mut budget = ScriptedWindowProbeBudget::new(&[true, true, false], &[true]);

        let result = supervise_window_probe(&mut probe, &mut budget);

        assert_eq!(result, Err("window probe timed out"));
        assert_eq!(probe.polls, 2);
        assert_eq!(probe.kill_calls, 1);
        assert_eq!(probe.wait_calls, 1);
    }

    #[test]
    fn failed_kill_never_enters_unbounded_wait_before_reap() {
        let mut probe = CleanupWindowProbe {
            poll_results: vec![Ok(None), Ok(None)],
            polls: 0,
            kill_fails: true,
            kill_calls: 0,
            wait_fails: false,
            wait_calls: 0,
        };
        let mut budget = ScriptedWindowProbeBudget::new(&[true, true, false], &[true, true, false]);

        let result = supervise_window_probe(&mut probe, &mut budget);

        assert_eq!(result, Err("window probe cleanup failed"));
        assert_eq!(probe.kill_calls, 1);
        assert_eq!(probe.wait_calls, 0);
    }

    #[test]
    fn cleanup_poll_failure_overrides_probe_timeout_after_bounded_reap() {
        let mut probe = CleanupWindowProbe {
            poll_results: vec![Ok(None), Err("injected poll failure"), Ok(Some(false))],
            polls: 0,
            kill_fails: false,
            kill_calls: 0,
            wait_fails: false,
            wait_calls: 0,
        };
        let mut budget = ScriptedWindowProbeBudget::new(&[true, true, false], &[true, true, true]);

        let result = supervise_window_probe(&mut probe, &mut budget);

        assert_eq!(result, Err("window probe cleanup failed"));
        assert_eq!(probe.polls, 3);
        assert_eq!(probe.kill_calls, 1);
        assert_eq!(probe.wait_calls, 1);
    }

    #[test]
    fn wait_failure_after_deadline_ready_race_has_cleanup_precedence() {
        let mut probe = CleanupWindowProbe {
            poll_results: vec![Ok(None), Ok(Some(true))],
            polls: 0,
            kill_fails: false,
            kill_calls: 0,
            wait_fails: true,
            wait_calls: 0,
        };
        let mut budget = ScriptedWindowProbeBudget::new(&[true, true, false], &[true]);

        let result = supervise_window_probe(&mut probe, &mut budget);

        assert_eq!(result, Err("window probe cleanup failed"));
        assert_eq!(probe.kill_calls, 1);
        assert_eq!(probe.wait_calls, 1);
    }

    #[test]
    fn stable_phase_uses_capture_prepare_authorize_start_observe_revalidate_and_cleanup_order() {
        let mut phase = FakePhase::new();

        run_spike_phase(&mut phase, false).unwrap();

        assert_eq!(
            phase.actions,
            [
                "capture",
                "prepare",
                "authorize",
                "start",
                "observe-captured-window",
                "revalidate-source",
                "terminate-managed",
                "require-clean",
            ]
        );
        assert!(phase.clean);
    }

    #[test]
    fn mutation_phase_changes_source_only_after_live_child_and_executes_captured_bytes() {
        let mut phase = FakePhase::new();

        run_spike_phase(&mut phase, true).unwrap();

        assert_eq!(
            phase.actions,
            [
                "capture",
                "prepare",
                "authorize",
                "start",
                "mutate",
                "observe-captured-window",
                "revalidate-source",
                "terminate-managed",
                "require-clean",
            ]
        );
        assert_eq!(phase.child_digest, Some("captured"));
        assert_eq!(phase.source_digest, "mutated");
        assert!(phase.clean);
    }

    #[test]
    fn observation_failure_still_terminates_and_requires_zero_residual_processes() {
        let mut phase = FakePhase::new();
        phase.observation_fails = true;

        assert_eq!(
            run_spike_phase(&mut phase, true),
            Err("captured window was not observed")
        );

        assert!(phase.terminated);
        assert!(phase.clean);
        assert_eq!(
            &phase.actions[phase.actions.len() - 2..],
            ["terminate-managed", "require-clean"]
        );
    }
}
