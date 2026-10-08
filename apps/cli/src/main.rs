use compatforge_bottle::{BottleMigrationError, BottleStore, DiagnosticCode, RuntimeMap};
use compatforge_capability::HostProbe;
use compatforge_domain::{CoreConfig, LaunchPlan, LaunchRequest, RuntimeEventKind, RuntimePackManifest};
#[cfg(target_os = "macos")]
use compatforge_domain::{CpuArchitecture, ExecutableMode};
#[cfg(any(target_os = "macos", test))]
use compatforge_guest_artifact::PublishedEvidenceBinding;
#[cfg(target_os = "macos")]
use compatforge_guest_artifact::{
    GuestArtifactStore, HeldExternalWorkRoot, InheritedEvidenceFile, PinnedBottleExecutable, PinnedEvidenceKind,
};
use compatforge_inspect::inspect_path;
use compatforge_orchestrator::{PolicyEngine, PreparedLaunch};
use compatforge_process::LaunchHandle;
use compatforge_process::{EventPoll, ProcessError, ProcessSupervisor};
use compatforge_provider_linux::{
    create_local_context as create_linux_local_context, LinuxLocalContextRequest, LinuxProviderConfig, LinuxProviderSet,
};
use compatforge_provider_macos::{
    create_local_context as create_macos_local_context, MacOsLocalContextRequest, MacOsProviderConfig, MacOsProviderSet,
};
use compatforge_runtime::{sha256_digest_bytes, RejectAllSignatures, RuntimePackStore};
use compatforge_service::{AutomationService, ServiceConfig, ServiceRequest};
use serde::Serialize;
use serde_json::{Map, Value};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const PINNED_SUMATRAPDF_FAILURE: &str = "pinned SumatraPDF launch failed";

#[derive(Debug, PartialEq, Eq)]
enum LinuxCommand<'a> {
    Probe(&'a str),
    Context(&'a str, &'a str),
    Local(&'a str, Option<&'a str>),
}

fn parse_linux_command(arguments: &[String]) -> io::Result<Option<LinuxCommand<'_>>> {
    if !matches!(arguments, [group, platform, ..] if matches!(group.as_str(), "provider" | "local") && platform == "linux")
    {
        return Ok(None);
    }
    let command = match arguments {
        [group, _, command, config] if group == "provider" && command == "probe" => LinuxCommand::Probe(config),
        [group, _, command, config, storage] if group == "provider" && command == "context" => {
            LinuxCommand::Context(config, storage)
        }
        [group, _, command, request] if group == "local" && command == "context" => LinuxCommand::Local(request, None),
        [group, _, command, request, output] if group == "local" && command == "context" => {
            LinuxCommand::Local(request, Some(output))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Linux command arguments",
            ))
        }
    };
    Ok(Some(command))
}

trait PrivateOutput: Write {
    fn sync_private(&mut self) -> io::Result<()>;
}

trait PrivateOutputFs {
    type Output: PrivateOutput;
    fn validate_parent(&self, path: &Path) -> io::Result<()>;
    fn create_new(&self, path: &Path, mode: u32) -> io::Result<Self::Output>;
    fn remove_partial(&self, path: &Path) -> io::Result<()>;
}

fn write_private_output_with<T: Serialize, F: PrivateOutputFs>(
    path: &Path,
    value: &T,
    filesystem: &F,
) -> io::Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output requires an absolute path",
        ));
    }
    filesystem.validate_parent(path)?;
    let mut file = filesystem.create_new(path, 0o600)?;
    let result = (|| {
        serde_json::to_writer_pretty(&mut file, value).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_private()
    })();
    drop(file);
    if let Err(error) = result {
        filesystem.remove_partial(path)?;
        return Err(error);
    }
    Ok(())
}

struct SystemPrivateOutputFs;

fn validate_private_parent_facts(
    is_directory: bool,
    is_symlink: bool,
    canonical: bool,
    caller_owned: bool,
) -> io::Result<()> {
    if !is_directory || is_symlink || !canonical || !caller_owned {
        Err(io::Error::other(
            "private output requires a canonical caller-owned directory",
        ))
    } else {
        Ok(())
    }
}

impl PrivateOutput for fs::File {
    fn sync_private(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl PrivateOutputFs for SystemPrivateOutputFs {
    type Output = fs::File;
    fn validate_parent(&self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("private output has no parent"))?;
        for ancestor in parent.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            validate_private_parent_facts(metadata.is_dir(), metadata.file_type().is_symlink(), true, true)?;
        }
        let canonical = parent.canonicalize()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            extern "C" {
                fn geteuid() -> u32;
            }
            // SAFETY: geteuid has no arguments or memory preconditions.
            let caller_uid = unsafe { geteuid() };
            validate_private_parent_facts(
                true,
                false,
                canonical == parent,
                fs::metadata(&canonical)?.uid() == caller_uid,
            )?;
        }
        #[cfg(not(unix))]
        let _ = canonical;
        Ok(())
    }
    fn create_new(&self, path: &Path, mode: u32) -> io::Result<Self::Output> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        options.open(path)
    }
    fn remove_partial(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

fn run_linux_command(command: LinuxCommand<'_>) -> Result<(), Box<dyn Error>> {
    let output = match command {
        LinuxCommand::Probe(config) => {
            let config = read_json::<LinuxProviderConfig>(Path::new(config))?;
            let snapshot = LinuxProviderSet::probe(&HostProbe::probe()?, &config)?;
            LinuxOutput::Probe(snapshot.capabilities)
        }
        LinuxCommand::Context(config, storage) => {
            let config = read_json::<LinuxProviderConfig>(Path::new(config))?;
            let snapshot = LinuxProviderSet::probe(&HostProbe::probe()?, &config)?;
            LinuxOutput::Context(snapshot.core_config(storage.to_owned())?)
        }
        LinuxCommand::Local(request, output) => {
            let request = read_json::<LinuxLocalContextRequest>(Path::new(request))?;
            let local = create_linux_local_context(&HostProbe::probe()?, &request)?;
            LinuxOutput::Local(local, output.map(Path::new))
        }
    };
    publish_linux_output(output, &mut io::stdout().lock(), &SystemPrivateOutputFs)?;
    Ok(())
}

enum LinuxOutput<'a> {
    Probe(compatforge_domain::CapabilityReport),
    Context(CoreConfig),
    Local(compatforge_provider_linux::LinuxLocalContext, Option<&'a Path>),
}

fn publish_linux_output(
    output: LinuxOutput<'_>,
    stdout: &mut dyn Write,
    filesystem: &impl PrivateOutputFs,
) -> io::Result<()> {
    match output {
        LinuxOutput::Probe(report) => serde_json::to_writer_pretty(&mut *stdout, &report).map_err(io::Error::other)?,
        LinuxOutput::Context(config) => {
            serde_json::to_writer_pretty(&mut *stdout, &config).map_err(io::Error::other)?
        }
        LinuxOutput::Local(local, output) => {
            if let Some(path) = output {
                write_new_private_json(path, &local.config, filesystem)?;
            }
            serde_json::to_writer_pretty(&mut *stdout, &local.receipt).map_err(io::Error::other)?;
        }
    }
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn write_new_private_json(path: &Path, config: &CoreConfig, filesystem: &impl PrivateOutputFs) -> io::Result<()> {
    write_private_output_with(path, config, filesystem)
}
const PINNED_SUMATRAPDF_DIAGNOSTIC: &[u8] = b"compatforge-cli: pinned SumatraPDF launch failed\n";
#[cfg(any(target_os = "macos", test))]
const PINNED_RUNTIME_REQUEST_ID: &str = "pinned-sumatrapdf";

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let is_bottle = arguments.first().is_some_and(|argument| argument == "bottle");
    let is_pinned = arguments
        .first()
        .is_some_and(|argument| argument == "prepared-pinned-sumatrapdf-launch-terminate");
    if let Err(error) = run_arguments(&arguments) {
        if is_bottle {
            let diagnostic = error
                .downcast_ref::<BottleMigrationError>()
                .copied()
                .unwrap_or_else(|| BottleMigrationError::new(DiagnosticCode::InvalidManifest));
            let _ = io::stderr().write_all(&diagnostic_json(&diagnostic));
        } else if is_pinned {
            let _ = io::stderr().write_all(PINNED_SUMATRAPDF_DIAGNOSTIC);
        } else {
            eprintln!("compatforge-cli: {error}");
        }
        std::process::exit(1);
    }
}

fn run_arguments(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    if let Some(command) = parse_linux_command(arguments)? {
        return run_linux_command(command);
    }
    if arguments.first().is_some_and(|argument| argument == "bottle") {
        return run_bottle(arguments).map_err(|error| Box::new(error) as Box<dyn Error>);
    }
    if let Some(command) = parse_prepared_command(arguments) {
        return run_prepared_command(command);
    }
    if arguments.first().is_some_and(|command| {
        matches!(
            command.as_str(),
            "prepared-plan"
                | "prepared-launch"
                | "prepared-launch-terminate"
                | "prepared-pinned-sumatrapdf-launch-terminate"
        )
    }) {
        let message = if arguments
            .first()
            .is_some_and(|command| command == "prepared-pinned-sumatrapdf-launch-terminate")
        {
            PINNED_SUMATRAPDF_FAILURE
        } else {
            "invalid prepared command arguments"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidInput, message).into());
    }

    match arguments {
        [command] if matches!(command.as_str(), "--version" | "version") => {
            println!("compatforge-cli {}", env!("CARGO_PKG_VERSION"));
        }
        [command] if command == "probe" => {
            println!("{}", serde_json::to_string_pretty(&HostProbe::probe()?)?);
        }
        [command, executable_path] if command == "inspect" => {
            let executable_path = absolute_path(Path::new(executable_path))?;
            println!("{}", serde_json::to_string_pretty(&inspect_path(&executable_path)?)?);
        }
        [group, platform, command, config_path] if group == "provider" && platform == "macos" && command == "probe" => {
            let config = read_json::<MacOsProviderConfig>(Path::new(config_path))?;
            let snapshot = MacOsProviderSet::probe(&HostProbe::probe()?, &config)?;
            println!("{}", serde_json::to_string_pretty(&snapshot.capabilities)?);
        }
        [group, platform, command, config_path, storage_root]
            if group == "provider" && platform == "macos" && command == "context" =>
        {
            let config = read_json::<MacOsProviderConfig>(Path::new(config_path))?;
            let snapshot = MacOsProviderSet::probe(&HostProbe::probe()?, &config)?;
            let core_config = snapshot.core_config(storage_root.clone())?;
            println!("{}", serde_json::to_string_pretty(&core_config)?);
        }
        [group, platform, command, request_path] if group == "local" && platform == "macos" && command == "context" => {
            let request = read_json::<MacOsLocalContextRequest>(Path::new(request_path))?;
            let local = create_macos_local_context(&HostProbe::probe()?, &request)?;
            println!("{}", serde_json::to_string_pretty(&local.receipt)?);
        }
        [group, platform, command, request_path, context_output]
            if group == "local" && platform == "macos" && command == "context" =>
        {
            let request = read_json::<MacOsLocalContextRequest>(Path::new(request_path))?;
            let local = create_macos_local_context(&HostProbe::probe()?, &request)?;
            fs::write(
                context_output,
                format!("{}\n", serde_json::to_string_pretty(&local.config)?),
            )?;
            println!("{}", serde_json::to_string_pretty(&local.receipt)?);
        }
        [command] if command == "demo-plan" => {
            let config: CoreConfig =
                serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json"))?;
            let request: LaunchRequest = serde_json::from_str(include_str!("../../../examples/launch-request.json"))?;
            print_plan(&config, &request)?;
        }
        [command, config_path, request_path] if command == "plan" => {
            let config = read_json::<CoreConfig>(Path::new(config_path))?;
            let request = read_json::<LaunchRequest>(Path::new(request_path))?;
            print_plan(&config, &request)?;
        }
        [command, config_path, request_path] if command == "launch" => {
            let config = read_json::<CoreConfig>(Path::new(config_path))?;
            let request = read_json::<LaunchRequest>(Path::new(request_path))?;
            launch(&config, &request, None)?;
        }
        [command, config_path, service_config_path, request_path] if command == "api" => {
            let config = read_json::<CoreConfig>(Path::new(config_path))?;
            let service_config = read_json::<ServiceConfig>(Path::new(service_config_path))?;
            let request = read_json::<ServiceRequest>(Path::new(request_path))?;
            let service = AutomationService::new(config, service_config)?;
            println!("{}", serde_json::to_string(&service.call(request)?)?);
        }
        [command, config_path, service_config_path] if command == "api-session" => {
            let config = read_json::<CoreConfig>(Path::new(config_path))?;
            let service_config = read_json::<ServiceConfig>(Path::new(service_config_path))?;
            run_api_session(AutomationService::new(config, service_config)?)?;
        }
        [command, config_path, request_path, milliseconds] if command == "launch-terminate" => {
            let config = read_json::<CoreConfig>(Path::new(config_path))?;
            let request = read_json::<LaunchRequest>(Path::new(request_path))?;
            let milliseconds = milliseconds.parse::<u64>()?;
            launch(&config, &request, Some(Duration::from_millis(milliseconds)))?;
        }
        [group, command, manifest_path] if group == "runtime" && command == "manifest-digest" => {
            let manifest = read_json::<RuntimePackManifest>(Path::new(manifest_path))?;
            manifest.validate()?;
            println!("{}", sha256_digest_bytes(&manifest.canonical_unsigned_bytes()?));
        }
        [group, command, store_root, bundle_root, manifest_relative] if group == "runtime" && command == "install" => {
            let receipt = RuntimePackStore::new(store_root).install_bundle(
                bundle_root,
                manifest_relative,
                &RejectAllSignatures,
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        [group, command, store_root, digest] if group == "runtime" && command == "verify" => {
            let receipt = RuntimePackStore::new(store_root).verify_installed(digest)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        [group, command, store_root, pack_id] if group == "runtime" && command == "rollback" => {
            let receipt = RuntimePackStore::new(store_root).rollback(pack_id)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        _ => print_help(),
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedCommand<'a> {
    Plan {
        config_path: &'a str,
        executable_path: &'a str,
        request_path: &'a str,
    },
    Launch {
        config_path: &'a str,
        executable_path: &'a str,
        request_path: &'a str,
        terminate_after_milliseconds: Option<u64>,
    },
    PinnedSumatraPdfLaunchTerminate {
        config_path: &'a str,
        logical_executable_path: &'a str,
        request_path: &'a str,
        external_work_root: &'a str,
        inherited_work_root_fd: i32,
        inherited_inspection_fd: i32,
        inherited_plan_fd: i32,
        terminate_after_milliseconds: u64,
    },
}

fn parse_prepared_command(arguments: &[String]) -> Option<PreparedCommand<'_>> {
    match arguments {
        [command, config_path, executable_path, request_path] if command == "prepared-plan" => {
            Some(PreparedCommand::Plan {
                config_path,
                executable_path,
                request_path,
            })
        }
        [command, config_path, executable_path, request_path] if command == "prepared-launch" => {
            Some(PreparedCommand::Launch {
                config_path,
                executable_path,
                request_path,
                terminate_after_milliseconds: None,
            })
        }
        [command, config_path, executable_path, request_path, milliseconds]
            if command == "prepared-launch-terminate" =>
        {
            let milliseconds = milliseconds.parse::<u64>().ok()?;
            if !(1..=86_400_000).contains(&milliseconds) {
                return None;
            }
            Some(PreparedCommand::Launch {
                config_path,
                executable_path,
                request_path,
                terminate_after_milliseconds: Some(milliseconds),
            })
        }
        [command, config_path, logical_executable_path, request_path, external_work_root, inherited_work_root_fd, inherited_inspection_fd, inherited_plan_fd, milliseconds]
            if command == "prepared-pinned-sumatrapdf-launch-terminate" =>
        {
            if ![
                config_path.as_str(),
                logical_executable_path.as_str(),
                request_path.as_str(),
                external_work_root.as_str(),
            ]
            .into_iter()
            .all(is_closed_macos_absolute_path)
                || !has_fixed_sumatrapdf_suffix(logical_executable_path)
            {
                return None;
            }

            let inherited_work_root_fd = parse_closed_inherited_fd(inherited_work_root_fd)?;
            let inherited_inspection_fd = parse_closed_inherited_fd(inherited_inspection_fd)?;
            let inherited_plan_fd = parse_closed_inherited_fd(inherited_plan_fd)?;
            if inherited_work_root_fd == inherited_inspection_fd
                || inherited_work_root_fd == inherited_plan_fd
                || inherited_inspection_fd == inherited_plan_fd
            {
                return None;
            }

            let terminate_after_milliseconds = milliseconds.parse::<u64>().ok()?;
            if !(1..=86_400_000).contains(&terminate_after_milliseconds) {
                return None;
            }
            Some(PreparedCommand::PinnedSumatraPdfLaunchTerminate {
                config_path,
                logical_executable_path,
                request_path,
                external_work_root,
                inherited_work_root_fd,
                inherited_inspection_fd,
                inherited_plan_fd,
                terminate_after_milliseconds,
            })
        }
        _ => None,
    }
}

fn is_closed_macos_absolute_path(value: &str) -> bool {
    value.strip_prefix('/').is_some_and(|relative| {
        !relative.is_empty()
            && !relative.contains('\\')
            && relative
                .split('/')
                .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
    })
}

fn has_fixed_sumatrapdf_suffix(value: &str) -> bool {
    if !is_closed_macos_absolute_path(value) {
        return false;
    }
    let mut components = value.rsplit('/');
    components.next() == Some("SumatraPDF.exe")
        && components.next() == Some("SumatraPDF")
        && components.next() == Some("CompatForge")
        && components.next() == Some("drive_c")
        && components.next() == Some("prefix")
        && components.next() == Some("gui-sumatrapdf")
        && components.next() == Some("bottles")
}

fn parse_closed_inherited_fd(value: &str) -> Option<i32> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let descriptor = value.parse::<i32>().ok()?;
    (descriptor > 2).then_some(descriptor)
}

#[cfg(any(target_os = "macos", test))]
fn pinned_environment_has_path(config: &CoreConfig, request: &LaunchRequest) -> bool {
    request.environment.contains_key("PATH")
        || config
            .runtime_bindings
            .iter()
            .any(|binding| binding.environment.contains_key("PATH"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PinnedSessionError;

impl fmt::Display for PinnedSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(PINNED_SUMATRAPDF_FAILURE)
    }
}

impl Error for PinnedSessionError {}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PinnedEvidenceOutput {
    byte_length: u64,
    kind: &'static str,
    sha256: String,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PinnedEvidenceReceipt {
    outputs: [PinnedEvidenceOutput; 2],
    record_type: &'static str,
    schema_version: u8,
}

#[cfg(any(target_os = "macos", test))]
impl PinnedEvidenceReceipt {
    fn new(inspection: PublishedEvidenceBinding, plan: PublishedEvidenceBinding) -> Result<Self, PinnedSessionError> {
        if !valid_pinned_evidence_binding(&inspection) || !valid_pinned_evidence_binding(&plan) {
            return Err(PinnedSessionError);
        }
        Ok(Self {
            outputs: [
                PinnedEvidenceOutput {
                    byte_length: inspection.byte_length,
                    kind: "inspection",
                    sha256: inspection.sha256,
                },
                PinnedEvidenceOutput {
                    byte_length: plan.byte_length,
                    kind: "plan",
                    sha256: plan.sha256,
                },
            ],
            record_type: "pinned-evidence-receipt",
            schema_version: 1,
        })
    }
}

#[cfg(any(target_os = "macos", test))]
fn valid_pinned_evidence_binding(binding: &PublishedEvidenceBinding) -> bool {
    (1..=1_048_576).contains(&binding.byte_length)
        && binding.sha256.len() == 71
        && binding.sha256.starts_with("sha256:")
        && binding.sha256[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(target_os = "macos", test))]
fn pinned_receipt_line(receipt: &PinnedEvidenceReceipt) -> Result<Vec<u8>, PinnedSessionError> {
    let mut bytes = serde_json::to_vec(receipt).map_err(|_| PinnedSessionError)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedSessionTranscript {
    events: Vec<Vec<u8>>,
    receipt: PinnedEvidenceReceipt,
}

#[cfg(any(target_os = "macos", test))]
trait ClosedPinnedSession {
    type Handle;

    fn validate_closed_inputs(&mut self) -> Result<(), PinnedSessionError>;
    fn capture_source(&mut self) -> Result<(), PinnedSessionError>;
    fn prepare_pinned(&mut self) -> Result<(), PinnedSessionError>;
    fn authorize_pinned(&mut self) -> Result<(), PinnedSessionError>;
    fn publish_evidence(&mut self) -> Result<(), PinnedSessionError>;
    fn start_pinned(&mut self) -> Result<Self::Handle, PinnedSessionError>;
    fn post_spawn_revalidate(&mut self) -> Result<(), PinnedSessionError>;
    fn shutdown_integrity_failure(&mut self, handle: Self::Handle) -> Result<(), PinnedSessionError>;
    #[cfg(test)]
    fn supervise_pinned(&mut self, handle: Self::Handle) -> Result<Vec<Vec<u8>>, PinnedSessionError>;
    fn finalize_session(&mut self) -> Result<(), PinnedSessionError>;
    fn evidence_receipt(&self) -> Result<PinnedEvidenceReceipt, PinnedSessionError>;
}

#[cfg(test)]
fn run_closed_pinned_session<S: ClosedPinnedSession>(
    session: &mut S,
) -> Result<PinnedSessionTranscript, PinnedSessionError> {
    run_closed_pinned_session_inner(session, |_| {})
}

#[cfg(test)]
fn run_closed_pinned_session_inner<S, F>(
    session: &mut S,
    after_spawn: F,
) -> Result<PinnedSessionTranscript, PinnedSessionError>
where
    S: ClosedPinnedSession,
    F: FnOnce(&mut S),
{
    session.validate_closed_inputs()?;
    session.capture_source()?;
    session.prepare_pinned()?;
    session.authorize_pinned()?;
    session.publish_evidence()?;
    let handle = session.start_pinned()?;
    after_spawn(session);
    if let Err(integrity_error) = session.post_spawn_revalidate() {
        session.shutdown_integrity_failure(handle)?;
        return Err(integrity_error);
    }
    let events = session.supervise_pinned(handle)?;
    session.finalize_session()?;
    Ok(PinnedSessionTranscript {
        events,
        receipt: session.evidence_receipt()?,
    })
}

#[cfg(test)]
fn run_closed_pinned_session_with_test_callback<S, F>(
    session: &mut S,
    after_spawn: F,
) -> Result<PinnedSessionTranscript, PinnedSessionError>
where
    S: ClosedPinnedSession,
    F: FnOnce(&mut S),
{
    run_closed_pinned_session_inner(session, after_spawn)
}

#[cfg(target_os = "macos")]
struct TimedPinnedHandle {
    handle: LaunchHandle,
    started: Instant,
    cleanup_wait: Duration,
}

#[cfg(target_os = "macos")]
struct MacOsClosedPinnedSession<'a> {
    config_path: &'a str,
    logical_executable_path: &'a str,
    request_path: &'a str,
    external_work_root: &'a str,
    inherited_work_root_fd: i32,
    inherited_inspection_fd: i32,
    inherited_plan_fd: i32,
    terminate_after: Duration,
    config: Option<CoreConfig>,
    request: Option<LaunchRequest>,
    work_root: Option<HeldExternalWorkRoot>,
    inspection_output: Option<InheritedEvidenceFile>,
    plan_output: Option<InheritedEvidenceFile>,
    pinned: Option<PinnedBottleExecutable>,
    prepared: Option<PreparedLaunch>,
    receipt: Option<PinnedEvidenceReceipt>,
}

#[cfg(target_os = "macos")]
impl<'a> MacOsClosedPinnedSession<'a> {
    fn new(command: PreparedCommand<'a>) -> Result<Self, PinnedSessionError> {
        let PreparedCommand::PinnedSumatraPdfLaunchTerminate {
            config_path,
            logical_executable_path,
            request_path,
            external_work_root,
            inherited_work_root_fd,
            inherited_inspection_fd,
            inherited_plan_fd,
            terminate_after_milliseconds,
        } = command
        else {
            return Err(PinnedSessionError);
        };
        Ok(Self {
            config_path,
            logical_executable_path,
            request_path,
            external_work_root,
            inherited_work_root_fd,
            inherited_inspection_fd,
            inherited_plan_fd,
            terminate_after: Duration::from_millis(terminate_after_milliseconds),
            config: None,
            request: None,
            work_root: None,
            inspection_output: None,
            plan_output: None,
            pinned: None,
            prepared: None,
            receipt: None,
        })
    }

    fn config(&self) -> Result<&CoreConfig, PinnedSessionError> {
        self.config.as_ref().ok_or(PinnedSessionError)
    }

    fn request(&self) -> Result<&LaunchRequest, PinnedSessionError> {
        self.request.as_ref().ok_or(PinnedSessionError)
    }

    fn work_root(&self) -> Result<&HeldExternalWorkRoot, PinnedSessionError> {
        self.work_root.as_ref().ok_or(PinnedSessionError)
    }

    fn pinned(&self) -> Result<&PinnedBottleExecutable, PinnedSessionError> {
        self.pinned.as_ref().ok_or(PinnedSessionError)
    }

    fn prepared(&self) -> Result<&PreparedLaunch, PinnedSessionError> {
        self.prepared.as_ref().ok_or(PinnedSessionError)
    }
}

#[cfg(target_os = "macos")]
impl ClosedPinnedSession for MacOsClosedPinnedSession<'_> {
    type Handle = TimedPinnedHandle;

    fn validate_closed_inputs(&mut self) -> Result<(), PinnedSessionError> {
        let config = read_json::<CoreConfig>(Path::new(self.config_path)).map_err(|_| PinnedSessionError)?;
        let request = read_json::<LaunchRequest>(Path::new(self.request_path)).map_err(|_| PinnedSessionError)?;
        config.validate().map_err(|_| PinnedSessionError)?;
        request.validate().map_err(|_| PinnedSessionError)?;
        if request.bottle_id != "gui-sumatrapdf"
            || request.request_id != PINNED_RUNTIME_REQUEST_ID
            || request.executable.mode != ExecutableMode::BottleInPlace
            || request.executable.architecture != CpuArchitecture::X86_64
            || request.executable.path != self.logical_executable_path
            || !request.arguments.is_empty()
            || pinned_environment_has_path(&config, &request)
            || !is_closed_macos_absolute_path(&config.storage_root)
        {
            return Err(PinnedSessionError);
        }
        let storage_root = PathBuf::from(&config.storage_root);
        let bottle_root = storage_root.join("bottles").join("gui-sumatrapdf");
        let source = bottle_root
            .join("prefix")
            .join("drive_c")
            .join("CompatForge")
            .join("SumatraPDF")
            .join("SumatraPDF.exe");
        if source != Path::new(self.logical_executable_path) {
            return Err(PinnedSessionError);
        }

        let mut forbidden = vec![storage_root, bottle_root, source];
        for binding in &config.runtime_bindings {
            push_runtime_forbidden_root(&mut forbidden, &binding.executable)?;
            if let Some(wineserver) = &binding.wineserver_executable {
                push_runtime_forbidden_root(&mut forbidden, wineserver)?;
            }
            if let Some(working_directory) = &binding.working_directory {
                push_closed_forbidden_root(&mut forbidden, working_directory)?;
            }
            for value in binding.environment.values().chain(request.environment.values()) {
                if value.starts_with('/') {
                    push_closed_forbidden_root(&mut forbidden, value)?;
                }
            }
        }
        forbidden.sort();
        forbidden.dedup();
        let forbidden_refs = forbidden.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        let work_root = HeldExternalWorkRoot::duplicate_inherited(
            self.inherited_work_root_fd,
            Path::new(self.external_work_root),
            &forbidden_refs,
        )
        .map_err(|_| PinnedSessionError)?;
        let inspection_output =
            InheritedEvidenceFile::duplicate_inherited(self.inherited_inspection_fd, PinnedEvidenceKind::Inspection)
                .map_err(|_| PinnedSessionError)?;
        let plan_output = InheritedEvidenceFile::duplicate_inherited(self.inherited_plan_fd, PinnedEvidenceKind::Plan)
            .map_err(|_| PinnedSessionError)?;
        inspection_output
            .ensure_distinct(&plan_output)
            .map_err(|_| PinnedSessionError)?;
        work_root.revalidate().map_err(|_| PinnedSessionError)?;
        self.config = Some(config);
        self.request = Some(request);
        self.work_root = Some(work_root);
        self.inspection_output = Some(inspection_output);
        self.plan_output = Some(plan_output);
        Ok(())
    }

    fn capture_source(&mut self) -> Result<(), PinnedSessionError> {
        let pinned = GuestArtifactStore::new(&self.config()?.storage_root)
            .pin_sumatra_bottle_executable(
                "gui-sumatrapdf",
                Path::new(self.logical_executable_path),
                self.work_root()?,
            )
            .map_err(|_| PinnedSessionError)?;
        self.pinned = Some(pinned);
        Ok(())
    }

    fn prepare_pinned(&mut self) -> Result<(), PinnedSessionError> {
        let prepared = PreparedLaunch::prepare_pinned_bottle(self.config()?, self.request()?, self.pinned()?)
            .map_err(|_| PinnedSessionError)?;
        self.prepared = Some(prepared);
        Ok(())
    }

    fn authorize_pinned(&mut self) -> Result<(), PinnedSessionError> {
        self.prepared()?
            .authorize_pinned(self.config()?, self.pinned()?)
            .map_err(|_| PinnedSessionError)?;
        Ok(())
    }

    fn publish_evidence(&mut self) -> Result<(), PinnedSessionError> {
        let inspection_bytes = canonical_pinned_json(self.pinned()?.inspection())?;
        let plan_bytes = canonical_pinned_json(self.prepared()?.plan())?;
        self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;
        let inspection_binding = self
            .inspection_output
            .as_mut()
            .ok_or(PinnedSessionError)?
            .write_canonical(&inspection_bytes)
            .map_err(|_| PinnedSessionError)?;
        self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;
        self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;
        let plan_binding = self
            .plan_output
            .as_mut()
            .ok_or(PinnedSessionError)?
            .write_canonical(&plan_bytes)
            .map_err(|_| PinnedSessionError)?;
        self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;
        self.receipt = Some(PinnedEvidenceReceipt::new(inspection_binding, plan_binding)?);
        Ok(())
    }

    fn start_pinned(&mut self) -> Result<Self::Handle, PinnedSessionError> {
        let (inspection_binding, plan_binding) = {
            let receipt = self.receipt.as_ref().ok_or(PinnedSessionError)?;
            (
                PublishedEvidenceBinding {
                    byte_length: receipt.outputs[0].byte_length,
                    sha256: receipt.outputs[0].sha256.clone(),
                },
                PublishedEvidenceBinding {
                    byte_length: receipt.outputs[1].byte_length,
                    sha256: receipt.outputs[1].sha256.clone(),
                },
            )
        };
        self.inspection_output
            .as_mut()
            .ok_or(PinnedSessionError)?
            .revalidate_binding(&inspection_binding)
            .map_err(|_| PinnedSessionError)?;
        self.plan_output
            .as_mut()
            .ok_or(PinnedSessionError)?
            .revalidate_binding(&plan_binding)
            .map_err(|_| PinnedSessionError)?;
        self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;
        let handle = ProcessSupervisor::start_pinned_bottle(self.prepared()?.plan(), self.pinned()?)
            .map_err(|_| PinnedSessionError)?;
        let cleanup_wait = Duration::from_millis(self.prepared()?.plan().lifecycle.termination_grace_milliseconds);
        Ok(TimedPinnedHandle {
            handle,
            started: Instant::now(),
            cleanup_wait,
        })
    }

    fn post_spawn_revalidate(&mut self) -> Result<(), PinnedSessionError> {
        self.pinned()?.revalidate().map_err(|_| PinnedSessionError)
    }

    fn shutdown_integrity_failure(&mut self, timed: Self::Handle) -> Result<(), PinnedSessionError> {
        let termination = timed.handle.terminate().map_err(|_| PinnedSessionError);
        let cleanup = drain_pinned_integrity_shutdown(&timed.handle, timed.cleanup_wait);
        if termination.is_err() || cleanup.is_err() {
            Err(PinnedSessionError)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn supervise_pinned(&mut self, timed: Self::Handle) -> Result<Vec<Vec<u8>>, PinnedSessionError> {
        collect_pinned_runtime_events(&timed.handle, timed.started, self.terminate_after, timed.cleanup_wait)
    }

    fn finalize_session(&mut self) -> Result<(), PinnedSessionError> {
        self.work_root()?.revalidate().map_err(|_| PinnedSessionError)
    }

    fn evidence_receipt(&self) -> Result<PinnedEvidenceReceipt, PinnedSessionError> {
        self.receipt.clone().ok_or(PinnedSessionError)
    }
}

#[cfg(target_os = "macos")]
fn push_runtime_forbidden_root(roots: &mut Vec<PathBuf>, executable: &str) -> Result<(), PinnedSessionError> {
    if !is_closed_macos_absolute_path(executable) {
        return Err(PinnedSessionError);
    }
    let parent = Path::new(executable).parent().ok_or(PinnedSessionError)?;
    if parent == Path::new("/") {
        return Err(PinnedSessionError);
    }
    roots.push(parent.to_owned());
    Ok(())
}

#[cfg(target_os = "macos")]
fn push_closed_forbidden_root(roots: &mut Vec<PathBuf>, value: &str) -> Result<(), PinnedSessionError> {
    if !is_closed_macos_absolute_path(value) {
        return Err(PinnedSessionError);
    }
    roots.push(PathBuf::from(value));
    Ok(())
}

#[cfg(target_os = "macos")]
fn canonical_pinned_json<T: Serialize>(value: &T) -> Result<Vec<u8>, PinnedSessionError> {
    let value = serde_json::to_value(value).map_err(|_| PinnedSessionError)?;
    serde_json::to_vec(&canonicalize_json(&value)).map_err(|_| PinnedSessionError)
}

#[cfg(any(target_os = "macos", test))]
fn event_json_line(event: &compatforge_domain::RuntimeEvent) -> Result<Vec<u8>, PinnedSessionError> {
    let mut line = serde_json::to_vec(event).map_err(|_| PinnedSessionError)?;
    line.push(b'\n');
    Ok(line)
}

#[cfg(any(target_os = "macos", test))]
trait PinnedRuntimeHandle {
    fn next_event(&self, timeout: Duration) -> EventPoll;
    fn terminate(&self) -> Result<(), PinnedSessionError>;
    fn is_finished(&self) -> bool;
    fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), PinnedSessionError>;
}

#[cfg(target_os = "macos")]
impl PinnedRuntimeHandle for LaunchHandle {
    fn next_event(&self, timeout: Duration) -> EventPoll {
        LaunchHandle::next_event(self, timeout)
    }

    fn terminate(&self) -> Result<(), PinnedSessionError> {
        LaunchHandle::terminate(self).map_err(|_| PinnedSessionError)
    }

    fn is_finished(&self) -> bool {
        LaunchHandle::is_finished(self)
    }

    fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), PinnedSessionError> {
        LaunchHandle::terminate_and_wait(self, graceful_wait).map_err(|_| PinnedSessionError)
    }
}

#[cfg(test)]
fn collect_pinned_runtime_events<H: PinnedRuntimeHandle>(
    handle: &H,
    started: Instant,
    terminate_after: Duration,
    cleanup_wait: Duration,
) -> Result<Vec<Vec<u8>>, PinnedSessionError> {
    collect_pinned_runtime_events_with(handle, started, terminate_after, cleanup_wait, |_| Ok(()))
}

#[cfg(any(target_os = "macos", test))]
fn collect_pinned_runtime_events_with<H, F>(
    handle: &H,
    started: Instant,
    terminate_after: Duration,
    cleanup_wait: Duration,
    mut publish: F,
) -> Result<Vec<Vec<u8>>, PinnedSessionError>
where
    H: PinnedRuntimeHandle,
    F: FnMut(&[u8]) -> Result<(), PinnedSessionError>,
{
    let mut events = Vec::new();
    let mut termination_requested = false;
    let mut failed = false;
    let mut cleanup_deadline = None;
    loop {
        if !termination_requested && started.elapsed() >= terminate_after {
            termination_requested = true;
            cleanup_deadline = Some(Instant::now() + cleanup_wait);
            if handle.terminate().is_err() {
                failed = true;
            }
        }
        if cleanup_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let _ = handle.terminate_and_wait(Duration::ZERO);
            return Err(PinnedSessionError);
        }
        let poll_timeout = cleanup_deadline
            .map(|deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(250))
            })
            .unwrap_or(Duration::from_millis(250));
        match handle.next_event(poll_timeout) {
            EventPoll::Event(event) if event.kind == RuntimeEventKind::Failed => {
                failed = true;
                if !termination_requested {
                    termination_requested = true;
                    cleanup_deadline = Some(Instant::now() + cleanup_wait);
                    let _ = handle.terminate();
                }
            }
            EventPoll::Event(event) => {
                let terminal = event.kind == RuntimeEventKind::Exited;
                let success = event.exit.as_ref().is_some_and(|exit| exit.success);
                if !failed {
                    let line = event_json_line(&event)?;
                    publish(&line)?;
                    events.push(line);
                }
                if terminal {
                    let completion = handle.terminate_and_wait(cleanup_wait);
                    return if completion.is_err() || !handle.is_finished() || failed {
                        Err(PinnedSessionError)
                    } else if success || termination_requested {
                        Ok(events)
                    } else {
                        Err(PinnedSessionError)
                    };
                }
            }
            EventPoll::Timeout => {}
            EventPoll::Closed => {
                let _ = handle.terminate_and_wait(cleanup_wait);
                return Err(PinnedSessionError);
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn drain_pinned_integrity_shutdown<H: PinnedRuntimeHandle>(
    handle: &H,
    cleanup_wait: Duration,
) -> Result<(), PinnedSessionError> {
    let deadline = Instant::now() + cleanup_wait;
    let mut cleanup_failed = false;
    loop {
        if Instant::now() >= deadline {
            let _ = handle.terminate_and_wait(Duration::ZERO);
            return Err(PinnedSessionError);
        }
        let poll_timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        match handle.next_event(poll_timeout) {
            EventPoll::Event(event) if event.kind == RuntimeEventKind::Exited => {
                let completion = handle.terminate_and_wait(cleanup_wait);
                return if completion.is_err() || !handle.is_finished() || cleanup_failed {
                    Err(PinnedSessionError)
                } else {
                    Ok(())
                };
            }
            EventPoll::Event(event) if event.kind == RuntimeEventKind::Failed => cleanup_failed = true,
            EventPoll::Event(_) | EventPoll::Timeout => {}
            EventPoll::Closed => {
                let _ = handle.terminate_and_wait(cleanup_wait);
                return Err(PinnedSessionError);
            }
        }
    }
}

#[cfg(test)]
fn pinned_transcript_bytes(transcript: &PinnedSessionTranscript) -> Result<Vec<u8>, PinnedSessionError> {
    let receipt = pinned_receipt_line(&transcript.receipt)?;
    let total_length = transcript
        .events
        .iter()
        .try_fold(receipt.len(), |total, event| total.checked_add(event.len()))
        .ok_or(PinnedSessionError)?;
    let mut output = Vec::with_capacity(total_length);
    for event in &transcript.events {
        output.extend_from_slice(&project_pinned_runtime_event_line(event)?);
    }
    output.extend_from_slice(&receipt);
    Ok(output)
}

#[cfg(any(target_os = "macos", test))]
fn project_pinned_runtime_event_line(line: &[u8]) -> Result<Vec<u8>, PinnedSessionError> {
    let payload = line.strip_suffix(b"\n").ok_or(PinnedSessionError)?;
    let mut event: compatforge_domain::RuntimeEvent =
        serde_json::from_slice(payload).map_err(|_| PinnedSessionError)?;
    if event.schema_version != "1" || event.request_id != PINNED_RUNTIME_REQUEST_ID || event.output.is_some() {
        return Err(PinnedSessionError);
    }
    let expected_message = match event.kind {
        RuntimeEventKind::Started => None,
        RuntimeEventKind::TerminateRequested => Some("termination requested"),
        RuntimeEventKind::TimedOut => Some("maximum runtime exceeded"),
        RuntimeEventKind::GracePeriodExpired => {
            Some("graceful termination period expired; forcing process tree shutdown")
        }
        RuntimeEventKind::WineServerStopRequested => {
            let prefix = event
                .message
                .as_deref()
                .and_then(|message| message.strip_prefix("stopping wineserver for prefix "))
                .ok_or(PinnedSessionError)?;
            if !is_closed_macos_absolute_path(prefix) {
                return Err(PinnedSessionError);
            }
            event.message = Some("stopping wineserver".into());
            Some("stopping wineserver")
        }
        RuntimeEventKind::Exited => None,
        RuntimeEventKind::Output | RuntimeEventKind::Failed => return Err(PinnedSessionError),
    };
    if event.message.as_deref() != expected_message || (event.kind == RuntimeEventKind::Exited) != event.exit.is_some()
    {
        return Err(PinnedSessionError);
    }
    let mut projected = serde_json::to_vec(&event).map_err(|_| PinnedSessionError)?;
    projected.push(b'\n');
    if event.kind != RuntimeEventKind::WineServerStopRequested && projected != line {
        return Err(PinnedSessionError);
    }
    Ok(projected)
}

#[cfg(target_os = "macos")]
fn run_streamed_macos_pinned_session(session: &mut MacOsClosedPinnedSession<'_>) -> Result<(), PinnedSessionError> {
    session.validate_closed_inputs()?;
    session.capture_source()?;
    session.prepare_pinned()?;
    session.authorize_pinned()?;
    session.publish_evidence()?;
    let timed = session.start_pinned()?;
    if let Err(integrity_error) = session.post_spawn_revalidate() {
        session.shutdown_integrity_failure(timed)?;
        return Err(integrity_error);
    }

    let mut stdout = io::stdout().lock();
    collect_pinned_runtime_events_with(
        &timed.handle,
        timed.started,
        session.terminate_after,
        timed.cleanup_wait,
        |line| {
            let projected = project_pinned_runtime_event_line(line)?;
            stdout.write_all(&projected).map_err(|_| PinnedSessionError)?;
            stdout.flush().map_err(|_| PinnedSessionError)
        },
    )?;
    session.finalize_session()?;
    let receipt = pinned_receipt_line(&session.evidence_receipt()?)?;
    stdout.write_all(&receipt).map_err(|_| PinnedSessionError)?;
    stdout.flush().map_err(|_| PinnedSessionError)
}

fn run_pinned_prepared_command(command: PreparedCommand<'_>) -> Result<(), PinnedSessionError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = command;
        Err(PinnedSessionError)
    }
    #[cfg(target_os = "macos")]
    {
        let mut session = MacOsClosedPinnedSession::new(command)?;
        run_streamed_macos_pinned_session(&mut session)
    }
}

fn run_prepared_command(command: PreparedCommand<'_>) -> Result<(), Box<dyn Error>> {
    if matches!(command, PreparedCommand::PinnedSumatraPdfLaunchTerminate { .. }) {
        return run_pinned_prepared_command(command).map_err(|error| Box::new(error) as Box<dyn Error>);
    }

    let (config_path, executable_path, request_path) = match command {
        PreparedCommand::Plan {
            config_path,
            executable_path,
            request_path,
        }
        | PreparedCommand::Launch {
            config_path,
            executable_path,
            request_path,
            ..
        } => (config_path, executable_path, request_path),
        PreparedCommand::PinnedSumatraPdfLaunchTerminate { .. } => unreachable!(),
    };
    let config = read_json::<CoreConfig>(Path::new(config_path))?;
    let request = read_json::<LaunchRequest>(Path::new(request_path))?;
    let source = strict_absolute_path(Path::new(executable_path))?;
    let prepared = PreparedLaunch::prepare(&config, &source, &request)?;
    let plan = prepared.authorize(&config)?;
    match command {
        PreparedCommand::Plan { .. } => println!("{}", serde_json::to_string_pretty(plan)?),
        PreparedCommand::Launch {
            terminate_after_milliseconds,
            ..
        } => supervise_plan(plan, terminate_after_milliseconds.map(Duration::from_millis))?,
        PreparedCommand::PinnedSumatraPdfLaunchTerminate { .. } => unreachable!(),
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BottleCommand<'a> {
    Snapshot {
        store_root: &'a str,
        source_root: &'a str,
    },
    Plan {
        store_root: &'a str,
        snapshot_digest: &'a str,
        runtime_store_root: &'a str,
        runtime_map_path: &'a str,
    },
    Import {
        store_root: &'a str,
        snapshot_digest: &'a str,
        runtime_store_root: &'a str,
        runtime_map_path: &'a str,
    },
    Verify {
        store_root: &'a str,
        bottle_id: &'a str,
    },
    Rollback {
        store_root: &'a str,
        bottle_id: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct BottleVerifyReceipt {
    bottle_id: String,
    verified: bool,
}

fn parse_bottle_command(arguments: &[String]) -> Option<BottleCommand<'_>> {
    match arguments {
        [group, command, store_root, source_root] if group == "bottle" && command == "snapshot" => {
            Some(BottleCommand::Snapshot {
                store_root,
                source_root,
            })
        }
        [group, command, store_root, snapshot_digest, runtime_store_root, runtime_map_path]
            if group == "bottle" && command == "plan" =>
        {
            Some(BottleCommand::Plan {
                store_root,
                snapshot_digest,
                runtime_store_root,
                runtime_map_path,
            })
        }
        [group, command, store_root, snapshot_digest, runtime_store_root, runtime_map_path]
            if group == "bottle" && command == "import" =>
        {
            Some(BottleCommand::Import {
                store_root,
                snapshot_digest,
                runtime_store_root,
                runtime_map_path,
            })
        }
        [group, command, store_root, bottle_id] if group == "bottle" && command == "verify" => {
            Some(BottleCommand::Verify { store_root, bottle_id })
        }
        [group, command, store_root, bottle_id] if group == "bottle" && command == "rollback" => {
            Some(BottleCommand::Rollback { store_root, bottle_id })
        }
        _ => None,
    }
}

fn run_bottle(arguments: &[String]) -> Result<(), BottleMigrationError> {
    let Some(command) = parse_bottle_command(arguments) else {
        print!("{}", bottle_help_text());
        return Ok(());
    };

    match command {
        BottleCommand::Snapshot {
            store_root,
            source_root,
        } => {
            let receipt = BottleStore::new(PathBuf::from(store_root)).snapshot(Path::new(source_root))?;
            write_stdout(&canonical_json_line(&receipt)?)
        }
        BottleCommand::Plan {
            store_root,
            snapshot_digest,
            runtime_store_root,
            runtime_map_path,
        } => {
            let runtime_map = read_runtime_map(Path::new(runtime_map_path))?;
            let runtime_store = RuntimePackStore::new(PathBuf::from(runtime_store_root));
            let plan =
                BottleStore::new(PathBuf::from(store_root)).plan(snapshot_digest, &runtime_store, &runtime_map)?;
            write_stdout(&canonical_json_line_from_bytes(&plan.canonical_json()?)?)
        }
        BottleCommand::Import {
            store_root,
            snapshot_digest,
            runtime_store_root,
            runtime_map_path,
        } => {
            let runtime_map = read_runtime_map(Path::new(runtime_map_path))?;
            let runtime_store = RuntimePackStore::new(PathBuf::from(runtime_store_root));
            let store = BottleStore::new(PathBuf::from(store_root));
            let plan = store.plan(snapshot_digest, &runtime_store, &runtime_map)?;
            let receipt = store.import_with_runtime(&plan, &runtime_store)?;
            write_stdout(&canonical_json_line(&receipt)?)
        }
        BottleCommand::Verify { store_root, bottle_id } => {
            let store = BottleStore::new(PathBuf::from(store_root));
            store.verify_active(bottle_id)?;
            let receipt = BottleVerifyReceipt {
                bottle_id: bottle_id.to_owned(),
                verified: true,
            };
            write_stdout(&canonical_json_line(&receipt)?)
        }
        BottleCommand::Rollback { store_root, bottle_id } => {
            let receipt = BottleStore::new(PathBuf::from(store_root)).rollback(bottle_id)?;
            write_stdout(&canonical_json_line(&receipt)?)
        }
    }
}

fn read_runtime_map(path: &Path) -> Result<RuntimeMap, BottleMigrationError> {
    let bytes = fs::read(path).map_err(|_| BottleMigrationError::new(DiagnosticCode::InvalidManifest))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| BottleMigrationError::new(DiagnosticCode::InvalidManifest))?;
    RuntimeMap::from_json(text)
}

const MAX_CLI_OUTPUT_BYTES: usize = 1024 * 1024;

fn canonical_json_line<T: Serialize>(value: &T) -> Result<Vec<u8>, BottleMigrationError> {
    let value = serde_json::to_value(value).map_err(|_| BottleMigrationError::new(DiagnosticCode::InvalidManifest))?;
    let bytes = serde_json::to_vec(&canonicalize_json(&value))
        .map_err(|_| BottleMigrationError::new(DiagnosticCode::InvalidManifest))?;
    canonical_json_line_from_bytes(&bytes)
}

fn canonical_json_line_from_bytes(bytes: &[u8]) -> Result<Vec<u8>, BottleMigrationError> {
    if bytes.len() >= MAX_CLI_OUTPUT_BYTES {
        return Err(BottleMigrationError::new(DiagnosticCode::InvalidManifest));
    }
    let mut line = Vec::with_capacity(bytes.len() + 1);
    line.extend_from_slice(bytes);
    line.push(b'\n');
    Ok(line)
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut sorted = Map::new();
            for (key, item) in entries {
                sorted.insert(key.clone(), canonicalize_json(item));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        scalar => scalar.clone(),
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), BottleMigrationError> {
    io::stdout()
        .write_all(bytes)
        .map_err(|_| BottleMigrationError::new(DiagnosticCode::TransactionFailed))
}

fn diagnostic_json(error: &BottleMigrationError) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"{\"code\":\"");
    bytes.extend_from_slice(diagnostic_code(error.code()).as_bytes());
    bytes.extend_from_slice(b"\",\"message\":\"");
    bytes.extend_from_slice(error.message().as_bytes());
    bytes.extend_from_slice(b"\"}");
    bytes.push(b'\n');
    bytes
}

fn diagnostic_code(code: DiagnosticCode) -> &'static str {
    match code {
        DiagnosticCode::UnsupportedPlatform => "unsupported-platform",
        DiagnosticCode::SourceChanged => "source-changed",
        DiagnosticCode::UnsafeEntry => "unsafe-entry",
        DiagnosticCode::InvalidManifest => "invalid-manifest",
        DiagnosticCode::RuntimeUnmapped => "runtime-unmapped",
        DiagnosticCode::RuntimeMismatch => "runtime-mismatch",
        DiagnosticCode::SnapshotCorrupt => "snapshot-corrupt",
        DiagnosticCode::TargetCollision => "target-collision",
        DiagnosticCode::TransactionFailed => "transaction-failed",
        DiagnosticCode::RollbackUnavailable => "rollback-unavailable",
        DiagnosticCode::RollbackCorrupt => "rollback-corrupt",
    }
}

fn bottle_help_text() -> &'static str {
    "CompatForge Bottle migration CLI\nusage:\n  compatforge-cli bottle snapshot <store-root> <legacy-bottle-root>\n  compatforge-cli bottle plan <store-root> <snapshot-digest> <runtime-store-root> <runtime-map.json>\n  compatforge-cli bottle import <store-root> <snapshot-digest> <runtime-store-root> <runtime-map.json>\n  compatforge-cli bottle verify <store-root> <bottle-id>\n  compatforge-cli bottle rollback <store-root> <bottle-id>\n"
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn strict_absolute_path(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() || path.components().any(|component| component == Component::ParentDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "prepared executable path must be absolute without parent traversal",
        ));
    }
    Ok(path.to_owned())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn run_api_session(service: AutomationService) -> Result<(), Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request: ServiceRequest = serde_json::from_str(&line)?;
        serde_json::to_writer(&mut stdout, &service.call(request)?)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

fn print_plan(config: &CoreConfig, request: &LaunchRequest) -> Result<(), Box<dyn Error>> {
    let plan = PolicyEngine::compile(config, request)?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

fn launch(
    config: &CoreConfig,
    request: &LaunchRequest,
    terminate_after: Option<Duration>,
) -> Result<(), Box<dyn Error>> {
    let plan: LaunchPlan = PolicyEngine::compile(config, request)?;
    PolicyEngine::authorize(config, &plan)?;
    supervise_plan(&plan, terminate_after)
}

fn supervise_plan(plan: &LaunchPlan, terminate_after: Option<Duration>) -> Result<(), Box<dyn Error>> {
    let handle = ProcessSupervisor::start(plan)?;
    let configured = ConfiguredLaunch {
        handle,
        grace: Duration::from_millis(plan.lifecycle.termination_grace_milliseconds),
    };
    let mut sink = JsonLineEventSink(io::stdout().lock());
    supervise_launch(
        &configured,
        &mut sink,
        terminate_after.map_or(CompletionMode::Normal, CompletionMode::TerminateAfter),
    )
}

trait SupervisedLaunch {
    fn next_event(&self, timeout: Duration) -> EventPoll;
    fn terminate(&self) -> Result<(), ProcessError>;
    fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), ProcessError>;
    fn is_finished(&self) -> bool;
    fn grace_period(&self) -> Duration {
        Duration::from_secs(3)
    }
}

impl SupervisedLaunch for LaunchHandle {
    fn next_event(&self, timeout: Duration) -> EventPoll {
        self.next_event(timeout)
    }
    fn terminate(&self) -> Result<(), ProcessError> {
        self.terminate()
    }
    fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), ProcessError> {
        self.terminate_and_wait(graceful_wait)
    }
    fn is_finished(&self) -> bool {
        self.is_finished()
    }
}

struct ConfiguredLaunch {
    handle: LaunchHandle,
    grace: Duration,
}
impl SupervisedLaunch for ConfiguredLaunch {
    fn next_event(&self, timeout: Duration) -> EventPoll {
        self.handle.next_event(timeout)
    }
    fn terminate(&self) -> Result<(), ProcessError> {
        self.handle.terminate()
    }
    fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), ProcessError> {
        self.handle.terminate_and_wait(graceful_wait)
    }
    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
    fn grace_period(&self) -> Duration {
        self.grace
    }
}

trait EventSink {
    fn write_event(&mut self, event: &compatforge_domain::RuntimeEvent) -> io::Result<()>;
}

struct JsonLineEventSink<W: Write>(W);
impl<W: Write> EventSink for JsonLineEventSink<W> {
    fn write_event(&mut self, event: &compatforge_domain::RuntimeEvent) -> io::Result<()> {
        serde_json::to_writer(&mut self.0, event).map_err(io::Error::other)?;
        self.0.write_all(b"\n")?;
        self.0.flush()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionMode {
    Normal,
    TerminateAfter(Duration),
}

#[derive(Default)]
struct SupervisionState {
    next_sequence: u64,
    request_id: Option<String>,
    exited: bool,
    success: bool,
    failed: bool,
    timed_out: bool,
    grace_expired: bool,
    invalid: bool,
    sink_failed: bool,
    awaiting_explicit_ack: bool,
    explicit_termination_acknowledged: bool,
}

impl SupervisionState {
    fn consume(&mut self, event: &compatforge_domain::RuntimeEvent, sink: &mut dyn EventSink) {
        let valid = !self.exited
            && !self.invalid
            && event.sequence == self.next_sequence
            && (event.kind == RuntimeEventKind::Started) == (self.next_sequence == 0)
            && event.schema_version == compatforge_domain::SCHEMA_VERSION_V1
            && !event.request_id.is_empty()
            && self.request_id.as_ref().map_or(true, |id| id == &event.request_id)
            && event.process_id != Some(0)
            && (event.kind != RuntimeEventKind::Output || event.output.is_some())
            && (event.kind != RuntimeEventKind::Exited || event.exit.is_some())
            && (event.kind != RuntimeEventKind::Failed || event.message.is_some());
        if !valid {
            self.invalid = true;
            return;
        }
        self.request_id.get_or_insert_with(|| event.request_id.clone());
        if let Some(next) = self.next_sequence.checked_add(1) {
            self.next_sequence = next;
        } else {
            self.invalid = true;
        }
        match event.kind {
            RuntimeEventKind::TerminateRequested if self.awaiting_explicit_ack => {
                self.explicit_termination_acknowledged = true;
            }
            RuntimeEventKind::Failed => self.failed = true,
            RuntimeEventKind::TimedOut => self.timed_out = true,
            RuntimeEventKind::GracePeriodExpired => self.grace_expired = true,
            RuntimeEventKind::Exited => {
                self.exited = true;
                self.success = event.exit.as_ref().is_some_and(|exit| exit.success);
            }
            _ => {}
        }
        if !self.sink_failed && sink.write_event(event).is_err() {
            self.sink_failed = true;
        }
    }

    fn needs_shutdown(&self, explicit_termination: bool) -> bool {
        self.failed
            || self.timed_out
            || self.invalid
            || self.sink_failed
            || (self.grace_expired && !explicit_termination)
    }
}

fn supervise_launch(
    handle: &dyn SupervisedLaunch,
    sink: &mut dyn EventSink,
    mode: CompletionMode,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    supervise_launch_with_elapsed(handle, sink, mode, || started.elapsed())
}

fn supervise_launch_with_elapsed(
    handle: &dyn SupervisedLaunch,
    sink: &mut dyn EventSink,
    mode: CompletionMode,
    mut elapsed: impl FnMut() -> Duration,
) -> Result<(), Box<dyn Error>> {
    let terminate_after = match mode {
        CompletionMode::Normal => None,
        CompletionMode::TerminateAfter(delay) => Some(delay),
    };
    let mut termination_requested = false;
    let mut termination_failed = false;
    let mut premature_closed = false;
    let mut state = SupervisionState::default();
    const MAX_COMPLETION_DRAIN_EVENTS: usize = 1024;

    loop {
        if !termination_requested && terminate_after.is_some_and(|delay| elapsed() >= delay) {
            // Publishing a previous event may cross the timer boundary after the guest already exited.
            // Consume that queued evidence before deciding this is an explicit termination.
            let mut queue_empty = false;
            for index in 0..=MAX_COMPLETION_DRAIN_EVENTS {
                match handle.next_event(Duration::ZERO) {
                    EventPoll::Event(event) => {
                        if index == MAX_COMPLETION_DRAIN_EVENTS {
                            state.invalid = true;
                            break;
                        }
                        state.consume(&event, sink);
                        if state.exited || state.needs_shutdown(false) {
                            break;
                        }
                    }
                    EventPoll::Timeout => {
                        queue_empty = true;
                        break;
                    }
                    EventPoll::Closed => {
                        premature_closed = !state.exited;
                        break;
                    }
                }
            }
            if state.needs_shutdown(false) {
                termination_failed = handle.terminate().is_err();
            } else if queue_empty {
                termination_requested = true;
                // terminate() can return Ok after completion without accepting a new request.
                // Only a valid subsequent TerminateRequested before Exited proves acceptance.
                state.awaiting_explicit_ack = true;
                termination_failed = handle.terminate().is_err();
            }
            break;
        }
        match handle.next_event(Duration::from_millis(250)) {
            EventPoll::Event(event) => {
                state.consume(&event, sink);
                if state.needs_shutdown(termination_requested) {
                    // Do not wait for a terminal event from an already failing producer or sink.
                    if !termination_requested {
                        termination_failed = handle.terminate().is_err();
                    }
                    break;
                }
                if state.exited {
                    break;
                }
            }
            EventPoll::Timeout => {
                if handle.is_finished() {
                    break;
                }
            }
            EventPoll::Closed => {
                premature_closed = !state.exited;
                break;
            }
        }
    }

    // This is the authoritative completion acknowledgement, even after Exited or a failed terminate.
    let cleanup = handle.terminate_and_wait(handle.grace_period());
    // A joined supervisor cannot enqueue more events. Bound even a faulty adapter's drain.
    for index in 0..=MAX_COMPLETION_DRAIN_EVENTS {
        match handle.next_event(Duration::ZERO) {
            EventPoll::Event(event) => {
                if index == MAX_COMPLETION_DRAIN_EVENTS {
                    state.invalid = true;
                    break;
                }
                state.consume(&event, sink);
            }
            EventPoll::Timeout | EventPoll::Closed => break,
        }
    }
    // Cleanup failure has precedence over guest, transcript, publication, or termination errors.
    cleanup?;
    let explicit_termination = termination_requested && state.explicit_termination_acknowledged;
    if premature_closed
        || termination_failed
        || state.needs_shutdown(explicit_termination)
        || !state.exited
        || !(state.success || explicit_termination)
    {
        return Err(io::Error::other("supervised launch did not complete successfully").into());
    }
    Ok(())
}

fn print_help() {
    println!("CompatForge Core CLI");
    println!("usage:");
    println!("  compatforge-cli version");
    println!("  compatforge-cli probe");
    println!("  compatforge-cli provider linux probe <provider-config.json>");
    println!("  compatforge-cli provider linux context <provider-config.json> <storage-root>");
    println!("  compatforge-cli local linux context <bootstrap-request.json> [<private-context-output.json>]");
    println!("  compatforge-cli inspect <windows-executable>");
    println!("  compatforge-cli provider macos probe <provider-config.json>");
    println!("  compatforge-cli provider macos context <provider-config.json> <storage-root>");
    println!("  compatforge-cli local macos context <bootstrap-request.json>");
    println!("  compatforge-cli local macos context <bootstrap-request.json> <private-context-output.json>");
    println!("  compatforge-cli demo-plan");
    println!("  compatforge-cli plan <context-config.json> <launch-request.json>");
    println!(
        "  compatforge-cli prepared-plan <context-config.json> <absolute-windows-executable> <launch-request.json>"
    );
    println!(
        "  compatforge-cli prepared-launch <context-config.json> <absolute-windows-executable> <launch-request.json>"
    );
    println!("  compatforge-cli prepared-launch-terminate <context-config.json> <absolute-windows-executable> <launch-request.json> <delay-ms>");
    println!("  compatforge-cli launch <context-config.json> <launch-request.json>");
    println!("  compatforge-cli launch-terminate <context-config.json> <launch-request.json> <delay-ms>");
    println!("  compatforge-cli api <context-config.json> <service-config.json> <service-request.json>");
    println!("  compatforge-cli api-session <context-config.json> <service-config.json>  # JSON Lines on stdin/stdout");
    println!("  compatforge-cli runtime manifest-digest <manifest.json>");
    println!("  compatforge-cli runtime install <store-root> <bundle-root> <manifest-relative-path>");
    println!("  compatforge-cli runtime verify <store-root> <pack-digest>");
    println!("  compatforge-cli runtime rollback <store-root> <pack-id>");
    print!("{}", bottle_help_text());
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SupervisionFake {
        events: std::cell::RefCell<std::collections::VecDeque<EventPoll>>,
        after_terminate: std::cell::RefCell<std::collections::VecDeque<EventPoll>>,
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        cleanup_error: bool,
        terminate_error: bool,
        finished: bool,
        grace: Duration,
    }
    impl SupervisionFake {
        fn new(events: Vec<EventPoll>) -> Self {
            Self {
                events: std::cell::RefCell::new(events.into()),
                after_terminate: Default::default(),
                calls: Default::default(),
                cleanup_error: false,
                terminate_error: false,
                finished: true,
                grace: Duration::from_secs(3),
            }
        }
    }
    impl SupervisedLaunch for SupervisionFake {
        fn next_event(&self, timeout: Duration) -> EventPoll {
            self.calls
                .borrow_mut()
                .push(if timeout.is_zero() { "drain" } else { "poll" }.into());
            assert!(self.calls.borrow().len() < 100, "supervision must not poll forever");
            self.events.borrow_mut().pop_front().unwrap_or(EventPoll::Timeout)
        }
        fn terminate(&self) -> Result<(), ProcessError> {
            self.calls.borrow_mut().push("terminate".into());
            self.events
                .borrow_mut()
                .extend(self.after_terminate.borrow_mut().drain(..));
            if self.terminate_error {
                Err(ProcessError::Terminate(io::Error::other("terminate failed")))
            } else {
                Ok(())
            }
        }
        fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), ProcessError> {
            self.calls
                .borrow_mut()
                .push(format!("cleanup:{}", graceful_wait.as_millis()));
            if self.cleanup_error {
                Err(ProcessError::Terminate(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cleanup deadline",
                )))
            } else {
                Ok(())
            }
        }
        fn is_finished(&self) -> bool {
            self.calls.borrow_mut().push("finished".into());
            self.finished
        }
        fn grace_period(&self) -> Duration {
            self.grace
        }
    }
    struct SupervisionSink {
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        fail: bool,
    }
    impl EventSink for SupervisionSink {
        fn write_event(&mut self, event: &compatforge_domain::RuntimeEvent) -> io::Result<()> {
            self.calls.borrow_mut().push(format!("write:{}", event.sequence));
            if self.fail {
                Err(io::Error::other("sink failure"))
            } else {
                Ok(())
            }
        }
    }
    fn supervised_event(sequence: u64, kind: RuntimeEventKind, success: bool) -> EventPoll {
        EventPoll::Event(compatforge_domain::RuntimeEvent {
            schema_version: "1".into(),
            request_id: "supervised-test".into(),
            sequence,
            elapsed_milliseconds: sequence,
            kind,
            process_id: Some(1),
            output: (kind == RuntimeEventKind::Output).then(|| compatforge_domain::ProcessOutput {
                stream: compatforge_domain::OutputStream::Stdout,
                text: "output".into(),
            }),
            exit: (kind == RuntimeEventKind::Exited).then_some(compatforge_domain::ProcessExit {
                code: Some(if success { 0 } else { 1 }),
                success,
            }),
            message: (kind == RuntimeEventKind::Failed).then(|| "failed".into()),
        })
    }
    fn check_supervision(
        fake: &SupervisionFake,
        mode: CompletionMode,
        fail_sink: bool,
        success: bool,
        expected: &[&str],
    ) -> Option<String> {
        let mut sink = SupervisionSink {
            calls: fake.calls.clone(),
            fail: fail_sink,
        };
        let result = supervise_launch(fake, &mut sink, mode);
        assert_eq!(result.is_ok(), success);
        assert_eq!(*fake.calls.borrow(), expected);
        result.err().map(|error| error.to_string())
    }

    #[test]
    fn supervise_plan_success_still_acknowledges_cleanup_and_drains() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            true,
            &["poll", "write:0", "poll", "write:1", "cleanup:3000", "drain"],
        );
    }

    #[test]
    fn supervise_plan_timer_boundary_preserves_queued_natural_exit_after_slow_sink() {
        struct SlowSink<'a> {
            inner: SupervisionSink,
            elapsed: &'a std::cell::Cell<Duration>,
        }
        impl EventSink for SlowSink<'_> {
            fn write_event(&mut self, event: &compatforge_domain::RuntimeEvent) -> io::Result<()> {
                self.inner.write_event(event)?;
                self.elapsed.set(Duration::from_millis(51));
                Ok(())
            }
        }
        for guest_success in [false, true] {
            let fake = SupervisionFake::new(vec![
                supervised_event(0, RuntimeEventKind::Started, false),
                supervised_event(1, RuntimeEventKind::Exited, guest_success),
            ]);
            let elapsed = std::cell::Cell::new(Duration::ZERO);
            let mut sink = SlowSink {
                inner: SupervisionSink {
                    calls: fake.calls.clone(),
                    fail: false,
                },
                elapsed: &elapsed,
            };
            let result = supervise_launch_with_elapsed(
                &fake,
                &mut sink,
                CompletionMode::TerminateAfter(Duration::from_millis(50)),
                || elapsed.get(),
            );
            assert_eq!(result.is_ok(), guest_success);
            assert_eq!(
                *fake.calls.borrow(),
                ["poll", "write:0", "drain", "write:1", "cleanup:3000", "drain"]
            );
        }
    }

    #[test]
    fn supervise_plan_timer_boundary_noop_termination_does_not_waive_guest_failure() {
        for success in [false, true] {
            let fake = SupervisionFake::new(vec![supervised_event(0, RuntimeEventKind::Started, false)]);
            fake.after_terminate
                .borrow_mut()
                .push_back(supervised_event(1, RuntimeEventKind::Exited, success));
            check_supervision(
                &fake,
                CompletionMode::TerminateAfter(Duration::ZERO),
                false,
                success,
                &[
                    "drain",
                    "write:0",
                    "drain",
                    "terminate",
                    "cleanup:3000",
                    "drain",
                    "write:1",
                    "drain",
                ],
            );
        }
    }

    #[test]
    fn supervise_plan_timer_boundary_does_not_accept_preexisting_or_invalid_termination_ack() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::TerminateRequested, false),
        ]);
        fake.after_terminate
            .borrow_mut()
            .push_back(supervised_event(2, RuntimeEventKind::Exited, false));
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::ZERO),
            false,
            false,
            &[
                "drain",
                "write:0",
                "drain",
                "write:1",
                "drain",
                "terminate",
                "cleanup:3000",
                "drain",
                "write:2",
                "drain",
            ],
        );

        let fake = SupervisionFake::new(vec![supervised_event(0, RuntimeEventKind::Started, false)]);
        fake.after_terminate.borrow_mut().extend([
            supervised_event(2, RuntimeEventKind::TerminateRequested, false),
            supervised_event(3, RuntimeEventKind::Exited, false),
        ]);
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::ZERO),
            false,
            false,
            &[
                "drain",
                "write:0",
                "drain",
                "terminate",
                "cleanup:3000",
                "drain",
                "drain",
                "drain",
            ],
        );

        let fake = SupervisionFake::new(vec![supervised_event(0, RuntimeEventKind::Started, false)]);
        fake.after_terminate.borrow_mut().extend([
            supervised_event(1, RuntimeEventKind::Exited, false),
            supervised_event(2, RuntimeEventKind::TerminateRequested, false),
        ]);
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::ZERO),
            false,
            false,
            &[
                "drain",
                "write:0",
                "drain",
                "terminate",
                "cleanup:3000",
                "drain",
                "write:1",
                "drain",
                "drain",
            ],
        );
    }

    #[test]
    fn supervise_plan_timer_boundary_adverse_or_unpublishable_event_enters_cleanup_immediately() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Failed, false),
            supervised_event(2, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::ZERO),
            false,
            false,
            &[
                "drain",
                "write:0",
                "drain",
                "write:1",
                "terminate",
                "cleanup:3000",
                "drain",
                "write:2",
                "drain",
            ],
        );
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::ZERO),
            true,
            false,
            &["drain", "write:0", "terminate", "cleanup:3000", "drain", "drain"],
        );
    }

    #[test]
    fn supervise_plan_timer_boundary_predrain_is_bounded_even_for_infinite_adapter() {
        #[derive(Default)]
        struct InfiniteOutput {
            sequence: std::cell::Cell<u64>,
            completed: std::cell::Cell<bool>,
            calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        }
        impl SupervisedLaunch for InfiniteOutput {
            fn next_event(&self, timeout: Duration) -> EventPoll {
                assert!(timeout.is_zero());
                self.calls.borrow_mut().push("drain".into());
                if self.completed.get() {
                    return EventPoll::Timeout;
                }
                let sequence = self.sequence.get();
                self.sequence.set(sequence + 1);
                assert!(sequence < 2048, "timer boundary drain must not run forever");
                supervised_event(
                    sequence,
                    if sequence == 0 {
                        RuntimeEventKind::Started
                    } else {
                        RuntimeEventKind::Output
                    },
                    false,
                )
            }
            fn terminate(&self) -> Result<(), ProcessError> {
                self.calls.borrow_mut().push("terminate".into());
                Ok(())
            }
            fn terminate_and_wait(&self, _: Duration) -> Result<(), ProcessError> {
                self.calls.borrow_mut().push("cleanup".into());
                self.completed.set(true);
                Ok(())
            }
            fn is_finished(&self) -> bool {
                self.completed.get()
            }
        }
        let fake = InfiniteOutput::default();
        let mut sink = SupervisionSink {
            calls: fake.calls.clone(),
            fail: false,
        };
        assert!(supervise_launch(&fake, &mut sink, CompletionMode::TerminateAfter(Duration::ZERO)).is_err());
        let mut expected = Vec::new();
        for sequence in 0..1024 {
            expected.push("drain".to_owned());
            expected.push(format!("write:{sequence}"));
        }
        expected.extend(["drain", "terminate", "cleanup", "drain"].map(str::to_owned));
        assert_eq!(*fake.calls.borrow(), expected);
    }
    #[test]
    fn supervise_plan_failed_event_terminates_then_publishes_queued_terminal_in_sequence() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Failed, false),
            supervised_event(2, RuntimeEventKind::Output, false),
            supervised_event(3, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            false,
            &[
                "poll",
                "write:0",
                "poll",
                "write:1",
                "terminate",
                "cleanup:3000",
                "drain",
                "write:2",
                "drain",
                "write:3",
                "drain",
            ],
        );
    }
    #[test]
    fn supervise_plan_failed_without_exited_never_waits_for_forever_timeouts() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Failed, false),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            false,
            &[
                "poll",
                "write:0",
                "poll",
                "write:1",
                "terminate",
                "cleanup:3000",
                "drain",
            ],
        );
    }
    #[test]
    fn supervise_plan_closed_or_finished_timeout_without_exit_refuses_success() {
        for (event, expected) in [
            (EventPoll::Closed, vec!["poll", "cleanup:3000", "drain"]),
            (EventPoll::Timeout, vec!["poll", "finished", "cleanup:3000", "drain"]),
        ] {
            let fake = SupervisionFake::new(vec![event]);
            check_supervision(&fake, CompletionMode::Normal, false, false, &expected);
        }
    }
    #[test]
    fn supervise_plan_cleanup_error_overrides_guest_success_and_sink_failure() {
        for sink_error in [false, true] {
            let mut fake = SupervisionFake::new(vec![
                supervised_event(0, RuntimeEventKind::Started, false),
                supervised_event(1, RuntimeEventKind::Exited, true),
            ]);
            fake.cleanup_error = true;
            let expected = if sink_error {
                vec!["poll", "write:0", "terminate", "cleanup:3000", "drain", "drain"]
            } else {
                vec!["poll", "write:0", "poll", "write:1", "cleanup:3000", "drain"]
            };
            let error = check_supervision(&fake, CompletionMode::Normal, sink_error, false, &expected).unwrap();
            assert!(error.contains("cleanup deadline"));
        }
    }
    #[test]
    fn supervise_plan_sink_error_requests_cleanup_without_missing_exit_hang() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            true,
            false,
            &["poll", "write:0", "terminate", "cleanup:3000", "drain", "drain"],
        );
    }
    #[test]
    fn supervise_plan_explicit_termination_preserves_nonzero_and_grace_expiry_semantics() {
        let fake = SupervisionFake::new(vec![supervised_event(0, RuntimeEventKind::Started, false)]);
        fake.after_terminate.borrow_mut().extend([
            supervised_event(1, RuntimeEventKind::TerminateRequested, false),
            supervised_event(2, RuntimeEventKind::GracePeriodExpired, false),
            supervised_event(3, RuntimeEventKind::Exited, false),
        ]);
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::ZERO),
            false,
            true,
            &[
                "drain",
                "write:0",
                "drain",
                "terminate",
                "cleanup:3000",
                "drain",
                "write:1",
                "drain",
                "write:2",
                "drain",
                "write:3",
                "drain",
            ],
        );
    }
    #[test]
    fn supervise_plan_exit_before_explicit_delay_uses_normal_success_rules() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Exited, false),
        ]);
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::from_secs(60)),
            false,
            false,
            &["poll", "write:0", "poll", "write:1", "cleanup:3000", "drain"],
        );
    }
    #[test]
    fn supervise_plan_configured_grace_is_passed_exactly() {
        for grace in [Duration::from_millis(1), Duration::from_secs(60)] {
            let mut fake = SupervisionFake::new(vec![
                supervised_event(0, RuntimeEventKind::Started, false),
                supervised_event(1, RuntimeEventKind::Exited, true),
            ]);
            fake.grace = grace;
            check_supervision(
                &fake,
                CompletionMode::Normal,
                false,
                true,
                &[
                    "poll",
                    "write:0",
                    "poll",
                    "write:1",
                    &format!("cleanup:{}", grace.as_millis()),
                    "drain",
                ],
            );
        }
    }

    #[test]
    fn supervise_plan_explicit_termination_never_waits_for_missing_terminal() {
        let mut fake = SupervisionFake::new(vec![]);
        fake.finished = false;
        check_supervision(
            &fake,
            CompletionMode::TerminateAfter(Duration::ZERO),
            false,
            false,
            &["drain", "terminate", "cleanup:3000", "drain"],
        );
    }
    #[test]
    fn supervise_plan_requires_started_first_and_refuses_duplicate_started() {
        let fake = SupervisionFake::new(vec![supervised_event(0, RuntimeEventKind::Exited, true)]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            false,
            &["poll", "terminate", "cleanup:3000", "drain"],
        );
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Started, false),
            supervised_event(2, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            false,
            &["poll", "write:0", "poll", "terminate", "cleanup:3000", "drain", "drain"],
        );
    }

    #[test]
    fn supervise_plan_premature_closed_stream_cannot_be_repaired_by_queued_exit() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            EventPoll::Closed,
            supervised_event(1, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            false,
            &["poll", "write:0", "poll", "cleanup:3000", "drain", "write:1", "drain"],
        );
    }

    #[test]
    fn supervise_plan_termination_failure_still_joins_and_cleanup_error_takes_precedence() {
        for cleanup_error in [false, true] {
            let mut fake = SupervisionFake::new(vec![supervised_event(0, RuntimeEventKind::Started, false)]);
            fake.after_terminate
                .borrow_mut()
                .push_back(supervised_event(1, RuntimeEventKind::Exited, true));
            fake.terminate_error = true;
            fake.cleanup_error = cleanup_error;
            let error = check_supervision(
                &fake,
                CompletionMode::TerminateAfter(Duration::ZERO),
                false,
                false,
                &[
                    "drain",
                    "write:0",
                    "drain",
                    "terminate",
                    "cleanup:3000",
                    "drain",
                    "write:1",
                    "drain",
                ],
            )
            .unwrap();
            assert_eq!(error.contains("cleanup deadline"), cleanup_error);
        }
    }

    #[test]
    fn supervise_plan_adverse_events_are_not_waived_by_explicit_termination() {
        for kind in [RuntimeEventKind::Failed, RuntimeEventKind::TimedOut] {
            let fake = SupervisionFake::new(vec![supervised_event(0, RuntimeEventKind::Started, false)]);
            fake.after_terminate.borrow_mut().extend([
                supervised_event(1, RuntimeEventKind::TerminateRequested, false),
                supervised_event(2, kind, false),
                supervised_event(3, RuntimeEventKind::Exited, false),
            ]);
            check_supervision(
                &fake,
                CompletionMode::TerminateAfter(Duration::ZERO),
                false,
                false,
                &[
                    "drain",
                    "write:0",
                    "drain",
                    "terminate",
                    "cleanup:3000",
                    "drain",
                    "write:1",
                    "drain",
                    "write:2",
                    "drain",
                    "write:3",
                    "drain",
                ],
            );
        }
        for kind in [RuntimeEventKind::TimedOut, RuntimeEventKind::GracePeriodExpired] {
            let fake = SupervisionFake::new(vec![
                supervised_event(0, RuntimeEventKind::Started, false),
                supervised_event(1, kind, false),
                supervised_event(2, RuntimeEventKind::Exited, true),
            ]);
            check_supervision(
                &fake,
                CompletionMode::Normal,
                false,
                false,
                &[
                    "poll",
                    "write:0",
                    "poll",
                    "write:1",
                    "terminate",
                    "cleanup:3000",
                    "drain",
                    "write:2",
                    "drain",
                ],
            );
        }
    }

    #[test]
    fn supervise_plan_validates_every_field_and_sequence_before_publication() {
        for field in [
            "schema",
            "request-empty",
            "request-different",
            "pid",
            "sequence",
            "output",
            "exit",
            "message",
        ] {
            let EventPoll::Event(mut event) = supervised_event(1, RuntimeEventKind::Output, false) else {
                unreachable!()
            };
            match field {
                "schema" => event.schema_version = "2".into(),
                "request-empty" => event.request_id.clear(),
                "request-different" => event.request_id = "different".into(),
                "pid" => event.process_id = Some(0),
                "sequence" => event.sequence = 2,
                "output" => event.output = None,
                "exit" => event.kind = RuntimeEventKind::Exited,
                "message" => event.kind = RuntimeEventKind::Failed,
                _ => unreachable!(),
            }
            let fake = SupervisionFake::new(vec![
                supervised_event(0, RuntimeEventKind::Started, false),
                EventPoll::Event(event),
                supervised_event(2, RuntimeEventKind::Exited, true),
            ]);
            check_supervision(
                &fake,
                CompletionMode::Normal,
                false,
                false,
                &["poll", "write:0", "poll", "terminate", "cleanup:3000", "drain", "drain"],
            );
        }
    }

    #[test]
    fn supervise_plan_checks_sequences_during_cleanup_and_rejects_post_terminal_events() {
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Failed, false),
            supervised_event(3, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            false,
            &[
                "poll",
                "write:0",
                "poll",
                "write:1",
                "terminate",
                "cleanup:3000",
                "drain",
                "drain",
            ],
        );
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            supervised_event(1, RuntimeEventKind::Exited, true),
            supervised_event(2, RuntimeEventKind::Output, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            false,
            &["poll", "write:0", "poll", "write:1", "cleanup:3000", "drain", "drain"],
        );
    }

    #[test]
    fn supervise_plan_active_timeout_is_not_completion_but_finished_timeout_drains_exit() {
        let mut fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            EventPoll::Timeout,
            supervised_event(1, RuntimeEventKind::Exited, true),
        ]);
        fake.finished = false;
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            true,
            &[
                "poll",
                "write:0",
                "poll",
                "finished",
                "poll",
                "write:1",
                "cleanup:3000",
                "drain",
            ],
        );
        let fake = SupervisionFake::new(vec![
            supervised_event(0, RuntimeEventKind::Started, false),
            EventPoll::Timeout,
            supervised_event(1, RuntimeEventKind::Exited, true),
        ]);
        check_supervision(
            &fake,
            CompletionMode::Normal,
            false,
            true,
            &[
                "poll",
                "write:0",
                "poll",
                "finished",
                "cleanup:3000",
                "drain",
                "write:1",
                "drain",
            ],
        );
    }

    #[test]
    fn supervise_plan_real_jsonl_serialization_write_newline_and_flush_errors_cleanup() {
        struct FaultWriter {
            boundary: usize,
            written: usize,
            fail_flush: bool,
        }
        impl Write for FaultWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.written >= self.boundary {
                    return Err(io::Error::other("injected write failure"));
                }
                let count = bytes.len().min(self.boundary - self.written);
                self.written += count;
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                if self.fail_flush {
                    Err(io::Error::other("injected flush failure"))
                } else {
                    Ok(())
                }
            }
        }
        let EventPoll::Event(started) = supervised_event(0, RuntimeEventKind::Started, false) else {
            unreachable!()
        };
        let serialized_len = serde_json::to_vec(&started).unwrap().len();
        // The first failure is an actual serde_json::to_writer error caused by its underlying writer.
        for (boundary, fail_flush) in [(0, false), (serialized_len, false), (usize::MAX, true)] {
            let fake = SupervisionFake::new(vec![
                EventPoll::Event(started.clone()),
                supervised_event(1, RuntimeEventKind::Exited, true),
            ]);
            let mut sink = JsonLineEventSink(FaultWriter {
                boundary,
                written: 0,
                fail_flush,
            });
            assert!(supervise_launch(&fake, &mut sink, CompletionMode::Normal).is_err());
            assert_eq!(
                *fake.calls.borrow(),
                ["poll", "terminate", "cleanup:3000", "drain", "drain"]
            );
        }
    }

    #[test]
    fn linux_provider_argv_accepts_only_exact_forms() {
        for (argv, expected) in [
            (
                words(&["provider", "linux", "probe", "config"]),
                LinuxCommand::Probe("config"),
            ),
            (
                words(&["provider", "linux", "context", "config", "storage"]),
                LinuxCommand::Context("config", "storage"),
            ),
            (
                words(&["local", "linux", "context", "request"]),
                LinuxCommand::Local("request", None),
            ),
            (
                words(&["local", "linux", "context", "request", "output"]),
                LinuxCommand::Local("request", Some("output")),
            ),
        ] {
            assert_eq!(parse_linux_command(&argv).unwrap(), Some(expected));
            let mut extra = argv.clone();
            extra.push("extra".into());
            if argv.len() != 4 || argv[0] != "local" {
                assert!(parse_linux_command(&extra).is_err());
            }
        }
        for argv in [
            words(&["provider", "linux"]),
            words(&["local", "linux"]),
            words(&["provider", "linux", "porbe", "config"]),
            words(&["provider", "linux", "context", "config"]),
            words(&["local", "linux", "context"]),
            words(&["local", "linux", "probe", "request"]),
        ] {
            assert_eq!(
                parse_linux_command(&argv).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            parse_linux_command(&words(&["provider", "macos", "probe", "config"])).unwrap(),
            None
        );
    }

    #[derive(Default)]
    struct PrivateFs {
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        fail: &'static str,
    }
    struct PrivateFile {
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        fail: &'static str,
    }
    impl Write for PrivateFile {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls.borrow_mut().push("write".into());
            if self.fail == "write" {
                Err(io::Error::other("write"))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl PrivateOutput for PrivateFile {
        fn sync_private(&mut self) -> io::Result<()> {
            self.calls.borrow_mut().push("sync".into());
            if self.fail == "sync" {
                Err(io::Error::other("sync"))
            } else {
                Ok(())
            }
        }
    }
    impl PrivateOutputFs for PrivateFs {
        type Output = PrivateFile;
        fn validate_parent(&self, _: &Path) -> io::Result<()> {
            self.calls.borrow_mut().push("parent".into());
            if matches!(self.fail, "missing" | "symlink" | "directory" | "owner") {
                Err(io::Error::other(self.fail))
            } else {
                Ok(())
            }
        }
        fn create_new(&self, _: &Path, mode: u32) -> io::Result<Self::Output> {
            self.calls.borrow_mut().push(format!("create_new:{mode:o}"));
            if self.fail == "exists" {
                Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists"))
            } else {
                Ok(PrivateFile {
                    calls: self.calls.clone(),
                    fail: self.fail,
                })
            }
        }
        fn remove_partial(&self, _: &Path) -> io::Result<()> {
            self.calls.borrow_mut().push("remove".into());
            Ok(())
        }
    }
    fn private_test_path() -> PathBuf {
        std::env::temp_dir().join("private-context.json")
    }

    #[test]
    fn private_output_uses_create_new_and_mode_at_open() {
        let fs = PrivateFs::default();
        write_private_output_with(&private_test_path(), &serde_json::json!({"secret": 1}), &fs).unwrap();
        let calls = fs.calls.borrow();
        assert_eq!(&calls[..2], ["parent", "create_new:600"]);
        assert_eq!(calls.last().unwrap(), "sync");
        assert!(!calls.iter().any(|call| call == "remove"));
    }

    #[test]
    fn private_output_rejects_unsafe_targets_before_writing() {
        let fs = PrivateFs::default();
        assert!(write_private_output_with(Path::new("relative.json"), &1, &fs).is_err());
        assert!(fs.calls.borrow().is_empty());
        for fail in ["missing", "symlink", "directory", "owner", "exists"] {
            let fs = PrivateFs {
                fail,
                ..Default::default()
            };
            assert!(write_private_output_with(&private_test_path(), &1, &fs).is_err());
            assert!(!fs.calls.borrow().iter().any(|call| call == "write" || call == "remove"));
            assert!(!fs.calls.borrow().is_empty());
        }
    }

    #[test]
    fn private_output_removes_partial_write_sync_and_serialization_failures() {
        struct BadSerialization;
        impl Serialize for BadSerialization {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("serialization"))
            }
        }
        for fail in ["write", "sync", "serialization"] {
            let fs = PrivateFs {
                fail,
                ..Default::default()
            };
            let result = if fail == "serialization" {
                write_private_output_with(&private_test_path(), &BadSerialization, &fs)
            } else {
                write_private_output_with(&private_test_path(), &1, &fs)
            };
            assert!(result.is_err());
            assert_eq!(fs.calls.borrow().last().map(String::as_str), Some("remove"));
        }
    }

    #[test]
    fn private_output_parent_facts_refuse_alias_type_and_foreign_owner() {
        assert!(validate_private_parent_facts(true, false, true, true).is_ok());
        for (directory, symlink, canonical, owner) in [
            (false, false, true, true),
            (true, true, true, true),
            (true, false, false, true),
            (true, false, true, false),
        ] {
            assert!(validate_private_parent_facts(directory, symlink, canonical, owner).is_err());
        }
    }

    struct CliTempDir(PathBuf);
    impl CliTempDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "compatforge-cli-test-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for CliTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_output_real_filesystem_never_overwrites_and_refuses_missing_parent_or_directory() {
        let root = CliTempDir::new();
        let path = root.0.join("private.json");
        write_private_output_with(&path, &serde_json::json!({"secret": 1}), &SystemPrivateOutputFs).unwrap();
        let first = fs::read(&path).unwrap();
        assert!(write_private_output_with(&path, &2, &SystemPrivateOutputFs).is_err());
        assert_eq!(fs::read(&path).unwrap(), first);
        assert!(write_private_output_with(&root.0, &2, &SystemPrivateOutputFs).is_err());
        assert!(write_private_output_with(&root.0.join("missing/private.json"), &2, &SystemPrivateOutputFs).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            let alias = root.0.join("alias");
            symlink(&path, &alias).unwrap();
            assert!(write_private_output_with(&alias, &2, &SystemPrivateOutputFs).is_err());
            let parent_alias = root.0.join("parent-alias");
            symlink(&root.0, &parent_alias).unwrap();
            assert!(write_private_output_with(&parent_alias.join("other.json"), &2, &SystemPrivateOutputFs).is_err());
        }
    }

    #[test]
    fn private_output_absent_when_linux_bootstrap_validation_fails() {
        let root = CliTempDir::new();
        let request = root.0.join("request.json");
        let output = root.0.join("private.json");
        fs::write(&request, b"{}").unwrap();
        assert!(run_arguments(&words(&[
            "local",
            "linux",
            "context",
            request.to_str().unwrap(),
            output.to_str().unwrap()
        ]))
        .is_err());
        assert!(!output.exists());
    }

    #[test]
    fn linux_provider_output_projects_exact_public_or_private_document_for_all_four_forms() {
        // Serialization fixture only: the real provider's HostGate is never replaced.
        let config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let receipt = compatforge_provider_linux::LinuxLocalContextReceipt {
            schema_version: "1".into(),
            source: "local-preview".into(),
            version: "test".into(),
            architecture: compatforge_domain::CpuArchitecture::X86_64,
            pack_id: "preview".into(),
            pack_digest: format!("sha256:{}", "a".repeat(64)),
            capabilities: vec!["guest-x86_64".into()],
        };
        let root = CliTempDir::new();
        let output = root.0.join("private.json");
        for (value, expected) in [
            (
                LinuxOutput::Probe(config.capabilities.clone()),
                serde_json::to_value(&config.capabilities).unwrap(),
            ),
            (
                LinuxOutput::Context(config.clone()),
                serde_json::to_value(&config).unwrap(),
            ),
            (
                LinuxOutput::Local(
                    compatforge_provider_linux::LinuxLocalContext {
                        config: config.clone(),
                        receipt: receipt.clone(),
                    },
                    None,
                ),
                serde_json::to_value(&receipt).unwrap(),
            ),
            (
                LinuxOutput::Local(
                    compatforge_provider_linux::LinuxLocalContext {
                        config: config.clone(),
                        receipt: receipt.clone(),
                    },
                    Some(&output),
                ),
                serde_json::to_value(&receipt).unwrap(),
            ),
        ] {
            let mut stdout = Vec::new();
            publish_linux_output(value, &mut stdout, &SystemPrivateOutputFs).unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&stdout).unwrap(), expected);
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(output).unwrap()).unwrap(),
            serde_json::to_value(config).unwrap()
        );
    }

    fn words(value: &[&str]) -> Vec<String> {
        value.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn absolute_inspection_path_does_not_canonicalize_components() {
        let relative = Path::new("inspection/../inspection-link.exe");
        assert_eq!(
            absolute_path(relative).unwrap(),
            std::env::current_dir().unwrap().join(relative)
        );
    }

    #[test]
    fn prepared_argv_accepts_only_exact_bounded_forms() {
        assert!(matches!(
            parse_prepared_command(&words(&["prepared-plan", "context", "/tmp/probe.exe", "request"])),
            Some(PreparedCommand::Plan { .. })
        ));
        assert!(matches!(
            parse_prepared_command(&words(&["prepared-launch", "context", "/tmp/probe.exe", "request"])),
            Some(PreparedCommand::Launch {
                terminate_after_milliseconds: None,
                ..
            })
        ));
        assert!(matches!(
            parse_prepared_command(&words(&[
                "prepared-launch-terminate",
                "context",
                "/tmp/probe.exe",
                "request",
                "1000",
            ])),
            Some(PreparedCommand::Launch {
                terminate_after_milliseconds: Some(1000),
                ..
            })
        ));
        for invalid in [
            words(&["prepared-launch", "context", "request"]),
            words(&["prepared-launch", "context", "/tmp/probe.exe", "request", "extra"]),
            words(&["prepared-launch-terminate", "context", "/tmp/probe.exe", "request", "0"]),
            words(&[
                "prepared-launch-terminate",
                "context",
                "/tmp/probe.exe",
                "request",
                "86400001",
            ]),
        ] {
            assert!(parse_prepared_command(&invalid).is_none());
            assert!(run_arguments(&invalid).is_err());
        }
    }

    #[test]
    fn pinned_sumatrapdf_argv_accepts_only_the_closed_future_form() {
        let valid = words(&[
            "prepared-pinned-sumatrapdf-launch-terminate",
            "/private/compatforge/context.json",
            "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
            "/private/compatforge/request.json",
            "/private/compatforge/work",
            "7",
            "8",
            "9",
            "1000",
        ]);
        let Some(PreparedCommand::PinnedSumatraPdfLaunchTerminate {
            config_path,
            logical_executable_path,
            request_path,
            external_work_root,
            inherited_work_root_fd,
            inherited_inspection_fd,
            inherited_plan_fd,
            terminate_after_milliseconds,
        }) = parse_prepared_command(&valid)
        else {
            panic!("closed pinned SumatraPDF argv did not select its private command variant");
        };
        assert_eq!(config_path, "/private/compatforge/context.json");
        assert_eq!(
            logical_executable_path,
            "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe"
        );
        assert_eq!(request_path, "/private/compatforge/request.json");
        assert_eq!(external_work_root, "/private/compatforge/work");
        assert_eq!(inherited_work_root_fd, 7);
        assert_eq!(inherited_inspection_fd, 8);
        assert_eq!(inherited_plan_fd, 9);
        assert_eq!(terminate_after_milliseconds, 1000);
        assert_eq!(
            run_arguments(&valid).unwrap_err().to_string(),
            PINNED_SUMATRAPDF_FAILURE
        );

        let invalid = [
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
            ]),
            {
                let mut arguments = valid.clone();
                arguments.push("extra".into());
                arguments
            },
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "relative/context.json",
                "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
                "1000",
            ]),
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-7zip/prefix/drive_c/Program Files/7-Zip/7zFM.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
                "1000",
            ]),
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-7zip/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
                "1000",
            ]),
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
                "1000",
            ]),
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
                "1000",
            ]),
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge//request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
                "1000",
            ]),
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "--work-root",
                "7",
                "8",
                "9",
                "1000",
            ]),
            words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "C:\\compatforge\\context.json",
                "C:\\storage\\gui-sumatrapdf\\CompatForge\\SumatraPDF\\SumatraPDF.exe",
                "C:\\compatforge\\request.json",
                "C:\\compatforge\\work",
                "7",
                "8",
                "9",
                "1000",
            ]),
        ];
        for arguments in invalid {
            assert!(
                parse_prepared_command(&arguments).is_none(),
                "invalid pinned argv reached the private parser variant: {arguments:?}"
            );
            assert_eq!(
                run_arguments(&arguments).unwrap_err().to_string(),
                PINNED_SUMATRAPDF_FAILURE
            );
        }
    }

    #[test]
    fn pinned_sumatrapdf_suffix_rejects_an_ordinary_bottle_id() {
        assert!(!has_fixed_sumatrapdf_suffix(
            "/private/compatforge/storage/bottles/gui-7zip/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe"
        ));
    }

    #[test]
    fn pinned_sumatrapdf_suffix_requires_the_complete_bottle_tail_chain() {
        assert!(!has_fixed_sumatrapdf_suffix(
            "/private/compatforge/CompatForge/SumatraPDF/SumatraPDF.exe"
        ));
    }

    #[test]
    fn pinned_sumatrapdf_suffix_rejects_a_relative_complete_tail_chain() {
        assert!(!has_fixed_sumatrapdf_suffix(
            "bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe"
        ));
    }

    #[test]
    fn pinned_sumatrapdf_argv_accepts_full_i32_descriptors_and_bounded_duration() {
        for (descriptors, milliseconds) in [
            (["2147483647", "8", "9"], "1"),
            (["7", "2147483647", "9"], "1000"),
            (["7", "8", "2147483647"], "1000"),
            (["7", "8", "9"], "86400000"),
        ] {
            let arguments = words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                descriptors[0],
                descriptors[1],
                descriptors[2],
                milliseconds,
            ]);
            assert_eq!(
                run_arguments(&arguments).unwrap_err().to_string(),
                PINNED_SUMATRAPDF_FAILURE
            );
        }

        for milliseconds in ["0", "86400001", "--milliseconds"] {
            let arguments = words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                "7",
                "8",
                "9",
                milliseconds,
            ]);
            assert!(
                parse_prepared_command(&arguments).is_none(),
                "invalid pinned duration reached the private parser variant: {milliseconds}"
            );
            assert_eq!(
                run_arguments(&arguments).unwrap_err().to_string(),
                PINNED_SUMATRAPDF_FAILURE
            );
        }
    }

    #[test]
    fn pinned_sumatrapdf_argv_rejects_noncanonical_or_aliased_descriptors() {
        for (name, descriptors) in [
            ("sign", ["+7", "8", "9"]),
            ("negative", ["-7", "8", "9"]),
            ("whitespace", [" 7", "8", "9"]),
            ("leading-zero", ["07", "8", "9"]),
            ("stdin", ["0", "8", "9"]),
            ("stdout", ["7", "1", "9"]),
            ("stderr", ["7", "8", "2"]),
            ("duplicate-work-inspection", ["7", "7", "9"]),
            ("duplicate-work-plan", ["7", "8", "7"]),
            ("duplicate-inspection-plan", ["7", "8", "8"]),
            ("leading-zero-inspection", ["7", "08", "9"]),
            ("leading-zero-plan", ["7", "8", "09"]),
            ("too-large", ["2147483648", "8", "9"]),
            ("option", ["--work-root-fd", "8", "9"]),
        ] {
            let arguments = words(&[
                "prepared-pinned-sumatrapdf-launch-terminate",
                "/private/compatforge/context.json",
                "/private/compatforge/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe",
                "/private/compatforge/request.json",
                "/private/compatforge/work",
                descriptors[0],
                descriptors[1],
                descriptors[2],
                "1000",
            ]);
            assert!(
                parse_prepared_command(&arguments).is_none(),
                "invalid pinned descriptors reached the private parser variant: {name}"
            );
            assert_eq!(
                run_arguments(&arguments).unwrap_err().to_string(),
                PINNED_SUMATRAPDF_FAILURE,
                "{name}"
            );
        }
    }

    #[derive(Default)]
    struct FakeClosedPinnedSession {
        order: Vec<&'static str>,
        request_id: &'static str,
        source: Vec<u8>,
        captured: Vec<u8>,
        child_bytes: Vec<u8>,
        children_created: usize,
        shutdown: bool,
        pre_spawn_mutation: Option<PreSpawnMutation>,
        source_identity: u64,
        captured_source_identity: u64,
        evidence_descriptors_cloexec: [bool; 4],
        pre_spawn_evidence_mutation: Option<EvidenceDescriptorMutation>,
    }

    #[derive(Clone, Copy)]
    enum PreSpawnMutation {
        Overwrite,
        Replacement,
    }

    #[derive(Clone, Copy)]
    enum EvidenceDescriptorMutation {
        InspectionRaw,
        InspectionOwned,
        PlanRaw,
        PlanOwned,
    }

    impl EvidenceDescriptorMutation {
        fn index(self) -> usize {
            match self {
                Self::InspectionRaw => 0,
                Self::InspectionOwned => 1,
                Self::PlanRaw => 2,
                Self::PlanOwned => 3,
            }
        }
    }

    impl FakeClosedPinnedSession {
        fn stable() -> Self {
            Self {
                request_id: "pinned-sumatrapdf",
                source: b"captured SumatraPDF bytes".to_vec(),
                source_identity: 17,
                evidence_descriptors_cloexec: [true; 4],
                ..Self::default()
            }
        }
    }

    impl ClosedPinnedSession for FakeClosedPinnedSession {
        type Handle = ();

        fn validate_closed_inputs(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("validate");
            if self.request_id == PINNED_RUNTIME_REQUEST_ID {
                Ok(())
            } else {
                Err(PinnedSessionError)
            }
        }

        fn capture_source(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("capture");
            self.captured.clone_from(&self.source);
            self.captured_source_identity = self.source_identity;
            Ok(())
        }

        fn prepare_pinned(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("prepare");
            Ok(())
        }

        fn authorize_pinned(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("authorize");
            Ok(())
        }

        fn publish_evidence(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("publish");
            match self.pre_spawn_mutation {
                Some(PreSpawnMutation::Overwrite) => {
                    self.source = b"foreign overwrite before spawn".to_vec();
                }
                Some(PreSpawnMutation::Replacement) => {
                    self.source = b"foreign replacement before spawn".to_vec();
                    self.source_identity += 1;
                }
                None => {}
            }
            if let Some(mutation) = self.pre_spawn_evidence_mutation {
                self.evidence_descriptors_cloexec[mutation.index()] = false;
            }
            Ok(())
        }

        fn start_pinned(&mut self) -> Result<Self::Handle, PinnedSessionError> {
            self.order.push("start");
            if self.source != self.captured
                || self.source_identity != self.captured_source_identity
                || self.evidence_descriptors_cloexec.contains(&false)
            {
                return Err(PinnedSessionError);
            }
            self.children_created += 1;
            self.child_bytes.clone_from(&self.captured);
            Ok(())
        }

        fn post_spawn_revalidate(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("post-spawn-revalidate");
            if self.source == self.captured {
                Ok(())
            } else {
                Err(PinnedSessionError)
            }
        }

        fn shutdown_integrity_failure(&mut self, _handle: Self::Handle) -> Result<(), PinnedSessionError> {
            self.order.push("shutdown");
            self.shutdown = true;
            Ok(())
        }

        fn supervise_pinned(&mut self, _handle: Self::Handle) -> Result<Vec<Vec<u8>>, PinnedSessionError> {
            self.order.push("supervise");
            Ok(vec![pinned_test_event_line(&pinned_test_runtime_event(
                self.request_id,
                RuntimeEventKind::Exited,
                None,
            ))])
        }

        fn finalize_session(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("finalize");
            Ok(())
        }

        fn evidence_receipt(&self) -> Result<PinnedEvidenceReceipt, PinnedSessionError> {
            PinnedEvidenceReceipt::new(
                PublishedEvidenceBinding {
                    byte_length: 123,
                    sha256: format!("sha256:{}", "a".repeat(64)),
                },
                PublishedEvidenceBinding {
                    byte_length: 456,
                    sha256: format!("sha256:{}", "b".repeat(64)),
                },
            )
        }
    }

    #[test]
    fn pinned_closed_session_runs_each_boundary_in_the_required_order() {
        let mut session = FakeClosedPinnedSession::stable();
        let transcript = run_closed_pinned_session(&mut session).unwrap();
        assert_eq!(
            session.order,
            [
                "validate",
                "capture",
                "prepare",
                "authorize",
                "publish",
                "start",
                "post-spawn-revalidate",
                "supervise",
                "finalize",
            ]
        );
        assert_eq!(
            transcript.events,
            [pinned_test_event_line(&pinned_test_runtime_event(
                PINNED_RUNTIME_REQUEST_ID,
                RuntimeEventKind::Exited,
                None,
            ))]
        );
        assert_eq!(session.children_created, 1);
    }

    #[test]
    fn pinned_success_transcript_has_events_then_exactly_one_final_receipt() {
        let mut session = FakeClosedPinnedSession::stable();
        let transcript = run_closed_pinned_session(&mut session).unwrap();
        let output = String::from_utf8(pinned_transcript_bytes(&transcript).unwrap()).unwrap();
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"kind\":\"exited\""));
        assert_eq!(lines[1].matches("pinned-evidence-receipt").count(), 1);
        assert!(lines[1].starts_with("{\"outputs\":[{\"byteLength\":123,\"kind\":\"inspection\""));
        assert!(lines[1].ends_with("\"recordType\":\"pinned-evidence-receipt\",\"schemaVersion\":1}"));
    }

    fn pinned_test_runtime_event(
        request_id: &str,
        kind: RuntimeEventKind,
        message: Option<&str>,
    ) -> compatforge_domain::RuntimeEvent {
        compatforge_domain::RuntimeEvent {
            schema_version: "1".into(),
            request_id: request_id.into(),
            sequence: 7,
            elapsed_milliseconds: 11,
            kind,
            process_id: Some(41),
            output: None,
            exit: (kind == RuntimeEventKind::Exited).then_some(compatforge_domain::ProcessExit {
                code: Some(0),
                success: true,
            }),
            message: message.map(str::to_owned),
        }
    }

    fn pinned_test_event_line(event: &compatforge_domain::RuntimeEvent) -> Vec<u8> {
        let mut line = serde_json::to_vec(event).unwrap();
        line.push(b'\n');
        line
    }

    fn pinned_test_transcript(event: compatforge_domain::RuntimeEvent) -> PinnedSessionTranscript {
        PinnedSessionTranscript {
            events: vec![pinned_test_event_line(&event)],
            receipt: PinnedEvidenceReceipt::new(
                PublishedEvidenceBinding {
                    byte_length: 123,
                    sha256: format!("sha256:{}", "a".repeat(64)),
                },
                PublishedEvidenceBinding {
                    byte_length: 456,
                    sha256: format!("sha256:{}", "b".repeat(64)),
                },
            )
            .unwrap(),
        }
    }

    #[test]
    fn pinned_request_id_path_and_fd_leaks_are_rejected_before_spawn() {
        for request_id in ["/private/host-secret", "fd-41"] {
            let mut session = FakeClosedPinnedSession {
                request_id,
                ..FakeClosedPinnedSession::stable()
            };
            assert_eq!(run_closed_pinned_session(&mut session), Err(PinnedSessionError));
            assert_eq!(session.children_created, 0);
        }
    }

    #[test]
    fn pinned_transcript_rejects_request_and_message_path_fd_or_temp_leaks() {
        for event in [
            pinned_test_runtime_event("/private/host-secret", RuntimeEventKind::Started, None),
            pinned_test_runtime_event("fd-41", RuntimeEventKind::Started, None),
            pinned_test_runtime_event(
                "pinned-sumatrapdf",
                RuntimeEventKind::TerminateRequested,
                Some("/private/tmp/.compatforge-pinned-random fd-41"),
            ),
        ] {
            assert_eq!(
                pinned_transcript_bytes(&pinned_test_transcript(event)),
                Err(PinnedSessionError)
            );
            assert_eq!(PinnedSessionError.to_string(), PINNED_SUMATRAPDF_FAILURE);
        }
    }

    #[test]
    fn pinned_transcript_redacts_wineserver_prefix_without_dropping_the_event() {
        let transcript = pinned_test_transcript(pinned_test_runtime_event(
            "pinned-sumatrapdf",
            RuntimeEventKind::WineServerStopRequested,
            Some("stopping wineserver for prefix /private/host-secret/fd-41"),
        ));
        let output = String::from_utf8(pinned_transcript_bytes(&transcript).unwrap()).unwrap();
        assert!(!output.contains("/private/host-secret"));
        assert!(!output.contains("fd-41"));
        let event: serde_json::Value = serde_json::from_str(output.lines().next().unwrap()).unwrap();
        assert_eq!(event["kind"], "wine-server-stop-requested");
        assert_eq!(event["message"], "stopping wineserver");
    }

    #[test]
    fn pinned_allowed_runtime_event_serialization_remains_byte_compatible() {
        let event = pinned_test_runtime_event("pinned-sumatrapdf", RuntimeEventKind::Started, None);
        let expected = pinned_test_event_line(&event);
        let output = pinned_transcript_bytes(&pinned_test_transcript(event)).unwrap();
        assert_eq!(&output[..expected.len()], expected);
    }

    struct FakePinnedRuntimeHandle {
        polls: std::sync::Mutex<std::collections::VecDeque<EventPoll>>,
        terminate_fails: bool,
        completion_fails: bool,
        terminate_calls: std::sync::atomic::AtomicUsize,
        completion_calls: std::sync::atomic::AtomicUsize,
        workers_active: std::sync::atomic::AtomicBool,
    }

    impl FakePinnedRuntimeHandle {
        fn new(polls: impl IntoIterator<Item = EventPoll>) -> Self {
            Self {
                polls: std::sync::Mutex::new(polls.into_iter().collect()),
                terminate_fails: false,
                completion_fails: false,
                terminate_calls: std::sync::atomic::AtomicUsize::new(0),
                completion_calls: std::sync::atomic::AtomicUsize::new(0),
                workers_active: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    impl PinnedRuntimeHandle for FakePinnedRuntimeHandle {
        fn next_event(&self, _timeout: Duration) -> EventPoll {
            self.polls.lock().unwrap().pop_front().unwrap_or(EventPoll::Timeout)
        }

        fn terminate(&self) -> Result<(), PinnedSessionError> {
            self.terminate_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.terminate_fails {
                Err(PinnedSessionError)
            } else {
                Ok(())
            }
        }

        fn is_finished(&self) -> bool {
            !self.workers_active.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn terminate_and_wait(&self, _graceful_wait: Duration) -> Result<(), PinnedSessionError> {
            self.completion_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.workers_active.store(false, std::sync::atomic::Ordering::SeqCst);
            if self.completion_fails {
                Err(PinnedSessionError)
            } else {
                Ok(())
            }
        }
    }

    fn pinned_failed_event() -> EventPoll {
        EventPoll::Event(pinned_test_runtime_event(
            PINNED_RUNTIME_REQUEST_ID,
            RuntimeEventKind::Failed,
            Some("cleanup failed at /private/host-secret/fd-41"),
        ))
    }

    fn pinned_exited_event() -> EventPoll {
        EventPoll::Event(pinned_test_runtime_event(
            PINNED_RUNTIME_REQUEST_ID,
            RuntimeEventKind::Exited,
            None,
        ))
    }

    #[test]
    fn pinned_failed_event_waits_for_delayed_exit_and_worker_completion() {
        let handle = FakePinnedRuntimeHandle::new([pinned_failed_event(), EventPoll::Timeout, pinned_exited_event()]);
        assert_eq!(
            collect_pinned_runtime_events(
                &handle,
                Instant::now(),
                Duration::from_secs(60),
                Duration::from_millis(10),
            ),
            Err(PinnedSessionError)
        );
        assert!(!handle.workers_active.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(handle.completion_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn pinned_failed_only_closed_stream_completes_without_waiting_forever() {
        let handle = FakePinnedRuntimeHandle::new([pinned_failed_event(), EventPoll::Closed]);
        assert_eq!(
            collect_pinned_runtime_events(
                &handle,
                Instant::now(),
                Duration::from_secs(60),
                Duration::from_millis(10),
            ),
            Err(PinnedSessionError)
        );
        assert!(!handle.workers_active.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(handle.completion_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn pinned_terminate_and_cleanup_errors_still_join_before_return() {
        for (terminate_fails, completion_fails) in [(true, false), (false, true)] {
            let mut handle = FakePinnedRuntimeHandle::new([pinned_failed_event(), pinned_exited_event()]);
            handle.terminate_fails = terminate_fails;
            handle.completion_fails = completion_fails;
            assert_eq!(
                collect_pinned_runtime_events(
                    &handle,
                    Instant::now(),
                    Duration::from_secs(60),
                    Duration::from_millis(10),
                ),
                Err(PinnedSessionError)
            );
            assert!(!handle.workers_active.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(handle.completion_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn pinned_cleanup_deadline_is_bounded_and_joins_before_error() {
        let handle = FakePinnedRuntimeHandle::new([EventPoll::Timeout]);
        let started = Instant::now();
        assert_eq!(
            collect_pinned_runtime_events(&handle, started, Duration::ZERO, Duration::ZERO),
            Err(PinnedSessionError)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!handle.workers_active.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(handle.completion_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn pinned_success_waits_for_exit_and_worker_completion() {
        let handle = FakePinnedRuntimeHandle::new([pinned_exited_event()]);
        let events = collect_pinned_runtime_events(
            &handle,
            Instant::now(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert!(!handle.workers_active.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn pinned_success_publishes_each_event_before_returning() {
        let handle = FakePinnedRuntimeHandle::new([pinned_exited_event()]);
        let mut published = Vec::new();
        let events = collect_pinned_runtime_events_with(
            &handle,
            Instant::now(),
            Duration::from_secs(60),
            Duration::from_millis(10),
            |line| {
                published.push(line.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(published, events);
        assert_eq!(published.len(), 1);
    }

    #[test]
    fn pinned_integrity_drain_failed_only_closed_is_bounded_and_joined() {
        let handle = FakePinnedRuntimeHandle::new([pinned_failed_event(), EventPoll::Closed]);
        assert_eq!(
            drain_pinned_integrity_shutdown(&handle, Duration::from_millis(10)),
            Err(PinnedSessionError)
        );
        assert!(!handle.workers_active.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn pinned_pre_spawn_overwrite_and_replacement_create_zero_children() {
        for mutation in [PreSpawnMutation::Overwrite, PreSpawnMutation::Replacement] {
            let mut session = FakeClosedPinnedSession {
                pre_spawn_mutation: Some(mutation),
                ..FakeClosedPinnedSession::stable()
            };
            assert_eq!(run_closed_pinned_session(&mut session), Err(PinnedSessionError));
            assert_eq!(session.children_created, 0);
            assert!(!session.shutdown);
        }
    }

    #[test]
    fn pinned_pre_spawn_evidence_cloexec_drift_creates_zero_children() {
        for mutation in [
            EvidenceDescriptorMutation::InspectionRaw,
            EvidenceDescriptorMutation::InspectionOwned,
            EvidenceDescriptorMutation::PlanRaw,
            EvidenceDescriptorMutation::PlanOwned,
        ] {
            let mut session = FakeClosedPinnedSession {
                pre_spawn_evidence_mutation: Some(mutation),
                ..FakeClosedPinnedSession::stable()
            };
            assert_eq!(run_closed_pinned_session(&mut session), Err(PinnedSessionError));
            assert_eq!(session.children_created, 0);
        }
    }

    #[test]
    fn pinned_test_callback_mutates_only_after_child_received_captured_bytes() {
        let mut session = FakeClosedPinnedSession::stable();
        let expected = session.source.clone();
        assert_eq!(
            run_closed_pinned_session_with_test_callback(&mut session, |session| {
                session.source = b"foreign bytes after spawn".to_vec();
            }),
            Err(PinnedSessionError)
        );
        assert_eq!(session.children_created, 1);
        assert_eq!(session.child_bytes, expected);
        assert!(session.shutdown);
        assert_eq!(
            session.order,
            [
                "validate",
                "capture",
                "prepare",
                "authorize",
                "publish",
                "start",
                "post-spawn-revalidate",
                "shutdown",
            ]
        );
    }

    #[test]
    fn pinned_receipt_is_compact_path_free_bounded_and_in_literal_output_order() {
        let receipt = PinnedEvidenceReceipt::new(
            PublishedEvidenceBinding {
                byte_length: 123,
                sha256: format!("sha256:{}", "a".repeat(64)),
            },
            PublishedEvidenceBinding {
                byte_length: 456,
                sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        assert_eq!(
            pinned_receipt_line(&receipt).unwrap(),
            format!(
                "{{\"outputs\":[{{\"byteLength\":123,\"kind\":\"inspection\",\"sha256\":\"sha256:{}\"}},{{\"byteLength\":456,\"kind\":\"plan\",\"sha256\":\"sha256:{}\"}}],\"recordType\":\"pinned-evidence-receipt\",\"schemaVersion\":1}}\n",
                "a".repeat(64),
                "b".repeat(64),
            )
            .into_bytes()
        );
    }

    #[test]
    fn pinned_receipt_rejects_empty_over_limit_and_noncanonical_digests() {
        for (length, digest) in [
            (0, format!("sha256:{}", "a".repeat(64))),
            (1_048_577, format!("sha256:{}", "a".repeat(64))),
            (1, format!("sha256:{}", "A".repeat(64))),
            (1, "sha256:abc".to_owned()),
        ] {
            assert_eq!(
                PinnedEvidenceReceipt::new(
                    PublishedEvidenceBinding {
                        byte_length: length,
                        sha256: digest,
                    },
                    PublishedEvidenceBinding {
                        byte_length: 1,
                        sha256: format!("sha256:{}", "b".repeat(64)),
                    },
                ),
                Err(PinnedSessionError)
            );
        }
    }

    #[test]
    fn pinned_error_mapping_is_one_fixed_path_and_descriptor_free_literal() {
        assert_eq!(PinnedSessionError.to_string(), PINNED_SUMATRAPDF_FAILURE);
        for forbidden in ["/", "\\", "fd", "descriptor", ".compatforge-pinned-"] {
            assert!(!PinnedSessionError.to_string().contains(forbidden));
        }
    }

    #[test]
    fn pinned_session_rejects_request_or_runtime_path_environment() {
        let mut config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let mut request: LaunchRequest =
            serde_json::from_str(include_str!("../../../examples/launch-request.json")).unwrap();
        assert!(!pinned_environment_has_path(&config, &request));
        request.environment.insert("PATH".into(), "/foreign/bin".into());
        assert!(pinned_environment_has_path(&config, &request));
        request.environment.remove("PATH");
        config.runtime_bindings[0]
            .environment
            .insert("PATH".into(), "/foreign/bin".into());
        assert!(pinned_environment_has_path(&config, &request));
    }

    #[test]
    fn bottle_argv_accepts_only_the_documented_positional_forms() {
        assert!(matches!(
            parse_bottle_command(&words(&["bottle", "snapshot", "store", "legacy",])),
            Some(BottleCommand::Snapshot { .. })
        ));
        assert!(matches!(
            parse_bottle_command(&words(&[
                "bottle",
                "plan",
                "store",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "runtime",
                "runtime-map.json",
            ])),
            Some(BottleCommand::Plan { .. })
        ));
        assert!(matches!(
            parse_bottle_command(&words(&[
                "bottle",
                "import",
                "store",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "runtime",
                "runtime-map.json",
            ])),
            Some(BottleCommand::Import { .. })
        ));
        assert!(matches!(
            parse_bottle_command(&words(&["bottle", "verify", "store", "bottle-1"])),
            Some(BottleCommand::Verify { .. })
        ));
        assert!(matches!(
            parse_bottle_command(&words(&["bottle", "rollback", "store", "bottle-1"])),
            Some(BottleCommand::Rollback { .. })
        ));
        assert!(parse_bottle_command(&words(&["bottle", "snapshot", "store"])).is_none());
        assert!(parse_bottle_command(&words(&["bottle", "snapshot", "store", "legacy", "unexpected",])).is_none());
        assert!(parse_bottle_command(&words(&["bottle", "unknown", "store", "legacy"])).is_none());
    }

    #[test]
    fn bottle_help_is_explicit_and_lists_all_stages() {
        let help = bottle_help_text();
        for command in ["snapshot", "plan", "import", "verify", "rollback"] {
            assert!(help.contains(&format!("compatforge-cli bottle {command}")));
        }
    }

    #[test]
    fn bottle_success_json_is_compact_recursively_sorted_and_bounded() {
        let receipt = BottleVerifyReceipt {
            bottle_id: "bottle-1".into(),
            verified: true,
        };
        assert_eq!(
            canonical_json_line(&receipt).unwrap(),
            b"{\"bottleId\":\"bottle-1\",\"verified\":true}\n"
        );
    }

    #[test]
    fn bottle_diagnostic_json_has_only_closed_fields() {
        let error = BottleMigrationError::new(DiagnosticCode::SnapshotCorrupt);
        assert_eq!(
            diagnostic_json(&error),
            b"{\"code\":\"snapshot-corrupt\",\"message\":\"Bottle snapshot is corrupt\"}\n"
        );
    }

    #[test]
    fn bottle_output_rejects_payloads_at_or_above_one_megabyte() {
        let payload = vec![b'x'; MAX_CLI_OUTPUT_BYTES];
        assert_eq!(
            canonical_json_line_from_bytes(&payload).unwrap_err().code(),
            DiagnosticCode::InvalidManifest
        );
    }

    #[test]
    fn bottle_diagnostics_never_reflect_a_supplied_absolute_path() {
        let error = BottleMigrationError::new(DiagnosticCode::InvalidManifest);
        let output = String::from_utf8(diagnostic_json(&error)).unwrap();
        assert!(!output.contains("C:\\Users\\secret"));
        assert!(!output.contains("/home/secret"));
    }
}
