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
#[cfg(target_os = "macos")]
use compatforge_process::LaunchHandle;
use compatforge_process::{EventPoll, ProcessSupervisor};
use compatforge_provider_macos::{
    create_local_context, MacOsLocalContextRequest, MacOsProviderConfig, MacOsProviderSet,
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
const PINNED_SUMATRAPDF_DIAGNOSTIC: &[u8] = b"compatforge-cli: pinned SumatraPDF launch failed\n";

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
            let local = create_local_context(&HostProbe::probe()?, &request)?;
            println!("{}", serde_json::to_string_pretty(&local.receipt)?);
        }
        [group, platform, command, request_path, context_output]
            if group == "local" && platform == "macos" && command == "context" =>
        {
            let request = read_json::<MacOsLocalContextRequest>(Path::new(request_path))?;
            let local = create_local_context(&HostProbe::probe()?, &request)?;
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

#[cfg(any(target_os = "macos", test))]
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
    fn supervise_pinned(&mut self, handle: Self::Handle) -> Result<Vec<Vec<u8>>, PinnedSessionError>;
    fn finalize_session(&mut self) -> Result<(), PinnedSessionError>;
    fn evidence_receipt(&self) -> Result<PinnedEvidenceReceipt, PinnedSessionError>;
}

#[cfg(any(target_os = "macos", test))]
fn run_closed_pinned_session<S: ClosedPinnedSession>(
    session: &mut S,
) -> Result<PinnedSessionTranscript, PinnedSessionError> {
    run_closed_pinned_session_inner(session, |_| {})
}

#[cfg(any(target_os = "macos", test))]
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
        self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;
        let handle = ProcessSupervisor::start_pinned_bottle(self.prepared()?.plan(), self.pinned()?)
            .map_err(|_| PinnedSessionError)?;
        Ok(TimedPinnedHandle {
            handle,
            started: Instant::now(),
        })
    }

    fn post_spawn_revalidate(&mut self) -> Result<(), PinnedSessionError> {
        self.pinned()?.revalidate().map_err(|_| PinnedSessionError)
    }

    fn shutdown_integrity_failure(&mut self, timed: Self::Handle) -> Result<(), PinnedSessionError> {
        timed.handle.terminate().map_err(|_| PinnedSessionError)?;
        drain_pinned_integrity_shutdown(&timed.handle)
    }

    fn supervise_pinned(&mut self, timed: Self::Handle) -> Result<Vec<Vec<u8>>, PinnedSessionError> {
        collect_pinned_runtime_events(&timed.handle, timed.started, self.terminate_after)
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

#[cfg(target_os = "macos")]
fn event_json_line(event: &compatforge_domain::RuntimeEvent) -> Result<Vec<u8>, PinnedSessionError> {
    let mut line = serde_json::to_vec(event).map_err(|_| PinnedSessionError)?;
    line.push(b'\n');
    Ok(line)
}

#[cfg(target_os = "macos")]
fn collect_pinned_runtime_events(
    handle: &LaunchHandle,
    started: Instant,
    terminate_after: Duration,
) -> Result<Vec<Vec<u8>>, PinnedSessionError> {
    let mut events = Vec::new();
    let mut termination_requested = false;
    loop {
        if !termination_requested && started.elapsed() >= terminate_after {
            handle.terminate().map_err(|_| PinnedSessionError)?;
            termination_requested = true;
        }
        match handle.next_event(Duration::from_millis(250)) {
            EventPoll::Event(event) => {
                let terminal = event.kind == RuntimeEventKind::Exited;
                let failed = event.kind == RuntimeEventKind::Failed;
                let success = event.exit.as_ref().is_some_and(|exit| exit.success);
                events.push(event_json_line(&event)?);
                if terminal {
                    return if success || termination_requested {
                        Ok(events)
                    } else {
                        Err(PinnedSessionError)
                    };
                }
                if failed {
                    return Err(PinnedSessionError);
                }
            }
            EventPoll::Timeout => {}
            EventPoll::Closed => return Err(PinnedSessionError),
        }
    }
}

#[cfg(target_os = "macos")]
fn drain_pinned_integrity_shutdown(handle: &LaunchHandle) -> Result<(), PinnedSessionError> {
    let mut cleanup_failed = false;
    loop {
        match handle.next_event(Duration::from_millis(250)) {
            EventPoll::Event(event) if event.kind == RuntimeEventKind::Exited => {
                return if cleanup_failed {
                    Err(PinnedSessionError)
                } else {
                    Ok(())
                };
            }
            EventPoll::Event(event) if event.kind == RuntimeEventKind::Failed => cleanup_failed = true,
            EventPoll::Event(_) | EventPoll::Timeout => {}
            EventPoll::Closed => return Err(PinnedSessionError),
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn pinned_transcript_bytes(transcript: &PinnedSessionTranscript) -> Result<Vec<u8>, PinnedSessionError> {
    let receipt = pinned_receipt_line(&transcript.receipt)?;
    let total_length = transcript
        .events
        .iter()
        .try_fold(receipt.len(), |total, event| total.checked_add(event.len()))
        .ok_or(PinnedSessionError)?;
    let mut output = Vec::with_capacity(total_length);
    for event in &transcript.events {
        output.extend_from_slice(event);
    }
    output.extend_from_slice(&receipt);
    Ok(output)
}

#[cfg(target_os = "macos")]
fn write_pinned_transcript(transcript: &PinnedSessionTranscript) -> Result<(), PinnedSessionError> {
    let output = pinned_transcript_bytes(transcript)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output).map_err(|_| PinnedSessionError)?;
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
        let transcript = run_closed_pinned_session(&mut session)?;
        write_pinned_transcript(&transcript)
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
    let started = Instant::now();
    let mut termination_requested = false;

    loop {
        if !termination_requested && terminate_after.is_some_and(|delay| started.elapsed() >= delay) {
            handle.terminate()?;
            termination_requested = true;
        }
        match handle.next_event(Duration::from_millis(250)) {
            EventPoll::Event(event) => {
                println!("{}", serde_json::to_string(&event)?);
                if event.kind == RuntimeEventKind::Exited {
                    let success = event.exit.as_ref().is_some_and(|exit| exit.success);
                    if success || termination_requested {
                        return Ok(());
                    }
                    return Err(io::Error::other("supervised process exited unsuccessfully").into());
                }
                if event.kind == RuntimeEventKind::Failed {
                    return Err(io::Error::other("process supervision failed").into());
                }
            }
            EventPoll::Timeout => {}
            EventPoll::Closed => return Err(io::Error::other("runtime event stream closed").into()),
        }
    }
}

fn print_help() {
    println!("CompatForge Core CLI");
    println!("usage:");
    println!("  compatforge-cli version");
    println!("  compatforge-cli probe");
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
        source: Vec<u8>,
        captured: Vec<u8>,
        child_bytes: Vec<u8>,
        children_created: usize,
        shutdown: bool,
        pre_spawn_mutation: Option<PreSpawnMutation>,
        source_identity: u64,
        captured_source_identity: u64,
    }

    #[derive(Clone, Copy)]
    enum PreSpawnMutation {
        Overwrite,
        Replacement,
    }

    impl FakeClosedPinnedSession {
        fn stable() -> Self {
            Self {
                source: b"captured SumatraPDF bytes".to_vec(),
                source_identity: 17,
                ..Self::default()
            }
        }
    }

    impl ClosedPinnedSession for FakeClosedPinnedSession {
        type Handle = ();

        fn validate_closed_inputs(&mut self) -> Result<(), PinnedSessionError> {
            self.order.push("validate");
            Ok(())
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
            Ok(())
        }

        fn start_pinned(&mut self) -> Result<Self::Handle, PinnedSessionError> {
            self.order.push("start");
            if self.source != self.captured || self.source_identity != self.captured_source_identity {
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
            Ok(vec![b"{\"kind\":\"exited\"}\n".to_vec()])
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
        assert_eq!(transcript.events, [b"{\"kind\":\"exited\"}\n".to_vec()]);
        assert_eq!(session.children_created, 1);
    }

    #[test]
    fn pinned_success_transcript_has_events_then_exactly_one_final_receipt() {
        let mut session = FakeClosedPinnedSession::stable();
        let transcript = run_closed_pinned_session(&mut session).unwrap();
        let output = String::from_utf8(pinned_transcript_bytes(&transcript).unwrap()).unwrap();
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "{\"kind\":\"exited\"}");
        assert_eq!(lines[1].matches("pinned-evidence-receipt").count(), 1);
        assert!(lines[1].starts_with("{\"outputs\":[{\"byteLength\":123,\"kind\":\"inspection\""));
        assert!(lines[1].ends_with("\"recordType\":\"pinned-evidence-receipt\",\"schemaVersion\":1}"));
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
