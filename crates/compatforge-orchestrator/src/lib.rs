//! Deterministic, side-effect-free compilation of launch requests.

#![forbid(unsafe_code)]

use compatforge_domain::{
    BottleExecutableBinding, CapabilityReport, ContractError, CoreConfig, CpuArchitecture, ExecutableMode,
    GraphicsBackendKind, GraphicsSelection, GuestArtifactBinding, HostOs, LaunchPlan, LaunchRequest, NativeCommand,
    ProcessLifecycle, ProviderDescriptor, RuntimeKind, RuntimeSelection, SandboxPolicy, TranslatorKind,
    TranslatorSelection, WineServerLifecycle, SCHEMA_VERSION_V1,
};
use compatforge_guest_artifact::{
    GuestArtifactError, GuestArtifactStore, PinnedBottleExecutable, PreparedBottleExecutable,
};
use compatforge_inspect::{PeArchitecture, PeImageKind, PeInspectionReport, PeSubsystem};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    InvalidConfig(ContractError),
    InvalidRequest(ContractError),
    InvalidPlan(ContractError),
    MissingRequiredCapability(String),
    NoCompatibleRuntime,
    MissingRuntimeBinding(String),
    InvalidHostPath(&'static str),
    PlanMismatch(&'static str),
    NoCompatibleTranslator,
    NoCompatibleGraphicsBackend,
}

#[derive(Debug)]
pub enum PreparationError {
    InvalidRequest(ContractError),
    SourcePathMismatch,
    ArchitectureMismatch {
        requested: CpuArchitecture,
        inspected: CpuArchitecture,
    },
    DigestMismatch,
    GuestArtifact(GuestArtifactError),
    Planning(PlanError),
    ContextSerialization(serde_json::Error),
    ContextMismatch,
    PreparedPlanMismatch,
    PinnedLeaseMismatch,
    PinnedAuthorizationRequired,
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(error) => write!(formatter, "invalid launch request: {error}"),
            Self::SourcePathMismatch => {
                formatter.write_str("launch request executable path does not match the selected source")
            }
            Self::ArchitectureMismatch { requested, inspected } => write!(
                formatter,
                "requested architecture {requested:?} does not match inspected architecture {inspected:?}"
            ),
            Self::DigestMismatch => formatter.write_str("requested executable digest does not match inspected content"),
            Self::GuestArtifact(error) => write!(formatter, "guest artifact preparation failed: {error}"),
            Self::Planning(error) => write!(formatter, "prepared launch planning failed: {error}"),
            Self::ContextSerialization(error) => write!(formatter, "trusted context serialization failed: {error}"),
            Self::ContextMismatch => formatter.write_str("prepared launch context fingerprint mismatch"),
            Self::PreparedPlanMismatch => {
                formatter.write_str("prepared launch no longer recompiles to the pinned plan")
            }
            Self::PinnedLeaseMismatch => formatter.write_str("pinned Bottle lease does not match prepared state"),
            Self::PinnedAuthorizationRequired => {
                formatter.write_str("pinned Bottle state requires pinned authorization")
            }
        }
    }
}

impl std::error::Error for PreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::GuestArtifact(error) => Some(error),
            Self::Planning(error) => Some(error),
            Self::ContextSerialization(error) => Some(error),
            _ => None,
        }
    }
}

/// An opaque, inspection-bound launch decision. The original request is kept
/// privately so authorization can deterministically recompile the complete
/// plan against the caller's current trusted context.
#[derive(Debug, Clone)]
pub struct PreparedLaunch {
    request: LaunchRequest,
    inspection: PeInspectionReport,
    executable: PreparedExecutable,
    plan: LaunchPlan,
    context_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreparedExecutable {
    Immutable(GuestArtifactBinding),
    Bottle(BottleExecutableBinding),
    PinnedBottle(PinnedBottleSnapshot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PinnedExecutionIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone)]
struct PinnedBottleSnapshot {
    binding: BottleExecutableBinding,
    inspection: PeInspectionReport,
    execution_identity: PinnedExecutionIdentity,
    _execution_guard: Arc<File>,
}

impl fmt::Debug for PinnedBottleSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedBottleSnapshot")
            .field("binding", &self.binding)
            .field("inspection", &self.inspection)
            .field("execution_identity", &self.execution_identity)
            .field("execution_guard", &"held")
            .finish()
    }
}

impl PartialEq for PinnedBottleSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding
            && self.inspection == other.inspection
            && self.execution_identity == other.execution_identity
    }
}

impl Eq for PinnedBottleSnapshot {}

impl PreparedLaunch {
    pub fn prepare(config: &CoreConfig, source: &Path, request: &LaunchRequest) -> Result<Self, PreparationError> {
        config
            .validate()
            .map_err(PlanError::InvalidConfig)
            .map_err(PreparationError::Planning)?;
        request.validate().map_err(PreparationError::InvalidRequest)?;
        if Path::new(&request.executable.path) != source {
            return Err(PreparationError::SourcePathMismatch);
        }
        let store = GuestArtifactStore::new(&config.storage_root);
        let (inspection, executable, trusted_request) = match request.executable.mode {
            ExecutableMode::ImmutableArtifact => {
                let prepared = store.prepare(source).map_err(PreparationError::GuestArtifact)?;
                validate_requested_binding(request, prepared.binding.architecture, &prepared.binding.digest)?;
                let mut trusted_request = request.clone();
                trusted_request
                    .executable
                    .path
                    .clone_from(&prepared.binding.stored_path);
                trusted_request.executable.architecture = prepared.binding.architecture;
                trusted_request.executable.sha256 = prepared.binding.digest.strip_prefix("sha256:").map(str::to_owned);
                (
                    prepared.inspection,
                    PreparedExecutable::Immutable(prepared.binding),
                    trusted_request,
                )
            }
            ExecutableMode::BottleInPlace => {
                let prepared: PreparedBottleExecutable = store
                    .prepare_bottle_in_place(&request.bottle_id, source)
                    .map_err(PreparationError::GuestArtifact)?;
                validate_requested_binding(request, prepared.binding.architecture, &prepared.binding.digest)?;
                (
                    prepared.inspection,
                    PreparedExecutable::Bottle(prepared.binding),
                    request.clone(),
                )
            }
        };
        let plan = compile_prepared_plan(config, &trusted_request, &executable)?;
        let context_fingerprint = fingerprint_context(config)?;
        Ok(Self {
            request: trusted_request,
            inspection,
            executable,
            plan,
            context_fingerprint,
        })
    }

    pub fn prepare_pinned_bottle(
        config: &CoreConfig,
        request: &LaunchRequest,
        pinned: &PinnedBottleExecutable,
    ) -> Result<Self, PreparationError> {
        pinned.revalidate().map_err(PreparationError::GuestArtifact)?;
        let snapshot = capture_pinned_snapshot(pinned)?;
        Self::prepare_pinned_snapshot(config, request, snapshot)
    }

    fn prepare_pinned_snapshot(
        config: &CoreConfig,
        request: &LaunchRequest,
        snapshot: PinnedBottleSnapshot,
    ) -> Result<Self, PreparationError> {
        config
            .validate()
            .map_err(PlanError::InvalidConfig)
            .map_err(PreparationError::Planning)?;
        validate_pinned_request(config, request, &snapshot)?;
        let executable = PreparedExecutable::PinnedBottle(snapshot.clone());
        let plan = compile_prepared_plan(config, request, &executable)?;
        let context_fingerprint = fingerprint_context(config)?;
        Ok(Self {
            request: request.clone(),
            inspection: snapshot.inspection,
            executable,
            plan,
            context_fingerprint,
        })
    }

    #[must_use]
    pub const fn inspection(&self) -> &PeInspectionReport {
        &self.inspection
    }

    #[must_use]
    pub const fn plan(&self) -> &LaunchPlan {
        &self.plan
    }

    pub fn authorize<'a>(&'a self, config: &CoreConfig) -> Result<&'a LaunchPlan, PreparationError> {
        if matches!(&self.executable, PreparedExecutable::PinnedBottle(_)) {
            return Err(PreparationError::PinnedAuthorizationRequired);
        }
        if fingerprint_context(config)? != self.context_fingerprint {
            return Err(PreparationError::ContextMismatch);
        }
        let store = GuestArtifactStore::new(&config.storage_root);
        match &self.executable {
            PreparedExecutable::Immutable(binding) => store.verify(binding).map_err(PreparationError::GuestArtifact)?,
            PreparedExecutable::Bottle(binding) => {
                store.verify_bottle(binding).map_err(PreparationError::GuestArtifact)?
            }
            PreparedExecutable::PinnedBottle(_) => return Err(PreparationError::PinnedAuthorizationRequired),
        }
        let recompiled = compile_prepared_plan(config, &self.request, &self.executable)?;
        if recompiled != self.plan {
            return Err(PreparationError::PreparedPlanMismatch);
        }
        PolicyEngine::authorize(config, &self.plan).map_err(PreparationError::Planning)?;
        Ok(&self.plan)
    }

    pub fn authorize_pinned<'a>(
        &'a self,
        config: &CoreConfig,
        pinned: &PinnedBottleExecutable,
    ) -> Result<&'a LaunchPlan, PreparationError> {
        pinned.revalidate().map_err(PreparationError::GuestArtifact)?;
        let snapshot = capture_pinned_snapshot(pinned)?;
        self.authorize_pinned_snapshot(config, &snapshot)
    }

    fn authorize_pinned_snapshot<'a>(
        &'a self,
        config: &CoreConfig,
        candidate: &PinnedBottleSnapshot,
    ) -> Result<&'a LaunchPlan, PreparationError> {
        let PreparedExecutable::PinnedBottle(prepared) = &self.executable else {
            return Err(PreparationError::PinnedLeaseMismatch);
        };
        if prepared != candidate {
            return Err(PreparationError::PinnedLeaseMismatch);
        }
        validate_pinned_request(config, &self.request, candidate)?;
        if fingerprint_context(config)? != self.context_fingerprint {
            return Err(PreparationError::ContextMismatch);
        }
        let recompiled = compile_prepared_plan(config, &self.request, &self.executable)?;
        if recompiled != self.plan {
            return Err(PreparationError::PreparedPlanMismatch);
        }
        PolicyEngine::authorize(config, &self.plan).map_err(PreparationError::Planning)?;
        Ok(&self.plan)
    }
}

#[cfg(target_os = "macos")]
fn capture_pinned_snapshot(pinned: &PinnedBottleExecutable) -> Result<PinnedBottleSnapshot, PreparationError> {
    use std::os::unix::fs::MetadataExt;

    let execution = pinned
        .duplicate_execution_file()
        .map_err(PreparationError::GuestArtifact)?;
    let metadata = execution
        .metadata()
        .map_err(|_| PreparationError::GuestArtifact(GuestArtifactError::PinnedIntegrityFailure))?;
    if !metadata.is_file() {
        return Err(PreparationError::GuestArtifact(
            GuestArtifactError::PinnedIntegrityFailure,
        ));
    }
    Ok(PinnedBottleSnapshot {
        binding: pinned.binding().clone(),
        inspection: pinned.inspection().clone(),
        execution_identity: PinnedExecutionIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        _execution_guard: Arc::new(execution),
    })
}

#[cfg(not(target_os = "macos"))]
fn capture_pinned_snapshot(_pinned: &PinnedBottleExecutable) -> Result<PinnedBottleSnapshot, PreparationError> {
    Err(PreparationError::GuestArtifact(
        GuestArtifactError::PinnedUnsupportedPlatform,
    ))
}

fn validate_pinned_request(
    config: &CoreConfig,
    request: &LaunchRequest,
    snapshot: &PinnedBottleSnapshot,
) -> Result<(), PreparationError> {
    request.validate().map_err(PreparationError::InvalidRequest)?;
    snapshot
        .binding
        .validate()
        .map_err(GuestArtifactError::InvalidBottleBinding)
        .map_err(PreparationError::GuestArtifact)?;
    if request.executable.mode != ExecutableMode::BottleInPlace
        || request.bottle_id != "gui-sumatrapdf"
        || snapshot.binding.bottle_id != "gui-sumatrapdf"
    {
        return Err(PreparationError::PinnedLeaseMismatch);
    }
    let expected_path = Path::new(&config.storage_root)
        .join("bottles")
        .join("gui-sumatrapdf")
        .join("prefix")
        .join("drive_c")
        .join("CompatForge")
        .join("SumatraPDF")
        .join("SumatraPDF.exe");
    if Path::new(&snapshot.binding.path) != expected_path || request.executable.path != snapshot.binding.path {
        return Err(PreparationError::SourcePathMismatch);
    }
    validate_requested_binding(request, snapshot.binding.architecture, &snapshot.binding.digest)?;

    let inspected_architecture = match snapshot.inspection.architecture {
        PeArchitecture::X86 => CpuArchitecture::I386,
        PeArchitecture::X86_64 => CpuArchitecture::X86_64,
        PeArchitecture::Arm | PeArchitecture::Arm64 => return Err(PreparationError::PinnedLeaseMismatch),
    };
    let inspected_subsystem = match snapshot.inspection.subsystem {
        PeSubsystem::WindowsConsole => "windowsConsole",
        PeSubsystem::WindowsGui => "windowsGui",
        _ => return Err(PreparationError::PinnedLeaseMismatch),
    };
    if snapshot.inspection.image_kind != PeImageKind::Executable
        || snapshot.binding.digest != snapshot.inspection.file_digest
        || snapshot.binding.size_bytes != snapshot.inspection.file_size_bytes
        || snapshot.binding.architecture != inspected_architecture
        || snapshot.binding.image_kind != "executable"
        || snapshot.binding.subsystem != inspected_subsystem
        || snapshot.binding.inspection_schema_version != snapshot.inspection.schema_version
    {
        return Err(PreparationError::PinnedLeaseMismatch);
    }
    Ok(())
}

fn compile_prepared_plan(
    config: &CoreConfig,
    request: &LaunchRequest,
    executable: &PreparedExecutable,
) -> Result<LaunchPlan, PreparationError> {
    let mut plan = PolicyEngine::compile(config, request).map_err(PreparationError::Planning)?;
    match executable {
        PreparedExecutable::Immutable(binding) => {
            plan.guest_artifact = Some(binding.clone());
            plan.decision_trace
                .push(format!("guest-artifact {} pinned", binding.digest));
            plan.decision_trace.push(format!(
                "inspection {} {} accepted",
                binding.architecture.as_str(),
                binding.subsystem
            ));
        }
        PreparedExecutable::Bottle(binding) => {
            plan.bottle_executable = Some(binding.clone());
            plan.decision_trace
                .push(format!("bottle-executable {} pinned in place", binding.digest));
            plan.decision_trace.push(format!(
                "inspection {} {} accepted",
                binding.architecture.as_str(),
                binding.subsystem
            ));
        }
        PreparedExecutable::PinnedBottle(snapshot) => {
            let binding = &snapshot.binding;
            plan.bottle_executable = Some(binding.clone());
            plan.decision_trace
                .push(format!("bottle-executable {} pinned in place", binding.digest));
            plan.decision_trace.push(format!(
                "inspection {} {} accepted",
                binding.architecture.as_str(),
                binding.subsystem
            ));
        }
    }
    plan.validate()
        .map_err(PlanError::InvalidPlan)
        .map_err(PreparationError::Planning)?;
    Ok(plan)
}

fn validate_requested_binding(
    request: &LaunchRequest,
    inspected_architecture: CpuArchitecture,
    inspected_digest: &str,
) -> Result<(), PreparationError> {
    if request.executable.architecture != inspected_architecture {
        return Err(PreparationError::ArchitectureMismatch {
            requested: request.executable.architecture,
            inspected: inspected_architecture,
        });
    }
    if request.executable.sha256.as_deref().is_some_and(|digest| {
        !inspected_digest
            .strip_prefix("sha256:")
            .is_some_and(|actual| actual.eq_ignore_ascii_case(digest))
    }) {
        return Err(PreparationError::DigestMismatch);
    }
    Ok(())
}

fn fingerprint_context(config: &CoreConfig) -> Result<String, PreparationError> {
    let bytes = serde_json::to_vec(config).map_err(PreparationError::ContextSerialization)?;
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(value)
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "invalid core config: {error}"),
            Self::InvalidRequest(error) => write!(formatter, "invalid launch request: {error}"),
            Self::InvalidPlan(error) => write!(formatter, "invalid launch plan: {error}"),
            Self::MissingRequiredCapability(capability) => {
                write!(formatter, "required capability is unavailable: {capability}")
            }
            Self::NoCompatibleRuntime => formatter.write_str("no compatible runtime provider"),
            Self::MissingRuntimeBinding(provider) => {
                write!(formatter, "runtime provider {provider} has no pinned binding")
            }
            Self::InvalidHostPath(field) => write!(formatter, "{field} must be an absolute host path"),
            Self::PlanMismatch(field) => write!(formatter, "launch plan does not match trusted context: {field}"),
            Self::NoCompatibleTranslator => formatter.write_str("no compatible architecture translator"),
            Self::NoCompatibleGraphicsBackend => formatter.write_str("no compatible graphics backend"),
        }
    }
}

impl std::error::Error for PlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) | Self::InvalidRequest(error) | Self::InvalidPlan(error) => Some(error),
            _ => None,
        }
    }
}

pub struct PolicyEngine;

impl PolicyEngine {
    /// Compile a request to a fully serializable plan without launching a process.
    pub fn compile(config: &CoreConfig, request: &LaunchRequest) -> Result<LaunchPlan, PlanError> {
        config.validate().map_err(PlanError::InvalidConfig)?;
        request.validate().map_err(PlanError::InvalidRequest)?;
        Self::check_required_capabilities(&config.capabilities, request)?;

        if !is_absolute_host_path(&config.storage_root) {
            return Err(PlanError::InvalidHostPath("storageRoot"));
        }

        let (runtime_provider, runtime_kind) = Self::select_runtime(&config.capabilities, request)?;
        let binding = config
            .runtime_bindings
            .iter()
            .find(|candidate| candidate.provider_id == runtime_provider.id)
            .ok_or_else(|| PlanError::MissingRuntimeBinding(runtime_provider.id.clone()))?;
        if !is_absolute_host_path(&binding.executable) {
            return Err(PlanError::InvalidHostPath("runtimeBindings.executable"));
        }
        if binding
            .wineserver_executable
            .as_deref()
            .is_some_and(|path| !is_absolute_host_path(path))
        {
            return Err(PlanError::InvalidHostPath("runtimeBindings.wineserverExecutable"));
        }

        let translator = Self::select_translator(&config.capabilities, request, runtime_kind)?;
        let graphics = Self::select_graphics(&config.capabilities, request, runtime_kind)?;
        let bottle_directory = join_host_path(&config.storage_root, &["bottles", &request.bottle_id]);

        let mut environment = request.environment.clone();
        environment.extend(binding.environment.clone());
        let wine_prefix = (runtime_kind == RuntimeKind::Wine).then(|| join_host_path(&bottle_directory, &["prefix"]));
        if let Some(prefix) = &wine_prefix {
            environment.insert("WINEPREFIX".into(), prefix.clone());
        }

        let mut arguments = Vec::with_capacity(request.arguments.len() + 1);
        arguments.push(request.executable.path.clone());
        arguments.extend(request.arguments.clone());

        let working_directory = binding
            .working_directory
            .clone()
            .unwrap_or_else(|| bottle_directory.clone());
        if !is_absolute_host_path(&working_directory) {
            return Err(PlanError::InvalidHostPath("runtimeBindings.workingDirectory"));
        }

        let decision_trace = vec![
            format!(
                "runtime provider {} selected as {}",
                runtime_provider.id,
                runtime_kind.as_str()
            ),
            format!("translator {} selected", translator.provider.as_str()),
            format!("graphics backend {} selected", graphics.backend.as_str()),
            format!("runtime pack {} pinned by digest", binding.pack_id),
        ];

        Ok(LaunchPlan {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: request.request_id.clone(),
            runtime: RuntimeSelection {
                provider: runtime_kind,
                pack_id: binding.pack_id.clone(),
                pack_digest: binding.pack_digest.clone(),
            },
            translator,
            graphics,
            process: NativeCommand {
                executable: binding.executable.clone(),
                arguments,
                environment,
                working_directory,
            },
            guest_artifact: None,
            bottle_executable: None,
            mounts: Vec::new(),
            sandbox: SandboxPolicy {
                profile: config.sandbox_profile,
                network: request.constraints.network_policy,
                allow_devices: Vec::new(),
            },
            lifecycle: ProcessLifecycle {
                termination_grace_milliseconds: config.supervisor.termination_grace_milliseconds,
                maximum_runtime_milliseconds: config.supervisor.maximum_runtime_milliseconds,
                wineserver: binding
                    .wineserver_executable
                    .as_ref()
                    .zip(wine_prefix)
                    .map(|(executable, prefix)| WineServerLifecycle {
                        executable: executable.clone(),
                        prefix,
                    }),
            },
            decision_trace,
        })
    }

    /// Re-authorize a serialized plan before it crosses the process boundary.
    ///
    /// A frontend may cache or transport a plan, but it cannot replace the
    /// pinned runtime executable, digest, protected environment, sandbox, or
    /// storage location selected by the trusted context.
    pub fn authorize(config: &CoreConfig, plan: &LaunchPlan) -> Result<(), PlanError> {
        config.validate().map_err(PlanError::InvalidConfig)?;
        plan.validate().map_err(PlanError::InvalidPlan)?;

        if !is_absolute_host_path(&config.storage_root) {
            return Err(PlanError::InvalidHostPath("storageRoot"));
        }
        if !is_absolute_host_path(&plan.process.executable) {
            return Err(PlanError::InvalidHostPath("process.executable"));
        }
        if !is_absolute_host_path(&plan.process.working_directory) {
            return Err(PlanError::InvalidHostPath("process.workingDirectory"));
        }

        if let Some(guest) = &plan.guest_artifact {
            let digest = guest
                .digest
                .strip_prefix("sha256:")
                .ok_or(PlanError::PlanMismatch("guest artifact digest"))?;
            let expected = join_host_path(
                &config.storage_root,
                &["guest-artifacts", "objects", "sha256", &digest.to_ascii_lowercase()],
            );
            if guest.stored_path != expected || !host_path_is_within(&config.storage_root, &guest.stored_path) {
                return Err(PlanError::PlanMismatch("guest artifact path"));
            }
            if plan.process.arguments.first() != Some(&guest.stored_path) {
                return Err(PlanError::PlanMismatch("guest executable argument"));
            }
        }
        if let Some(bottle) = &plan.bottle_executable {
            if plan.guest_artifact.is_some() {
                return Err(PlanError::PlanMismatch(
                    "guest artifact and Bottle executable are mutually exclusive",
                ));
            }
            let expected_root = join_host_path(
                &config.storage_root,
                &["bottles", &bottle.bottle_id, "prefix", "drive_c"],
            );
            if !host_path_is_within(&expected_root, &bottle.path)
                || plan.process.arguments.first() != Some(&bottle.path)
            {
                return Err(PlanError::PlanMismatch("Bottle executable path"));
            }
            if !host_path_is_within(&config.storage_root, &plan.process.working_directory) {
                return Err(PlanError::PlanMismatch("working directory"));
            }
        }

        let binding = config
            .runtime_bindings
            .iter()
            .find(|candidate| {
                candidate.pack_id == plan.runtime.pack_id && candidate.pack_digest == plan.runtime.pack_digest
            })
            .ok_or(PlanError::PlanMismatch("runtime pack or digest"))?;
        if binding.executable != plan.process.executable {
            return Err(PlanError::PlanMismatch("runtime executable"));
        }
        let provider_matches = config.capabilities.runtime_providers.iter().any(|provider| {
            provider.available && provider.id == binding.provider_id && provider.kind == plan.runtime.provider.as_str()
        });
        if !provider_matches {
            return Err(PlanError::PlanMismatch("runtime provider"));
        }
        if plan.sandbox.profile != config.sandbox_profile {
            return Err(PlanError::PlanMismatch("sandbox profile"));
        }
        if plan.lifecycle.termination_grace_milliseconds != config.supervisor.termination_grace_milliseconds
            || plan.lifecycle.maximum_runtime_milliseconds != config.supervisor.maximum_runtime_milliseconds
        {
            return Err(PlanError::PlanMismatch("supervisor policy"));
        }
        if !host_path_is_within(&config.storage_root, &plan.process.working_directory) {
            return Err(PlanError::PlanMismatch("working directory"));
        }
        for (key, value) in &binding.environment {
            if plan.process.environment.get(key) != Some(value) {
                return Err(PlanError::PlanMismatch("protected runtime environment"));
            }
        }
        if plan.runtime.provider == RuntimeKind::Wine {
            let wine_prefix = plan
                .process
                .environment
                .get("WINEPREFIX")
                .ok_or(PlanError::PlanMismatch("WINEPREFIX"))?;
            if !host_path_is_within(&config.storage_root, wine_prefix) {
                return Err(PlanError::PlanMismatch("WINEPREFIX"));
            }
            let expected_wineserver = binding
                .wineserver_executable
                .as_ref()
                .map(|executable| WineServerLifecycle {
                    executable: executable.clone(),
                    prefix: wine_prefix.clone(),
                });
            if plan.lifecycle.wineserver != expected_wineserver {
                return Err(PlanError::PlanMismatch("wineserver lifecycle"));
            }
        } else if plan.lifecycle.wineserver.is_some() {
            return Err(PlanError::PlanMismatch("wineserver lifecycle"));
        }
        Ok(())
    }

    fn check_required_capabilities(capabilities: &CapabilityReport, request: &LaunchRequest) -> Result<(), PlanError> {
        for required in &request.constraints.required_capabilities {
            let feature_available = capabilities
                .features
                .get(required)
                .and_then(compatforge_domain::CapabilityValue::as_bool)
                .unwrap_or(false);
            let provider_available = capabilities
                .runtime_providers
                .iter()
                .chain(capabilities.translators.iter())
                .chain(capabilities.graphics_backends.iter())
                .filter(|provider| provider.available)
                .any(|provider| provider.capabilities.contains(required));
            if !feature_available && !provider_available {
                return Err(PlanError::MissingRequiredCapability(required.clone()));
            }
        }
        Ok(())
    }

    fn select_runtime<'a>(
        capabilities: &'a CapabilityReport,
        request: &LaunchRequest,
    ) -> Result<(&'a ProviderDescriptor, RuntimeKind), PlanError> {
        let candidates: &[RuntimeKind] = if request.constraints.requires_kernel_driver {
            if request.constraints.allow_virtual_machine {
                &[RuntimeKind::VirtualMachine, RuntimeKind::Remote]
            } else {
                &[RuntimeKind::Remote]
            }
        } else {
            &[RuntimeKind::Wine, RuntimeKind::VirtualMachine, RuntimeKind::Remote]
        };

        for kind in candidates {
            if *kind == RuntimeKind::VirtualMachine && !request.constraints.allow_virtual_machine {
                continue;
            }
            if *kind == RuntimeKind::Remote && !request.constraints.allow_remote {
                continue;
            }
            if let Some(provider) = available_provider(&capabilities.runtime_providers, kind.as_str()) {
                return Ok((provider, *kind));
            }
        }
        Err(PlanError::NoCompatibleRuntime)
    }

    fn select_translator(
        capabilities: &CapabilityReport,
        request: &LaunchRequest,
        runtime: RuntimeKind,
    ) -> Result<TranslatorSelection, PlanError> {
        if runtime == RuntimeKind::Remote {
            return Ok(TranslatorSelection {
                provider: TranslatorKind::Remote,
                version: None,
            });
        }
        if runtime == RuntimeKind::VirtualMachine {
            return Ok(TranslatorSelection {
                provider: TranslatorKind::Native,
                version: None,
            });
        }

        let host_architecture = capabilities.host.architecture;
        let guest_architecture = request.executable.architecture;
        let same_family = host_architecture == guest_architecture
            || (host_architecture == CpuArchitecture::X86_64 && guest_architecture == CpuArchitecture::I386);
        if same_family {
            return Ok(TranslatorSelection {
                provider: TranslatorKind::Native,
                version: None,
            });
        }

        let preference: &[TranslatorKind] = match capabilities.host.os {
            HostOs::MacOs => &[TranslatorKind::Rosetta, TranslatorKind::Qemu],
            HostOs::Linux => &[TranslatorKind::Fex, TranslatorKind::Box64, TranslatorKind::Qemu],
            HostOs::Android => &[TranslatorKind::Box64, TranslatorKind::Fex, TranslatorKind::Qemu],
            HostOs::Windows => &[TranslatorKind::Native],
        };

        preference
            .iter()
            .find_map(|kind| {
                available_provider(&capabilities.translators, kind.as_str()).map(|provider| TranslatorSelection {
                    provider: *kind,
                    version: Some(provider.version.clone()),
                })
            })
            .ok_or(PlanError::NoCompatibleTranslator)
    }

    fn select_graphics(
        capabilities: &CapabilityReport,
        request: &LaunchRequest,
        runtime: RuntimeKind,
    ) -> Result<GraphicsSelection, PlanError> {
        if runtime == RuntimeKind::Remote {
            return Ok(GraphicsSelection {
                backend: GraphicsBackendKind::Remote,
                version: None,
                options: BTreeMap::new(),
            });
        }
        if runtime == RuntimeKind::VirtualMachine {
            return Ok(GraphicsSelection {
                backend: GraphicsBackendKind::Virtualized,
                version: None,
                options: BTreeMap::new(),
            });
        }

        let preference: &[GraphicsBackendKind] = match (capabilities.host.os, request.constraints.requires_direct_x12) {
            (HostOs::MacOs, true) => &[
                GraphicsBackendKind::D3dMetal,
                GraphicsBackendKind::Vkd3dProton,
                GraphicsBackendKind::WineD3d,
            ],
            (HostOs::MacOs, false) => &[
                GraphicsBackendKind::D3dMetal,
                GraphicsBackendKind::MoltenVk,
                GraphicsBackendKind::WineD3d,
            ],
            (_, true) => &[GraphicsBackendKind::Vkd3dProton, GraphicsBackendKind::WineD3d],
            (_, false) => &[GraphicsBackendKind::Dxvk, GraphicsBackendKind::WineD3d],
        };

        preference
            .iter()
            .find_map(|kind| {
                available_provider(&capabilities.graphics_backends, kind.as_str()).map(|provider| GraphicsSelection {
                    backend: *kind,
                    version: Some(provider.version.clone()),
                    options: BTreeMap::new(),
                })
            })
            .ok_or(PlanError::NoCompatibleGraphicsBackend)
    }
}

fn available_provider<'a>(providers: &'a [ProviderDescriptor], kind: &str) -> Option<&'a ProviderDescriptor> {
    providers
        .iter()
        .find(|provider| provider.available && provider.kind == kind)
}

fn join_host_path(root: &str, components: &[&str]) -> String {
    let separator = if root.contains('\\') { '\\' } else { '/' };
    let mut path = root.trim_end_matches(['/', '\\']).to_owned();
    for component in components {
        if !path.is_empty() {
            path.push(separator);
        } else if root.starts_with('/') {
            path.push('/');
        }
        path.push_str(component.trim_matches(['/', '\\']));
    }
    path
}

fn is_absolute_host_path(value: &str) -> bool {
    normalize_host_path(value).is_some()
}

fn host_path_is_within(root: &str, candidate: &str) -> bool {
    let Some((root_namespace, root_components)) = normalize_host_path(root) else {
        return false;
    };
    let Some((candidate_namespace, candidate_components)) = normalize_host_path(candidate) else {
        return false;
    };
    root_namespace == candidate_namespace && candidate_components.starts_with(&root_components)
}

/// Normalize a serialized host path without depending on the OS compiling the
/// planner. Windows namespaces are case-insensitive; POSIX components retain
/// case. Parent traversal is rejected instead of being lexically contained.
fn normalize_host_path(value: &str) -> Option<(String, Vec<String>)> {
    let path = value.replace('\\', "/");
    let (namespace, remainder, case_insensitive) = if let Some(unc) = path.strip_prefix("//") {
        let mut components = unc.split('/').filter(|component| !component.is_empty());
        let server = components.next()?;
        let share = components.next()?;
        let namespace = format!("unc:{server}/{share}").to_ascii_lowercase();
        let remainder = components.collect::<Vec<_>>().join("/");
        (namespace, remainder, true)
    } else if path
        .as_bytes()
        .first()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().get(2) == Some(&b'/')
    {
        let drive = path[..1].to_ascii_lowercase();
        (format!("drive:{drive}"), path[3..].to_owned(), true)
    } else {
        let remainder = path.strip_prefix('/')?;
        ("posix".to_owned(), remainder.to_owned(), false)
    };

    let mut normalized = Vec::new();
    for component in remainder.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            component => {
                normalized.push(if case_insensitive {
                    component.to_ascii_lowercase()
                } else {
                    component.to_owned()
                });
            }
        }
    }
    Some((namespace, normalized))
}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::{
        ExecutableRequest, HostDescriptor, LaunchConstraints, NetworkPolicy, RuntimeBinding, SandboxProfile,
        SupervisorPolicy,
    };

    fn provider(id: &str, kind: &str) -> ProviderDescriptor {
        ProviderDescriptor {
            id: id.into(),
            kind: kind.into(),
            version: "test".into(),
            available: true,
            reason: None,
            capabilities: Vec::new(),
        }
    }

    fn config(host_architecture: CpuArchitecture) -> CoreConfig {
        CoreConfig {
            schema_version: SCHEMA_VERSION_V1.into(),
            capabilities: CapabilityReport {
                schema_version: SCHEMA_VERSION_V1.into(),
                host: HostDescriptor {
                    os: HostOs::Linux,
                    os_version: "test".into(),
                    architecture: host_architecture,
                    kernel: None,
                    device_model: None,
                },
                runtime_providers: vec![provider("wine-local", "wine"), provider("vm-local", "virtual-machine")],
                translators: vec![provider("fex-local", "fex")],
                graphics_backends: vec![provider("dxvk-local", "dxvk")],
                observations: Vec::new(),
                features: BTreeMap::new(),
            },
            runtime_bindings: vec![
                RuntimeBinding {
                    provider_id: "wine-local".into(),
                    pack_id: "wine-test".into(),
                    pack_digest: format!("sha256:{}", "0".repeat(64)),
                    executable: "/opt/compatforge/wine/bin/wine".into(),
                    wineserver_executable: Some("/opt/compatforge/wine/bin/wineserver".into()),
                    environment: BTreeMap::new(),
                    working_directory: None,
                },
                RuntimeBinding {
                    provider_id: "vm-local".into(),
                    pack_id: "vm-test".into(),
                    pack_digest: format!("sha256:{}", "1".repeat(64)),
                    executable: "/opt/compatforge/vm/bin/launch".into(),
                    wineserver_executable: None,
                    environment: BTreeMap::new(),
                    working_directory: None,
                },
            ],
            storage_root: "/var/lib/compatforge".into(),
            sandbox_profile: SandboxProfile::Desktop,
            supervisor: SupervisorPolicy::default(),
        }
    }

    fn request() -> LaunchRequest {
        LaunchRequest {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: "018fe3cb-9d12-7b52-b334-1cce0e857fc9".into(),
            bottle_id: "example-bottle".into(),
            recipe_id: None,
            executable: ExecutableRequest {
                path: "C:\\Program Files\\Example\\example.exe".into(),
                architecture: CpuArchitecture::X86_64,
                mode: ExecutableMode::ImmutableArtifact,
                sha256: None,
            },
            arguments: vec!["--safe".into()],
            environment: BTreeMap::new(),
            constraints: LaunchConstraints {
                allow_virtual_machine: true,
                allow_remote: false,
                requires_kernel_driver: false,
                requires_direct_x12: false,
                network_policy: NetworkPolicy::Deny,
                required_capabilities: Vec::new(),
            },
        }
    }

    fn prepared_fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hello-x86_64.exe")
            .canonicalize()
            .unwrap()
    }

    fn prepared_config(label: &str) -> (CoreConfig, std::path::PathBuf) {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("compatforge-{label}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut config = config(CpuArchitecture::X86_64);
        config.storage_root = root.join("store").to_string_lossy().into_owned();
        (config, root)
    }

    fn prepared_request() -> LaunchRequest {
        let mut request = request();
        request.executable.path = prepared_fixture().to_string_lossy().into_owned();
        request
    }

    fn gui_fixture_bytes() -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/hello-x86_64.exe");
        let mut bytes = std::fs::read(path).unwrap();
        bytes[0xdc..0xde].copy_from_slice(&2_u16.to_le_bytes());
        bytes
    }

    fn pinned_oracle_input(
        label: &str,
    ) -> (
        CoreConfig,
        std::path::PathBuf,
        LaunchRequest,
        PreparedLaunch,
        PinnedBottleSnapshot,
    ) {
        let (config, root) = prepared_config(label);
        let source = Path::new(&config.storage_root)
            .join("bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, gui_fixture_bytes()).unwrap();
        let mut request = request();
        request.bottle_id = "gui-sumatrapdf".into();
        request.executable.path = source.to_string_lossy().into_owned();
        request.executable.mode = ExecutableMode::BottleInPlace;
        request.executable.architecture = CpuArchitecture::X86_64;
        request.executable.sha256 = None;
        let ordinary = PreparedLaunch::prepare(&config, &source, &request).unwrap();
        let binding = match &ordinary.executable {
            PreparedExecutable::Bottle(binding) => binding.clone(),
            PreparedExecutable::Immutable(_) | PreparedExecutable::PinnedBottle(_) => {
                panic!("Bottle fixture must prepare an in-place binding")
            }
        };
        let snapshot = PinnedBottleSnapshot {
            binding,
            inspection: ordinary.inspection.clone(),
            execution_identity: PinnedExecutionIdentity { device: 17, inode: 29 },
            _execution_guard: Arc::new(File::open(prepared_fixture()).unwrap()),
        };
        (config, root, request, ordinary, snapshot)
    }

    #[cfg(target_os = "macos")]
    fn real_pinned_fixture(
        label: &str,
    ) -> (
        CoreConfig,
        std::path::PathBuf,
        std::path::PathBuf,
        LaunchRequest,
        compatforge_guest_artifact::PinnedBottleExecutable,
        compatforge_guest_artifact::HeldExternalWorkRoot,
        std::fs::File,
    ) {
        use compatforge_guest_artifact::{GuestArtifactStore, HeldExternalWorkRoot};
        use std::os::fd::AsRawFd;

        let (config, root) = prepared_config(label);
        let source = root.join("store/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe");
        let work_root_path = root.join("external-work");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&work_root_path).unwrap();
        std::fs::write(&source, gui_fixture_bytes()).unwrap();
        let directory = std::fs::File::open(&work_root_path).unwrap();
        let held = HeldExternalWorkRoot::duplicate_inherited(
            directory.as_raw_fd(),
            &work_root_path,
            &[Path::new(&config.storage_root)],
        )
        .unwrap();
        let pinned = GuestArtifactStore::new(&config.storage_root)
            .pin_sumatra_bottle_executable("gui-sumatrapdf", &source, &held)
            .unwrap();
        let mut request = request();
        request.bottle_id = "gui-sumatrapdf".into();
        request.executable.path = source.to_string_lossy().into_owned();
        request.executable.mode = ExecutableMode::BottleInPlace;
        request.executable.architecture = CpuArchitecture::X86_64;
        request.executable.sha256 = None;
        (config, root, source, request, pinned, held, directory)
    }

    fn make_object_writable(prepared: &PreparedLaunch) {
        let path = match &prepared.executable {
            PreparedExecutable::Immutable(binding) => Path::new(&binding.stored_path),
            PreparedExecutable::Bottle(binding) => Path::new(&binding.path),
            PreparedExecutable::PinnedBottle(snapshot) => Path::new(&snapshot.binding.path),
        };
        #[cfg(unix)]
        if let Ok(mut permissions) = std::fs::metadata(path).map(|metadata| metadata.permissions()) {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o600);
            let _ = std::fs::set_permissions(path, permissions);
        }
        #[cfg(windows)]
        {
            let status = std::process::Command::new("attrib")
                .arg("-R")
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    #[test]
    fn prepares_an_inspection_bound_launch_plan() {
        let (config, root) = prepared_config("prepared-plan");
        let prepared = PreparedLaunch::prepare(&config, &prepared_fixture(), &prepared_request()).unwrap();
        let guest = prepared.plan().guest_artifact.as_ref().unwrap();
        assert_eq!(guest.digest, prepared.inspection().file_digest);
        assert_eq!(guest.architecture, CpuArchitecture::X86_64);
        assert_eq!(prepared.plan().translator.provider, TranslatorKind::Native);
        prepared.authorize(&config).unwrap();
        make_object_writable(&prepared);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_caller_architecture_and_digest_lies() {
        let (config, root) = prepared_config("prepared-lies");
        let mut request = prepared_request();
        request.executable.architecture = CpuArchitecture::I386;
        assert!(matches!(
            PreparedLaunch::prepare(&config, &prepared_fixture(), &request),
            Err(PreparationError::ArchitectureMismatch { .. })
        ));

        let mut request = prepared_request();
        request.executable.sha256 = Some("0".repeat(64));
        assert!(matches!(
            PreparedLaunch::prepare(&config, &prepared_fixture(), &request),
            Err(PreparationError::DigestMismatch)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_context_changes_after_preparation() {
        let (config, root) = prepared_config("prepared-context");
        let prepared = PreparedLaunch::prepare(&config, &prepared_fixture(), &prepared_request()).unwrap();
        let mut changed = config.clone();
        changed.sandbox_profile = SandboxProfile::Strict;
        assert!(matches!(
            prepared.authorize(&changed),
            Err(PreparationError::ContextMismatch)
        ));
        make_object_writable(&prepared);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_guest_object_tampering_before_start() {
        let (config, root) = prepared_config("prepared-tamper");
        let prepared = PreparedLaunch::prepare(&config, &prepared_fixture(), &prepared_request()).unwrap();
        make_object_writable(&prepared);
        let path = match &prepared.executable {
            PreparedExecutable::Immutable(binding) => &binding.stored_path,
            PreparedExecutable::Bottle(binding) => &binding.path,
            PreparedExecutable::PinnedBottle(snapshot) => &snapshot.binding.path,
        };
        std::fs::write(path, b"replaced object").unwrap();
        assert!(matches!(
            prepared.authorize(&config),
            Err(PreparationError::GuestArtifact(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepares_gui_bottle_executable_in_place_and_rechecks_before_authorize() {
        let (config, root) = prepared_config("prepared-bottle");
        let source = root.join("store/bottles/gui-test/prefix/drive_c/Program Files/Example/Example.exe");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, gui_fixture_bytes()).unwrap();
        let mut request = request();
        request.bottle_id = "gui-test".into();
        request.executable.path = source.to_string_lossy().into_owned();
        request.executable.mode = ExecutableMode::BottleInPlace;
        request.executable.architecture = CpuArchitecture::X86_64;
        request.executable.sha256 = None;
        let prepared = PreparedLaunch::prepare(&config, &source, &request).unwrap();
        let plan = prepared.plan();
        assert!(plan.guest_artifact.is_none());
        assert_eq!(plan.bottle_executable.as_ref().unwrap().subsystem, "windowsGui");
        PolicyEngine::authorize(&config, plan).unwrap();
        std::fs::write(&source, b"tampered").unwrap();
        assert!(matches!(
            prepared.authorize(&config),
            Err(PreparationError::GuestArtifact(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preparation_is_deterministic_for_the_same_context_and_input() {
        let (config, root) = prepared_config("prepared-deterministic");
        let first = PreparedLaunch::prepare(&config, &prepared_fixture(), &prepared_request()).unwrap();
        let second = PreparedLaunch::prepare(&config, &prepared_fixture(), &prepared_request()).unwrap();
        assert_eq!(first.inspection(), second.inspection());
        assert_eq!(first.plan(), second.plan());
        make_object_writable(&first);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_plan_json_is_identical_to_the_equivalent_stable_bottle_plan() {
        let (config, root, request, ordinary, snapshot) = pinned_oracle_input("pinned-plan-json");
        let pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot).unwrap();

        assert_eq!(
            serde_json::to_vec(pinned.plan()).unwrap(),
            serde_json::to_vec(ordinary.plan()).unwrap()
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_accepts_the_same_closed_snapshot() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-same-snapshot");
        let pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();

        pinned.authorize_pinned_snapshot(&config, &snapshot).unwrap();

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_compares_lease_fields_instead_of_guard_arc_identity() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-guard-equality");
        let pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();
        let mut candidate = snapshot;
        candidate._execution_guard = Arc::new(File::open(prepared_fixture()).unwrap());

        pinned.authorize_pinned_snapshot(&config, &candidate).unwrap();

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_prepared_state_keeps_the_execution_guard_alive_across_clones() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-guard-lifetime");
        let guard = std::sync::Arc::downgrade(&snapshot._execution_guard);
        let prepared = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot).unwrap();
        assert!(guard.upgrade().is_some());

        let cloned = prepared.clone();
        drop(prepared);
        assert!(guard.upgrade().is_some());
        drop(cloned);
        assert!(guard.upgrade().is_none());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_rejects_another_lease_identity() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-other-lease");
        let pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();
        let mut other = snapshot;
        other.execution_identity.inode += 1;

        assert!(matches!(
            pinned.authorize_pinned_snapshot(&config, &other),
            Err(PreparationError::PinnedLeaseMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_rejects_changed_binding_identity_fields() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-binding-identity");
        let pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();

        for mutate in [
            |candidate: &mut PinnedBottleSnapshot| candidate.binding.bottle_id.push_str("-other"),
            |candidate: &mut PinnedBottleSnapshot| candidate.binding.path.push_str(".other"),
            |candidate: &mut PinnedBottleSnapshot| candidate.binding.digest = format!("sha256:{}", "0".repeat(64)),
            |candidate: &mut PinnedBottleSnapshot| candidate.binding.architecture = CpuArchitecture::I386,
        ] {
            let mut candidate = snapshot.clone();
            mutate(&mut candidate);
            assert!(matches!(
                pinned.authorize_pinned_snapshot(&config, &candidate),
                Err(PreparationError::PinnedLeaseMismatch)
            ));
        }

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_rejects_changed_inspection() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-inspection");
        let pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();
        let mut changed = snapshot;
        changed.inspection.file_digest = format!("sha256:{}", "1".repeat(64));

        assert!(matches!(
            pinned.authorize_pinned_snapshot(&config, &changed),
            Err(PreparationError::PinnedLeaseMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_preparation_rejects_request_binding_lies() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-request-lies");

        let mut wrong_bottle = request.clone();
        wrong_bottle.bottle_id.push_str("-other");
        assert!(matches!(
            PreparedLaunch::prepare_pinned_snapshot(&config, &wrong_bottle, snapshot.clone()),
            Err(PreparationError::PinnedLeaseMismatch)
        ));

        let mut wrong_path = request.clone();
        wrong_path.executable.path.push_str(".other");
        assert!(matches!(
            PreparedLaunch::prepare_pinned_snapshot(&config, &wrong_path, snapshot.clone()),
            Err(PreparationError::SourcePathMismatch)
        ));

        let mut wrong_architecture = request.clone();
        wrong_architecture.executable.architecture = CpuArchitecture::I386;
        assert!(matches!(
            PreparedLaunch::prepare_pinned_snapshot(&config, &wrong_architecture, snapshot.clone()),
            Err(PreparationError::ArchitectureMismatch { .. })
        ));

        let mut wrong_digest = request;
        wrong_digest.executable.sha256 = Some("0".repeat(64));
        assert!(matches!(
            PreparedLaunch::prepare_pinned_snapshot(&config, &wrong_digest, snapshot),
            Err(PreparationError::DigestMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_preparation_rejects_an_initial_cross_storage_root() {
        let (mut config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-cross-storage");
        config.storage_root = root.join("other-store").to_string_lossy().into_owned();

        assert!(matches!(
            PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot),
            Err(PreparationError::SourcePathMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_preparation_rejects_non_bottle_request_mode() {
        let (config, root, mut request, _ordinary, snapshot) = pinned_oracle_input("pinned-request-mode");
        request.executable.mode = ExecutableMode::ImmutableArtifact;

        assert!(matches!(
            PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot),
            Err(PreparationError::PinnedLeaseMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_rejects_cross_storage_before_context_fingerprint() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-authorize-storage");
        let prepared = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();
        let mut changed = config;
        changed.storage_root = root.join("other-store").to_string_lossy().into_owned();

        assert!(matches!(
            prepared.authorize_pinned_snapshot(&changed, &snapshot),
            Err(PreparationError::SourcePathMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_rejects_context_and_prepared_request_drift() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-context-request");
        let mut pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();
        let mut changed_config = config.clone();
        changed_config.sandbox_profile = SandboxProfile::Strict;
        assert!(matches!(
            pinned.authorize_pinned_snapshot(&changed_config, &snapshot),
            Err(PreparationError::ContextMismatch)
        ));

        pinned.request.arguments.push("--drift".into());
        assert!(matches!(
            pinned.authorize_pinned_snapshot(&config, &snapshot),
            Err(PreparationError::PreparedPlanMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_authorization_rejects_direct_plan_drift() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-plan-drift");
        let mut pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot.clone()).unwrap();
        pinned.plan.process.arguments.push("--drift".into());

        assert!(matches!(
            pinned.authorize_pinned_snapshot(&config, &snapshot),
            Err(PreparationError::PreparedPlanMismatch)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ordinary_authorize_rejects_pinned_state_without_reopening_the_path() {
        let (config, root, request, _ordinary, snapshot) = pinned_oracle_input("pinned-no-path-fallback");
        let pinned = PreparedLaunch::prepare_pinned_snapshot(&config, &request, snapshot).unwrap();
        std::fs::remove_file(&request.executable.path).unwrap();

        assert!(matches!(
            pinned.authorize(&config),
            Err(PreparationError::PinnedAuthorizationRequired)
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_same_lease_prepares_and_authorizes() {
        let (config, root, _source, request, pinned, _held, _raw_work) = real_pinned_fixture("pinned-valid-same-lease");
        let prepared = PreparedLaunch::prepare_pinned_bottle(&config, &request, &pinned).unwrap();

        prepared.authorize_pinned(&config, &pinned).unwrap();

        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_preparation_revalidates_source_drift() {
        let (config, root, source, request, pinned, _held, _raw_work) =
            real_pinned_fixture("pinned-prepare-source-drift");
        std::fs::write(&source, b"drifted after capture").unwrap();

        assert!(matches!(
            PreparedLaunch::prepare_pinned_bottle(&config, &request, &pinned),
            Err(PreparationError::GuestArtifact(_))
        ));

        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_authorization_revalidates_source_drift() {
        let (config, root, source, request, pinned, _held, _raw_work) =
            real_pinned_fixture("pinned-authorize-source-drift");
        let prepared = PreparedLaunch::prepare_pinned_bottle(&config, &request, &pinned).unwrap();
        std::fs::write(&source, b"drifted after preparation").unwrap();

        assert!(matches!(
            prepared.authorize_pinned(&config, &pinned),
            Err(PreparationError::GuestArtifact(_))
        ));

        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_public_preparation_rejects_an_initial_cross_storage_root() {
        let (mut config, root, _source, request, pinned, _held, _raw_work) =
            real_pinned_fixture("pinned-public-storage");
        config.storage_root = root.join("other-store").to_string_lossy().into_owned();

        assert!(matches!(
            PreparedLaunch::prepare_pinned_bottle(&config, &request, &pinned),
            Err(PreparationError::SourcePathMismatch)
        ));

        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_public_preparation_rejects_execution_overwrite() {
        use std::io::{Seek, Write};

        let (config, root, _source, request, pinned, _held, _raw_work) =
            real_pinned_fixture("pinned-execution-overwrite");
        let mut execution = pinned.duplicate_execution_file().unwrap();
        execution.seek(std::io::SeekFrom::Start(0)).unwrap();
        execution.write_all(b"XX").unwrap();
        execution.sync_all().unwrap();

        assert!(matches!(
            PreparedLaunch::prepare_pinned_bottle(&config, &request, &pinned),
            Err(PreparationError::GuestArtifact(_))
        ));

        drop(execution);
        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_public_authorization_rejects_execution_size_drift() {
        let (config, root, _source, request, pinned, _held, _raw_work) = real_pinned_fixture("pinned-execution-size");
        let prepared = PreparedLaunch::prepare_pinned_bottle(&config, &request, &pinned).unwrap();
        let execution = pinned.duplicate_execution_file().unwrap();
        execution.set_len(pinned.binding().size_bytes - 1).unwrap();
        execution.sync_all().unwrap();

        assert!(matches!(
            prepared.authorize_pinned(&config, &pinned),
            Err(PreparationError::GuestArtifact(_))
        ));

        drop(execution);
        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_public_authorization_rejects_another_equivalent_lease() {
        use compatforge_guest_artifact::GuestArtifactStore;

        let (config, root, source, request, pinned, held, _raw_work) = real_pinned_fixture("pinned-public-other-lease");
        let prepared = PreparedLaunch::prepare_pinned_bottle(&config, &request, &pinned).unwrap();
        drop(pinned);
        let other = GuestArtifactStore::new(&config.storage_root)
            .pin_sumatra_bottle_executable("gui-sumatrapdf", &source, &held)
            .unwrap();

        assert!(matches!(
            prepared.authorize_pinned(&config, &other),
            Err(PreparationError::PinnedLeaseMismatch)
        ));

        drop(other);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compiles_native_linux_plan_without_shell_commands() {
        let plan = PolicyEngine::compile(&config(CpuArchitecture::X86_64), &request()).unwrap();
        assert_eq!(plan.runtime.provider, RuntimeKind::Wine);
        assert_eq!(plan.translator.provider, TranslatorKind::Native);
        assert_eq!(plan.graphics.backend, GraphicsBackendKind::Dxvk);
        assert_eq!(plan.process.arguments[0], request().executable.path);
        assert_eq!(
            plan.process.environment["WINEPREFIX"],
            "/var/lib/compatforge/bottles/example-bottle/prefix"
        );
        assert_eq!(
            plan.lifecycle.wineserver.as_ref().unwrap().prefix,
            "/var/lib/compatforge/bottles/example-bottle/prefix"
        );
        assert_eq!(
            plan.lifecycle.termination_grace_milliseconds,
            config(CpuArchitecture::X86_64)
                .supervisor
                .termination_grace_milliseconds
        );
    }

    #[test]
    fn compiles_windows_paths_without_using_the_build_host_separator() {
        let mut config = config(CpuArchitecture::X86_64);
        config.capabilities.host.os = HostOs::Windows;
        config.storage_root = "C:\\ProgramData\\CompatForge".into();
        config.runtime_bindings[0].executable = "C:\\Program Files\\CompatForge\\wine.exe".into();
        config.runtime_bindings[0].wineserver_executable =
            Some("C:\\Program Files\\CompatForge\\wineserver.exe".into());

        let plan = PolicyEngine::compile(&config, &request()).unwrap();

        assert_eq!(
            plan.process.environment["WINEPREFIX"],
            "C:\\ProgramData\\CompatForge\\bottles\\example-bottle\\prefix"
        );
        assert_eq!(
            plan.process.working_directory,
            "C:\\ProgramData\\CompatForge\\bottles\\example-bottle"
        );
        assert_eq!(
            plan.lifecycle.wineserver.unwrap().prefix,
            "C:\\ProgramData\\CompatForge\\bottles\\example-bottle\\prefix"
        );
    }

    #[test]
    fn selects_fex_for_x86_64_guest_on_linux_arm64() {
        let plan = PolicyEngine::compile(&config(CpuArchitecture::Arm64), &request()).unwrap();
        assert_eq!(plan.translator.provider, TranslatorKind::Fex);
    }

    #[test]
    fn sends_driver_dependent_software_to_a_vm() {
        let mut request = request();
        request.constraints.requires_kernel_driver = true;
        let plan = PolicyEngine::compile(&config(CpuArchitecture::X86_64), &request).unwrap();
        assert_eq!(plan.runtime.provider, RuntimeKind::VirtualMachine);
        assert_eq!(plan.graphics.backend, GraphicsBackendKind::Virtualized);
        assert!(plan.lifecycle.wineserver.is_none());
    }

    #[test]
    fn refuses_unpinned_runtime_provider() {
        let mut config = config(CpuArchitecture::X86_64);
        config.runtime_bindings.clear();
        assert!(matches!(
            PolicyEngine::compile(&config, &request()),
            Err(PlanError::MissingRuntimeBinding(_))
        ));
    }

    #[test]
    fn authorizes_a_freshly_compiled_plan() {
        let config = config(CpuArchitecture::X86_64);
        let plan = PolicyEngine::compile(&config, &request()).unwrap();
        PolicyEngine::authorize(&config, &plan).unwrap();
    }

    #[test]
    fn rejects_a_plan_with_a_replaced_runtime_executable() {
        let config = config(CpuArchitecture::X86_64);
        let mut plan = PolicyEngine::compile(&config, &request()).unwrap();
        plan.process.executable = "/tmp/untrusted-runtime".into();
        assert!(matches!(
            PolicyEngine::authorize(&config, &plan),
            Err(PlanError::PlanMismatch("runtime executable"))
        ));
    }

    #[test]
    fn rejects_replaced_supervisor_and_wineserver_policies() {
        let config = config(CpuArchitecture::X86_64);
        let mut plan = PolicyEngine::compile(&config, &request()).unwrap();
        plan.lifecycle.termination_grace_milliseconds += 1;
        assert!(matches!(
            PolicyEngine::authorize(&config, &plan),
            Err(PlanError::PlanMismatch("supervisor policy"))
        ));

        let mut plan = PolicyEngine::compile(&config, &request()).unwrap();
        plan.lifecycle.wineserver.as_mut().unwrap().executable = "/tmp/untrusted-wineserver".into();
        assert!(matches!(
            PolicyEngine::authorize(&config, &plan),
            Err(PlanError::PlanMismatch("wineserver lifecycle"))
        ));
    }

    #[test]
    fn runtime_binding_environment_cannot_be_overridden_by_a_request() {
        let mut config = config(CpuArchitecture::X86_64);
        config.runtime_bindings[0]
            .environment
            .insert("COMPATFORGE_RUNTIME_PACK".into(), "trusted".into());
        let mut request = request();
        request
            .environment
            .insert("COMPATFORGE_RUNTIME_PACK".into(), "untrusted".into());
        let plan = PolicyEngine::compile(&config, &request).unwrap();
        assert_eq!(plan.process.environment["COMPATFORGE_RUNTIME_PACK"], "trusted");
        PolicyEngine::authorize(&config, &plan).unwrap();
    }

    #[test]
    fn recognizes_serialized_absolute_paths_independent_of_build_host() {
        assert!(is_absolute_host_path("/var/lib/compatforge"));
        assert!(is_absolute_host_path("C:\\Program Files\\CompatForge"));
        assert!(is_absolute_host_path("\\\\server\\share\\CompatForge"));
        assert!(!is_absolute_host_path("relative/path"));
        assert!(!is_absolute_host_path("C:relative"));
    }

    #[test]
    fn host_path_containment_is_cross_platform_and_rejects_traversal() {
        assert!(host_path_is_within(
            "/var/lib/compatforge",
            "/var/lib/compatforge/bottles/example"
        ));
        assert!(host_path_is_within(
            "C:\\Program Files\\CompatForge",
            "c:/program files/compatforge/bottles/example"
        ));
        assert!(!host_path_is_within(
            "/var/lib/compatforge",
            "/var/lib/compatforge/../outside"
        ));
        assert!(!host_path_is_within(
            "C:\\Program Files\\CompatForge",
            "D:\\Program Files\\CompatForge"
        ));
    }
}
