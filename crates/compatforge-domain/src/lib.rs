//! Versioned, platform-neutral contracts shared by every CompatForge client.

#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const SCHEMA_VERSION_V1: &str = "1";
pub const DEFAULT_TERMINATION_GRACE_MILLISECONDS: u64 = 3_000;
pub const MAX_TERMINATION_GRACE_MILLISECONDS: u64 = 60_000;
pub const MAX_RUNTIME_MILLISECONDS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostOs {
    MacOs,
    Linux,
    Android,
    Windows,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CpuArchitecture {
    #[serde(rename = "i386")]
    I386,
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "arm64")]
    Arm64,
    #[serde(rename = "unknown")]
    Unknown,
}

impl CpuArchitecture {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::I386 => "i386",
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
pub enum RuntimeKind {
    #[serde(rename = "wine")]
    Wine,
    #[serde(rename = "virtual-machine")]
    VirtualMachine,
    #[serde(rename = "remote")]
    Remote,
}

impl RuntimeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wine => "wine",
            Self::VirtualMachine => "virtual-machine",
            Self::Remote => "remote",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
pub enum TranslatorKind {
    #[serde(rename = "native")]
    Native,
    #[serde(rename = "rosetta")]
    Rosetta,
    #[serde(rename = "fex")]
    Fex,
    #[serde(rename = "box64")]
    Box64,
    #[serde(rename = "qemu")]
    Qemu,
    #[serde(rename = "remote")]
    Remote,
}

impl TranslatorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Rosetta => "rosetta",
            Self::Fex => "fex",
            Self::Box64 => "box64",
            Self::Qemu => "qemu",
            Self::Remote => "remote",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
pub enum GraphicsBackendKind {
    #[serde(rename = "wined3d")]
    WineD3d,
    #[serde(rename = "dxvk")]
    Dxvk,
    #[serde(rename = "vkd3d-proton")]
    Vkd3dProton,
    #[serde(rename = "d3dmetal")]
    D3dMetal,
    #[serde(rename = "moltenvk")]
    MoltenVk,
    #[serde(rename = "virtualized")]
    Virtualized,
    #[serde(rename = "remote")]
    Remote,
}

impl GraphicsBackendKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WineD3d => "wined3d",
            Self::Dxvk => "dxvk",
            Self::Vkd3dProton => "vkd3d-proton",
            Self::D3dMetal => "d3dmetal",
            Self::MoltenVk => "moltenvk",
            Self::Virtualized => "virtualized",
            Self::Remote => "remote",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    #[default]
    Deny,
    InstallerOnly,
    Allow,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxProfile {
    Strict,
    #[default]
    Desktop,
    Game,
    Developer,
    Unconfined,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostDescriptor {
    pub os: HostOs,
    pub os_version: String,
    pub architecture: CpuArchitecture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDescriptor {
    pub id: String,
    pub kind: String,
    pub version: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl ProviderDescriptor {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("provider.id", &self.id)?;
        if self.kind.is_empty() {
            return Err(ContractError::MissingField("provider.kind"));
        }
        if self.version.is_empty() {
            return Err(ContractError::MissingField("provider.version"));
        }
        if !self.available && self.reason.as_deref().map_or(true, str::is_empty) {
            return Err(ContractError::MissingField("provider.reason"));
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capabilities {
            if capability.is_empty() {
                return Err(ContractError::MissingField("provider.capabilities"));
            }
            if !capabilities.insert(capability) {
                return Err(ContractError::DuplicateValue("provider.capabilities"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeStatus {
    Detected,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeSource {
    RustStandardLibrary,
    OperatingSystemFile,
    OperatingSystemApi,
    BuiltIn,
    RuntimePack,
    Configuration,
}

/// A Schema v1 capability value.
///
/// Keeping this as a closed scalar type prevents domain objects from carrying
/// arrays, objects, or JSON null into public capability reports.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CapabilityValue {
    Boolean(bool),
    String(String),
    Number(serde_json::Number),
}

impl CapabilityValue {
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            Self::String(_) | Self::Number(_) => None,
        }
    }
}

impl From<bool> for CapabilityValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<String> for CapabilityValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for CapabilityValue {
    fn from(value: &str) -> Self {
        Self::String(value.into())
    }
}

impl From<u64> for CapabilityValue {
    fn from(value: u64) -> Self {
        Self::Number(value.into())
    }
}

fn deserialize_optional_capability_value<'de, D>(deserializer: D) -> Result<Option<CapabilityValue>, D::Error>
where
    D: Deserializer<'de>,
{
    CapabilityValue::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityObservation {
    pub id: String,
    pub category: String,
    pub status: ProbeStatus,
    pub source: ProbeSource,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_capability_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<CapabilityValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl CapabilityObservation {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("observations.id", &self.id)?;
        if self.category.is_empty() {
            return Err(ContractError::MissingField("observations.category"));
        }
        match self.status {
            ProbeStatus::Detected if self.value.is_none() => Err(ContractError::MissingField("observations.value")),
            ProbeStatus::Unavailable | ProbeStatus::Unknown if self.reason.as_deref().map_or(true, str::is_empty) => {
                Err(ContractError::MissingField("observations.reason"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityReport {
    pub schema_version: String,
    pub host: HostDescriptor,
    pub runtime_providers: Vec<ProviderDescriptor>,
    pub translators: Vec<ProviderDescriptor>,
    pub graphics_backends: Vec<ProviderDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<CapabilityObservation>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub features: BTreeMap<String, CapabilityValue>,
}

impl CapabilityReport {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_schema_version(&self.schema_version)?;
        if self.host.os_version.is_empty() {
            return Err(ContractError::MissingField("host.osVersion"));
        }
        if self.host.architecture == CpuArchitecture::Unknown {
            return Err(ContractError::UnsupportedValue("host.architecture"));
        }

        let mut provider_ids = BTreeSet::new();
        for provider in self
            .runtime_providers
            .iter()
            .chain(self.translators.iter())
            .chain(self.graphics_backends.iter())
        {
            provider.validate()?;
            if !provider_ids.insert(&provider.id) {
                return Err(ContractError::DuplicateValue("provider.id"));
            }
        }

        let mut observation_ids = BTreeSet::new();
        for observation in &self.observations {
            observation.validate()?;
            if !observation_ids.insert(&observation.id) {
                return Err(ContractError::DuplicateValue("observations.id"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ExecutableMode {
    #[default]
    ImmutableArtifact,
    BottleInPlace,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutableRequest {
    pub path: String,
    pub architecture: CpuArchitecture,
    #[serde(default)]
    pub mode: ExecutableMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchConstraints {
    pub allow_virtual_machine: bool,
    pub allow_remote: bool,
    #[serde(default)]
    pub requires_kernel_driver: bool,
    #[serde(default)]
    pub requires_direct_x12: bool,
    #[serde(default)]
    pub network_policy: NetworkPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisorPolicy {
    #[serde(default = "default_termination_grace_milliseconds")]
    pub termination_grace_milliseconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_runtime_milliseconds: Option<u64>,
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            termination_grace_milliseconds: DEFAULT_TERMINATION_GRACE_MILLISECONDS,
            maximum_runtime_milliseconds: None,
        }
    }
}

impl SupervisorPolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !(1..=MAX_TERMINATION_GRACE_MILLISECONDS).contains(&self.termination_grace_milliseconds) {
            return Err(ContractError::UnsupportedValue(
                "supervisor.terminationGraceMilliseconds",
            ));
        }
        if self
            .maximum_runtime_milliseconds
            .is_some_and(|value| value == 0 || value > MAX_RUNTIME_MILLISECONDS)
        {
            return Err(ContractError::UnsupportedValue("supervisor.maximumRuntimeMilliseconds"));
        }
        Ok(())
    }
}

const fn default_termination_grace_milliseconds() -> u64 {
    DEFAULT_TERMINATION_GRACE_MILLISECONDS
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchRequest {
    pub schema_version: String,
    pub request_id: String,
    pub bottle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipe_id: Option<String>,
    pub executable: ExecutableRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    pub constraints: LaunchConstraints,
}

impl LaunchRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_schema_version(&self.schema_version)?;
        validate_id("bottleId", &self.bottle_id)?;
        if let Some(recipe_id) = &self.recipe_id {
            validate_id("recipeId", recipe_id)?;
        }
        if self.request_id.is_empty() {
            return Err(ContractError::MissingField("requestId"));
        }
        if self.executable.path.is_empty() {
            return Err(ContractError::MissingField("executable.path"));
        }
        if self.executable.architecture == CpuArchitecture::Unknown {
            return Err(ContractError::UnsupportedValue("executable.architecture"));
        }
        if let Some(digest) = &self.executable.sha256 {
            validate_sha256("executable.sha256", digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeBinding {
    pub provider_id: String,
    pub pack_id: String,
    pub pack_digest: String,
    pub executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wineserver_executable: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

impl RuntimeBinding {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("runtimeBindings.providerId", &self.provider_id)?;
        validate_id("runtimeBindings.packId", &self.pack_id)?;
        validate_digest("runtimeBindings.packDigest", &self.pack_digest)?;
        if self.executable.is_empty() {
            return Err(ContractError::MissingField("runtimeBindings.executable"));
        }
        if self.wineserver_executable.as_deref() == Some("") {
            return Err(ContractError::MissingField("runtimeBindings.wineserverExecutable"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreConfig {
    pub schema_version: String,
    pub capabilities: CapabilityReport,
    pub runtime_bindings: Vec<RuntimeBinding>,
    pub storage_root: String,
    #[serde(default)]
    pub sandbox_profile: SandboxProfile,
    #[serde(default)]
    pub supervisor: SupervisorPolicy,
}

impl CoreConfig {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_schema_version(&self.schema_version)?;
        self.capabilities.validate()?;
        if self.storage_root.is_empty() {
            return Err(ContractError::MissingField("storageRoot"));
        }
        for binding in &self.runtime_bindings {
            binding.validate()?;
        }
        self.supervisor.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSelection {
    pub provider: RuntimeKind,
    pub pack_id: String,
    pub pack_digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranslatorSelection {
    pub provider: TranslatorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphicsSelection {
    pub backend: GraphicsBackendKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: String,
}

/// Immutable evidence binding for a guest executable materialized in the
/// dedicated content-addressed guest artifact store.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestArtifactBinding {
    pub digest: String,
    pub size_bytes: u64,
    pub stored_path: String,
    pub original_name: String,
    pub architecture: CpuArchitecture,
    pub image_kind: String,
    pub subsystem: String,
    pub inspection_schema_version: String,
}

impl GuestArtifactBinding {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_digest("guestArtifact.digest", &self.digest)?;
        if self.size_bytes == 0 {
            return Err(ContractError::UnsupportedValue("guestArtifact.sizeBytes"));
        }
        if self.stored_path.is_empty() {
            return Err(ContractError::MissingField("guestArtifact.storedPath"));
        }
        if self.original_name.is_empty()
            || self.original_name.contains('/')
            || self.original_name.contains('\\')
            || matches!(self.original_name.as_str(), "." | "..")
        {
            return Err(ContractError::UnsupportedValue("guestArtifact.originalName"));
        }
        if !matches!(self.architecture, CpuArchitecture::I386 | CpuArchitecture::X86_64) {
            return Err(ContractError::UnsupportedValue("guestArtifact.architecture"));
        }
        if self.image_kind != "executable" {
            return Err(ContractError::UnsupportedValue("guestArtifact.imageKind"));
        }
        if !matches!(self.subsystem.as_str(), "windowsConsole" | "windowsGui") {
            return Err(ContractError::UnsupportedValue("guestArtifact.subsystem"));
        }
        validate_schema_version(&self.inspection_schema_version)
    }
}

/// Digest-bound executable that remains in an authorized Bottle prefix so
/// Wine can resolve its sibling DLLs, plugins and resources.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BottleExecutableBinding {
    pub bottle_id: String,
    pub digest: String,
    pub size_bytes: u64,
    pub path: String,
    pub original_name: String,
    pub architecture: CpuArchitecture,
    pub image_kind: String,
    pub subsystem: String,
    pub inspection_schema_version: String,
}

impl BottleExecutableBinding {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("bottleExecutable.bottleId", &self.bottle_id)?;
        validate_digest("bottleExecutable.digest", &self.digest)?;
        if self.size_bytes == 0 {
            return Err(ContractError::UnsupportedValue("bottleExecutable.sizeBytes"));
        }
        if self.path.is_empty() {
            return Err(ContractError::MissingField("bottleExecutable.path"));
        }
        if self.original_name.is_empty()
            || self.original_name.contains('/')
            || self.original_name.contains('\\')
            || matches!(self.original_name.as_str(), "." | "..")
        {
            return Err(ContractError::UnsupportedValue("bottleExecutable.originalName"));
        }
        if !matches!(self.architecture, CpuArchitecture::I386 | CpuArchitecture::X86_64) {
            return Err(ContractError::UnsupportedValue("bottleExecutable.architecture"));
        }
        if self.image_kind != "executable" {
            return Err(ContractError::UnsupportedValue("bottleExecutable.imageKind"));
        }
        if !matches!(self.subsystem.as_str(), "windowsConsole" | "windowsGui") {
            return Err(ContractError::UnsupportedValue("bottleExecutable.subsystem"));
        }
        validate_schema_version(&self.inspection_schema_version)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mount {
    pub source: String,
    pub destination: String,
    pub access: MountAccess,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPolicy {
    pub profile: SandboxProfile,
    pub network: NetworkPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_devices: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WineServerLifecycle {
    pub executable: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessLifecycle {
    #[serde(default = "default_termination_grace_milliseconds")]
    pub termination_grace_milliseconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_runtime_milliseconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wineserver: Option<WineServerLifecycle>,
}

impl Default for ProcessLifecycle {
    fn default() -> Self {
        Self {
            termination_grace_milliseconds: DEFAULT_TERMINATION_GRACE_MILLISECONDS,
            maximum_runtime_milliseconds: None,
            wineserver: None,
        }
    }
}

impl ProcessLifecycle {
    pub fn validate(&self) -> Result<(), ContractError> {
        SupervisorPolicy {
            termination_grace_milliseconds: self.termination_grace_milliseconds,
            maximum_runtime_milliseconds: self.maximum_runtime_milliseconds,
        }
        .validate()?;
        if let Some(wineserver) = &self.wineserver {
            if wineserver.executable.is_empty() {
                return Err(ContractError::MissingField("lifecycle.wineserver.executable"));
            }
            if wineserver.prefix.is_empty() {
                return Err(ContractError::MissingField("lifecycle.wineserver.prefix"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchPlan {
    pub schema_version: String,
    pub request_id: String,
    pub runtime: RuntimeSelection,
    pub translator: TranslatorSelection,
    pub graphics: GraphicsSelection,
    pub process: NativeCommand,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_artifact: Option<GuestArtifactBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bottle_executable: Option<BottleExecutableBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    pub sandbox: SandboxPolicy,
    #[serde(default)]
    pub lifecycle: ProcessLifecycle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decision_trace: Vec<String>,
}

impl LaunchPlan {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_schema_version(&self.schema_version)?;
        if self.request_id.is_empty() {
            return Err(ContractError::MissingField("requestId"));
        }
        validate_id("runtime.packId", &self.runtime.pack_id)?;
        validate_digest("runtime.packDigest", &self.runtime.pack_digest)?;
        if self.process.executable.is_empty() {
            return Err(ContractError::MissingField("process.executable"));
        }
        if self.process.working_directory.is_empty() {
            return Err(ContractError::MissingField("process.workingDirectory"));
        }
        if let Some(binding) = &self.guest_artifact {
            if self.bottle_executable.is_some() {
                return Err(ContractError::UnsupportedValue("guestArtifact/bottleExecutable"));
            }
            binding.validate()?;
            if self.process.arguments.first() != Some(&binding.stored_path) {
                return Err(ContractError::UnsupportedValue("process.arguments[0]"));
            }
        }
        if let Some(binding) = &self.bottle_executable {
            if self.guest_artifact.is_some() {
                return Err(ContractError::UnsupportedValue("guestArtifact/bottleExecutable"));
            }
            binding.validate()?;
            if self.process.arguments.first() != Some(&binding.path) {
                return Err(ContractError::UnsupportedValue("process.arguments[0]"));
            }
        }
        self.lifecycle.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeEventKind {
    Started,
    Output,
    TerminateRequested,
    TimedOut,
    GracePeriodExpired,
    WineServerStopRequested,
    Exited,
    Failed,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessOutput {
    pub stream: OutputStream,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessExit {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    pub success: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvent {
    pub schema_version: String,
    pub request_id: String,
    pub sequence: u64,
    pub elapsed_milliseconds: u64,
    pub kind: RuntimeEventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<ProcessOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<ProcessExit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BottleManifest {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub guest: BottleGuest,
    pub runtime_pack: RuntimePackReference,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipes: Vec<RecipeReference>,
    pub storage: BottleStorage,
    pub created_at: String,
    pub updated_at: String,
}

impl BottleManifest {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_schema_version(&self.schema_version)?;
        validate_id("bottle.id", &self.id)?;
        if self.name.is_empty() {
            return Err(ContractError::MissingField("bottle.name"));
        }
        if !matches!(
            self.guest.architecture,
            CpuArchitecture::I386 | CpuArchitecture::X86_64 | CpuArchitecture::Arm64
        ) {
            return Err(ContractError::UnsupportedValue("bottle.guest.architecture"));
        }

        validate_id("bottle.runtimePack.id", &self.runtime_pack.id)?;
        validate_digest("bottle.runtimePack.digest", &self.runtime_pack.digest)?;

        let mut recipe_ids = BTreeSet::new();
        for recipe in &self.recipes {
            validate_id("bottle.recipes.id", &recipe.id)?;
            validate_digest("bottle.recipes.digest", &recipe.digest)?;
            if !recipe_ids.insert(recipe.id.as_str()) {
                return Err(ContractError::DuplicateValue("bottle.recipes.id"));
            }
        }

        if self.storage.layout_version == 0 {
            return Err(ContractError::UnsupportedValue("bottle.storage.layoutVersion"));
        }
        match self.storage.state {
            BottleState::Ready
            | BottleState::Preparing
            | BottleState::Migrating
            | BottleState::Repairing
            | BottleState::Failed => {}
        }

        validate_rfc3339("bottle.createdAt", &self.created_at)?;
        validate_rfc3339("bottle.updatedAt", &self.updated_at)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BottleGuest {
    pub windows_version: WindowsVersion,
    pub architecture: CpuArchitecture,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowsVersion {
    Win7,
    Win10,
    Win11,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePackReference {
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipeReference {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BottleStorage {
    pub layout_version: u32,
    pub state: BottleState,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BottleState {
    Ready,
    Preparing,
    Migrating,
    Repairing,
    Failed,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePackManifest {
    pub schema_version: String,
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<RuntimeChannel>,
    pub host: RuntimeHost,
    pub components: Vec<RuntimeComponent>,
    pub capabilities: Vec<String>,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ManifestSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom: Option<String>,
}

impl RuntimePackManifest {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_schema_version(&self.schema_version)?;
        validate_id("runtimePack.id", &self.id)?;
        if self.version.is_empty() {
            return Err(ContractError::MissingField("runtimePack.version"));
        }
        if !matches!(self.host.architecture, CpuArchitecture::X86_64 | CpuArchitecture::Arm64) {
            return Err(ContractError::UnsupportedValue("runtimePack.host.architecture"));
        }
        if self.host.minimum_version.as_deref().is_some_and(str::is_empty) {
            return Err(ContractError::MissingField("runtimePack.host.minimumVersion"));
        }
        if self.components.is_empty() {
            return Err(ContractError::MissingField("runtimePack.components"));
        }

        let mut component_names = BTreeSet::new();
        for component in &self.components {
            component.validate()?;
            if !component_names.insert(component.name.as_str()) {
                return Err(ContractError::DuplicateValue("runtimePack.components.name"));
            }
        }

        let mut capabilities = BTreeSet::new();
        for capability in &self.capabilities {
            if capability.is_empty() {
                return Err(ContractError::MissingField("runtimePack.capabilities"));
            }
            if !capabilities.insert(capability.as_str()) {
                return Err(ContractError::DuplicateValue("runtimePack.capabilities"));
            }
        }

        validate_digest("runtimePack.digest", &self.digest)?;
        if let Some(signature) = &self.signature {
            validate_id("runtimePack.signature.keyId", &signature.key_id)?;
            if signature.value.is_empty() {
                return Err(ContractError::MissingField("runtimePack.signature.value"));
            }
        }
        if self.sbom.as_deref().is_some_and(str::is_empty) {
            return Err(ContractError::MissingField("runtimePack.sbom"));
        }
        Ok(())
    }

    /// Canonical compact JSON signed and hashed for the pack digest.
    ///
    /// The self-referential `digest` and the replaceable `signature` envelope
    /// are deliberately excluded. Components and capabilities are sorted so
    /// semantically identical manifests have identical bytes.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut components = self.components.clone();
        for component in &mut components {
            if component.artifact.is_none() {
                component.artifact = Some(component.default_artifact_path());
            }
        }
        components.sort_by(|left, right| left.name.cmp(&right.name));
        let mut capabilities = self.capabilities.clone();
        capabilities.sort();
        serde_json::to_vec(&UnsignedRuntimePackManifest {
            schema_version: &self.schema_version,
            id: &self.id,
            version: &self.version,
            channel: self.channel,
            host: &self.host,
            components: &components,
            capabilities: &capabilities,
            sbom: self.sbom.as_deref(),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedRuntimePackManifest<'a> {
    schema_version: &'a str,
    id: &'a str,
    version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<RuntimeChannel>,
    host: &'a RuntimeHost,
    components: &'a [RuntimeComponent],
    capabilities: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    sbom: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeChannel {
    Stable,
    Candidate,
    Preview,
    Development,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeHost {
    pub os: HostOs,
    pub architecture: CpuArchitecture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeComponent {
    pub name: String,
    pub version: String,
    pub license: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Portable path to the opaque component artifact inside a bundle.
    /// Missing values use `components/<name>.blob` for Schema v1 compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    pub digest: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entrypoints: BTreeMap<String, String>,
}

impl RuntimeComponent {
    #[must_use]
    pub fn artifact_path(&self) -> String {
        self.artifact.clone().unwrap_or_else(|| self.default_artifact_path())
    }

    fn default_artifact_path(&self) -> String {
        format!("components/{}.blob", self.name)
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_id("runtimePack.components.name", &self.name)?;
        if self.version.is_empty() {
            return Err(ContractError::MissingField("runtimePack.components.version"));
        }
        if self.license.is_empty() {
            return Err(ContractError::MissingField("runtimePack.components.license"));
        }
        validate_portable_relative_path("runtimePack.components.artifact", &self.artifact_path())?;
        validate_digest("runtimePack.components.digest", &self.digest)?;
        for (name, path) in &self.entrypoints {
            validate_id("runtimePack.components.entrypoints.name", name)?;
            validate_portable_relative_path("runtimePack.components.entrypoints.path", path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestSignature {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
pub enum SignatureAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "p256-sha256")]
    P256Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    UnsupportedSchemaVersion,
    MissingField(&'static str),
    InvalidIdentifier(&'static str),
    InvalidDigest(&'static str),
    DuplicateValue(&'static str),
    UnsupportedValue(&'static str),
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion => formatter.write_str("unsupported schemaVersion"),
            Self::MissingField(field) => write!(formatter, "missing required field {field}"),
            Self::InvalidIdentifier(field) => write!(formatter, "invalid identifier in {field}"),
            Self::InvalidDigest(field) => write!(formatter, "invalid digest in {field}"),
            Self::DuplicateValue(field) => write!(formatter, "duplicate value in {field}"),
            Self::UnsupportedValue(field) => write!(formatter, "unsupported value in {field}"),
        }
    }
}

impl std::error::Error for ContractError {}

pub fn validate_schema_version(version: &str) -> Result<(), ContractError> {
    if version == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(ContractError::UnsupportedSchemaVersion)
    }
}

pub fn validate_id(field: &'static str, value: &str) -> Result<(), ContractError> {
    let mut characters = value.chars();
    let first_is_valid = characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit());
    let rest_is_valid = characters.all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || matches!(character, '.' | '_' | '-')
    });
    if first_is_valid && rest_is_valid && value.len() >= 2 {
        Ok(())
    } else {
        Err(ContractError::InvalidIdentifier(field))
    }
}

pub fn validate_sha256(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ContractError::InvalidDigest(field))
    }
}

pub fn validate_digest(field: &'static str, value: &str) -> Result<(), ContractError> {
    value
        .strip_prefix("sha256:")
        .ok_or(ContractError::InvalidDigest(field))
        .and_then(|digest| validate_sha256(field, digest))
}

pub fn validate_rfc3339(field: &'static str, value: &str) -> Result<(), ContractError> {
    if is_rfc3339(value.as_bytes()) {
        Ok(())
    } else {
        Err(ContractError::UnsupportedValue(field))
    }
}

fn is_rfc3339(value: &[u8]) -> bool {
    if value.len() < 20
        || value.get(4) != Some(&b'-')
        || value.get(7) != Some(&b'-')
        || !matches!(value.get(10), Some(b'T' | b't'))
        || value.get(13) != Some(&b':')
        || value.get(16) != Some(&b':')
    {
        return false;
    }

    let Some(year) = decimal(value, 0, 4) else {
        return false;
    };
    let Some(month) = decimal(value, 5, 7) else {
        return false;
    };
    let Some(day) = decimal(value, 8, 10) else {
        return false;
    };
    let Some(hour) = decimal(value, 11, 13) else {
        return false;
    };
    let Some(minute) = decimal(value, 14, 16) else {
        return false;
    };
    let Some(second) = decimal(value, 17, 19) else {
        return false;
    };

    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 60 {
        return false;
    }

    let timezone_start = if value[19] == b'.' {
        let Some(position) = value[20..]
            .iter()
            .position(|byte| matches!(byte, b'Z' | b'z' | b'+' | b'-'))
        else {
            return false;
        };
        let timezone_start = position + 20;
        if timezone_start == 20 || !value[20..timezone_start].iter().all(u8::is_ascii_digit) {
            return false;
        }
        timezone_start
    } else {
        19
    };

    let timezone_offset_minutes = match value.get(timezone_start) {
        Some(b'Z' | b'z') if timezone_start + 1 == value.len() => 0,
        Some(b'+' | b'-') => {
            if timezone_start + 6 != value.len() || value.get(timezone_start + 3) != Some(&b':') {
                return false;
            }
            let Some(offset_hour) = decimal(value, timezone_start + 1, timezone_start + 3) else {
                return false;
            };
            let Some(offset_minute) = decimal(value, timezone_start + 4, timezone_start + 6) else {
                return false;
            };
            if offset_hour > 23 || offset_minute > 59 {
                return false;
            }
            let offset = (offset_hour * 60 + offset_minute) as i32;
            if value[timezone_start] == b'-' {
                -offset
            } else {
                offset
            }
        }
        _ => return false,
    };

    if second < 60 {
        return true;
    }

    let local_minutes = (hour * 60 + minute) as i32;
    let utc_minutes = local_minutes - timezone_offset_minutes;
    let utc_day_delta = utc_minutes.div_euclid(24 * 60);
    utc_minutes.rem_euclid(24 * 60) == 23 * 60 + 59
        && matches!(
            (utc_day_delta, month, day),
            (0, 6, 30) | (0, 12, 31) | (-1, 7, 1) | (-1, 1, 1)
        )
}

fn decimal(value: &[u8], start: usize, end: usize) -> Option<u32> {
    value.get(start..end)?.iter().try_fold(0, |result, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        Some(result * 10 + u32::from(byte - b'0'))
    })
}

pub fn validate_portable_relative_path(field: &'static str, value: &str) -> Result<(), ContractError> {
    let valid = !value.is_empty()
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..");
    if valid {
        Ok(())
    } else {
        Err(ContractError::UnsupportedValue(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_launch_request_serialization_stays_byte_compatible() {
        let request: LaunchRequest =
            serde_json::from_str(include_str!("../../../examples/launch-request.json")).unwrap();

        assert_eq!(
            serde_json::to_vec(&request).unwrap(),
            br#"{"schemaVersion":"1","requestId":"018fe3cb-9d12-7b52-b334-1cce0e857fc9","bottleId":"7zip-default","recipeId":"7zip","executable":{"path":"C:\\Program Files\\7-Zip\\7zFM.exe","architecture":"x86_64","mode":"immutableArtifact"},"constraints":{"allowVirtualMachine":true,"allowRemote":true,"requiresKernelDriver":false,"requiresDirectX12":false,"networkPolicy":"allow"}}"#,
        );
    }

    #[test]
    fn pinned_bottle_executable_binding_serialization_stays_byte_compatible() {
        let binding = BottleExecutableBinding {
            bottle_id: "gui-sumatrapdf".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            size_bytes: 12_345,
            path: r"C:\CompatForge\SumatraPDF\SumatraPDF.exe".into(),
            original_name: "SumatraPDF.exe".into(),
            architecture: CpuArchitecture::X86_64,
            image_kind: "executable".into(),
            subsystem: "windowsGui".into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        };

        assert_eq!(
            serde_json::to_vec(&binding).unwrap(),
            br#"{"bottleId":"gui-sumatrapdf","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sizeBytes":12345,"path":"C:\\CompatForge\\SumatraPDF\\SumatraPDF.exe","originalName":"SumatraPDF.exe","architecture":"x86_64","imageKind":"executable","subsystem":"windowsGui","inspectionSchemaVersion":"1"}"#,
        );
    }

    #[test]
    fn pinned_launch_plan_serialization_stays_byte_compatible() {
        let plan: LaunchPlan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();

        assert_eq!(
            serde_json::to_vec(&plan).unwrap(),
            br#"{"schemaVersion":"1","requestId":"018fe3cb-9d12-7b52-b334-1cce0e857fc9","runtime":{"provider":"wine","packId":"wine-linux-arm64-fex","packDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"translator":{"provider":"fex","version":"pack-pinned"},"graphics":{"backend":"dxvk","version":"pack-pinned"},"process":{"executable":"/opt/compatforge/runtime/bin/wine","arguments":["C:\\Program Files\\7-Zip\\7zFM.exe"],"environment":{"WINEPREFIX":"/var/lib/compatforge/bottles/7zip-default/prefix"},"workingDirectory":"/var/lib/compatforge/bottles/7zip-default"},"mounts":[{"source":"/home/example/Documents","destination":"/mnt/documents","access":"read-write"}],"sandbox":{"profile":"desktop","network":"allow"},"lifecycle":{"terminationGraceMilliseconds":3000,"maximumRuntimeMilliseconds":21600000,"wineserver":{"executable":"/opt/compatforge/runtime/bin/wineserver","prefix":"/var/lib/compatforge/bottles/7zip-default/prefix"}},"decisionTrace":["local Wine is available","x86_64 guest on ARM64 requires translation","FEX selected before Box64 and QEMU","DXVK selected for D3D8-11 capability"]}"#,
        );
    }

    #[test]
    fn parses_checked_in_contract_examples() {
        let capability: CapabilityReport =
            serde_json::from_str(include_str!("../../../examples/capability-report.linux-arm64.json")).unwrap();
        assert_eq!(capability.host.architecture, CpuArchitecture::Arm64);

        let request: LaunchRequest =
            serde_json::from_str(include_str!("../../../examples/launch-request.json")).unwrap();
        request.validate().unwrap();

        let plan: LaunchPlan = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
        assert_eq!(plan.runtime.provider, RuntimeKind::Wine);
        plan.validate().unwrap();

        let config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        config.validate().unwrap();

        let event: RuntimeEvent = serde_json::from_str(include_str!("../../../examples/runtime-event.json")).unwrap();
        assert_eq!(event.kind, RuntimeEventKind::Output);

        let runtime: RuntimePackManifest = serde_json::from_str(include_str!(
            "../../../examples/runtime-packs/wine-linux-arm64-fex.json"
        ))
        .unwrap();
        assert_eq!(runtime.host.os, HostOs::Linux);
        runtime.validate().unwrap();

        let bottle: BottleManifest =
            serde_json::from_str(include_str!("../../../examples/bottles/7zip-default.json")).unwrap();
        assert_eq!(bottle.storage.state, BottleState::Ready);
    }

    fn valid_bottle_manifest() -> BottleManifest {
        serde_json::from_str(include_str!("../../../examples/bottles/7zip-default.json")).unwrap()
    }

    #[test]
    fn bottle_manifest_rejects_unknown_versions_and_unpinned_runtime() {
        let mut manifest = valid_bottle_manifest();
        manifest.schema_version = "2".into();
        assert_eq!(manifest.validate(), Err(ContractError::UnsupportedSchemaVersion));

        let mut manifest = valid_bottle_manifest();
        manifest.runtime_pack.digest = "sha256:0000".into();
        assert_eq!(
            manifest.validate(),
            Err(ContractError::InvalidDigest("bottle.runtimePack.digest"))
        );
    }

    #[test]
    fn bottle_manifest_validates_ids_names_and_timestamps() {
        let mut manifest = valid_bottle_manifest();
        manifest.id = "../escape".into();
        assert_eq!(manifest.validate(), Err(ContractError::InvalidIdentifier("bottle.id")));

        let mut manifest = valid_bottle_manifest();
        manifest.name.clear();
        assert_eq!(manifest.validate(), Err(ContractError::MissingField("bottle.name")));

        let mut manifest = valid_bottle_manifest();
        manifest.runtime_pack.id = "INVALID".into();
        assert_eq!(
            manifest.validate(),
            Err(ContractError::InvalidIdentifier("bottle.runtimePack.id"))
        );

        for field in ["createdAt", "updatedAt"] {
            let mut manifest = valid_bottle_manifest();
            if field == "createdAt" {
                manifest.created_at = "2026-02-30T00:00:00Z".into();
            } else {
                manifest.updated_at = "not-a-timestamp".into();
            }
            assert_eq!(
                manifest.validate(),
                Err(ContractError::UnsupportedValue(if field == "createdAt" {
                    "bottle.createdAt"
                } else {
                    "bottle.updatedAt"
                }))
            );
        }

        let mut manifest = valid_bottle_manifest();
        manifest.created_at = "2026-08-08T00:00:60Z".into();
        assert_eq!(
            manifest.validate(),
            Err(ContractError::UnsupportedValue("bottle.createdAt"))
        );

        for timestamp in ["2016-12-31T23:59:60Z", "2017-01-01T00:59:60+01:00"] {
            let mut manifest = valid_bottle_manifest();
            manifest.created_at = timestamp.into();
            manifest.validate().unwrap();
        }
    }

    #[test]
    fn bottle_manifest_rejects_non_digit_timestamp_components_without_panicking() {
        const TIMESTAMP: &str = "2026-08-08T00:00:00+08:30";
        const DIGIT_POSITIONS: [usize; 18] = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 23, 24];

        for replacement in ["/", "é"] {
            for position in DIGIT_POSITIONS {
                let mut timestamp = TIMESTAMP.to_owned();
                timestamp.replace_range(position..position + 1, replacement);
                let mut manifest = valid_bottle_manifest();
                manifest.created_at = timestamp;
                assert_eq!(
                    manifest.validate(),
                    Err(ContractError::UnsupportedValue("bottle.createdAt"))
                );
            }
        }
    }

    #[test]
    fn bottle_manifest_validates_guest_and_storage_schema() {
        let mut manifest = valid_bottle_manifest();
        manifest.guest.architecture = CpuArchitecture::Unknown;
        assert_eq!(
            manifest.validate(),
            Err(ContractError::UnsupportedValue("bottle.guest.architecture"))
        );

        for windows_version in [WindowsVersion::Win7, WindowsVersion::Win10, WindowsVersion::Win11] {
            for architecture in [CpuArchitecture::I386, CpuArchitecture::X86_64, CpuArchitecture::Arm64] {
                let mut manifest = valid_bottle_manifest();
                manifest.guest.windows_version = windows_version;
                manifest.guest.architecture = architecture;
                manifest.validate().unwrap();
            }
        }

        let mut manifest = valid_bottle_manifest();
        manifest.storage.layout_version = 0;
        assert_eq!(
            manifest.validate(),
            Err(ContractError::UnsupportedValue("bottle.storage.layoutVersion"))
        );

        for invalid_layout in [serde_json::json!(false), serde_json::json!(1.0)] {
            let mut value = serde_json::to_value(valid_bottle_manifest()).unwrap();
            value["storage"]["layoutVersion"] = invalid_layout;
            assert!(serde_json::from_value::<BottleManifest>(value).is_err());
        }
        let mut value = serde_json::to_value(valid_bottle_manifest()).unwrap();
        value["storage"]["state"] = serde_json::json!("unknown");
        assert!(serde_json::from_value::<BottleManifest>(value).is_err());
    }

    #[test]
    fn bottle_manifest_rejects_duplicate_recipes_and_invalid_recipe_fields() {
        let mut manifest = valid_bottle_manifest();
        manifest.recipes.push(manifest.recipes[0].clone());
        assert_eq!(
            manifest.validate(),
            Err(ContractError::DuplicateValue("bottle.recipes.id"))
        );

        let mut manifest = valid_bottle_manifest();
        manifest.recipes[0].id = "INVALID".into();
        assert_eq!(
            manifest.validate(),
            Err(ContractError::InvalidIdentifier("bottle.recipes.id"))
        );

        let mut manifest = valid_bottle_manifest();
        manifest.recipes[0].digest = "latest".into();
        assert_eq!(
            manifest.validate(),
            Err(ContractError::InvalidDigest("bottle.recipes.digest"))
        );

        let mut manifest = valid_bottle_manifest();
        manifest.recipes[0].version.clear();
        manifest.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_security_relevant_fields() {
        let json = r#"{
            "schemaVersion":"1",
            "requestId":"018fe3cb-9d12-7b52-b334-1cce0e857fc9",
            "bottleId":"example-bottle",
            "executable":{"path":"C:\\\\example.exe","architecture":"x86_64"},
            "constraints":{"allowVirtualMachine":false,"allowRemote":false,"unexpected":true}
        }"#;
        assert!(serde_json::from_str::<LaunchRequest>(json).is_err());
    }

    #[test]
    fn validates_identifiers_and_digests() {
        assert!(validate_id("id", "wine-linux-arm64").is_ok());
        assert!(validate_id("id", "../escape").is_err());
        assert!(validate_digest("digest", &format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(validate_digest("digest", "latest").is_err());
        assert!(validate_portable_relative_path("path", "components/wine.tar.zst").is_ok());
        assert!(validate_portable_relative_path("path", "../wine.tar.zst").is_err());
        assert!(validate_portable_relative_path("path", "C:\\wine.tar.zst").is_err());
    }

    #[test]
    fn rejects_unbounded_supervisor_policies() {
        assert!(SupervisorPolicy {
            termination_grace_milliseconds: 0,
            maximum_runtime_milliseconds: None,
        }
        .validate()
        .is_err());
        assert!(SupervisorPolicy {
            termination_grace_milliseconds: DEFAULT_TERMINATION_GRACE_MILLISECONDS,
            maximum_runtime_milliseconds: Some(MAX_RUNTIME_MILLISECONDS + 1),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn validates_capability_observation_evidence() {
        let mut report: CapabilityReport =
            serde_json::from_str(include_str!("../../../examples/capability-report.linux-arm64.json")).unwrap();
        report.validate().unwrap();

        report.observations.push(report.observations[0].clone());
        assert_eq!(report.validate(), Err(ContractError::DuplicateValue("observations.id")));

        let mut observation = report.observations[0].clone();
        observation.status = ProbeStatus::Unknown;
        observation.value = None;
        observation.reason = None;
        assert_eq!(
            observation.validate(),
            Err(ContractError::MissingField("observations.reason"))
        );
    }

    #[test]
    fn rejects_non_scalar_capability_values() {
        let report: CapabilityReport =
            serde_json::from_str(include_str!("../../../examples/capability-report.linux-arm64.json")).unwrap();

        for invalid in [serde_json::json!({"nested": true}), serde_json::json!([true])] {
            let mut value = serde_json::to_value(&report).unwrap();
            value["features"]["vulkan"] = invalid.clone();
            assert!(serde_json::from_value::<CapabilityReport>(value).is_err());

            let mut value = serde_json::to_value(&report).unwrap();
            value["observations"][0]["value"] = invalid;
            assert!(serde_json::from_value::<CapabilityReport>(value).is_err());
        }

        let mut null_feature = serde_json::to_value(&report).unwrap();
        null_feature["features"]["vulkan"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CapabilityReport>(null_feature).is_err());

        let mut null_observation = serde_json::to_value(&report).unwrap();
        null_observation["observations"][0]["status"] = serde_json::json!("unknown");
        null_observation["observations"][0]["reason"] = serde_json::json!("not detected");
        null_observation["observations"][0]["value"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CapabilityReport>(null_observation).is_err());
    }
}
