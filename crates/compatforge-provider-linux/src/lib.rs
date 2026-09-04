//! Linux x86_64 Wine Provider contracts.

#![deny(unsafe_op_in_unsafe_fn)]

mod elf;
mod probe;
#[cfg(target_os = "linux")]
mod unix_process_group;

pub use probe::{
    probe_runtime_with, ProbeCommand, ProbeCommandFailure, ProbeCommandOutput, ProbeCommandSpec, ProbeCommandStatus,
    RuntimeProbeObservation, SystemProbeCommand,
};

use compatforge_domain::{
    validate_digest, validate_id, validate_portable_relative_path, validate_schema_version, CapabilityReport,
    ContractError, CoreConfig, CpuArchitecture, HostOs, ProviderDescriptor, RuntimeBinding, RuntimeChannel,
    RuntimeComponent, RuntimeHost, RuntimePackManifest, SCHEMA_VERSION_V1,
};
use compatforge_runtime::{sha256_digest_bytes, RejectAllSignatures, RuntimePackStore};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_ID_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 128;
const MAX_ABSOLUTE_PATH_BYTES: usize = 4096;
const MAX_RELATIVE_PATH_BYTES: usize = 1024;
const RUNTIME_CAPABILITY: &str = "guest-x86_64";
const WINED3D_CAPABILITY: &str = "opengl";
const NATIVE_PROVIDER_ID: &str = "native-host";
const WINED3D_PROVIDER_ID: &str = "linux-wined3d";
const LOCAL_PREVIEW_PROVIDER_ID: &str = "wine-linux-x86-64-preview";
const LOCAL_PREVIEW_PACK_ID: &str = "wine-linux-x86-64-local-preview";
const BOOTSTRAP_STAGING_PARENT: &str = ".compatforge-bootstrap";
const BOOTSTRAP_STAGING_PREFIX: &str = ".compatforge-bootstrap-";
const WINE_BUNDLE_ARTIFACT: &str = "components/wine-entrypoint.bin";
const WINESERVER_BUNDLE_ARTIFACT: &str = "components/wineserver-entrypoint.bin";
const MAX_ACTIVE_REF_BYTES: u64 = 64 * 1024;
const MAX_ACTIVATION_HISTORY: usize = 32;
const MAX_SUPPLEMENTARY_GROUPS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactActiveRef {
    schema_version: String,
    pack_id: String,
    active_digest: String,
    #[serde(default)]
    history: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveRefObservation {
    raw: Option<Vec<u8>>,
    state: Option<ExactActiveRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnerIdentity {
    filesystem_uid: u32,
    filesystem_gid: u32,
    supplementary_groups: [u32; MAX_SUPPLEMENTARY_GROUPS],
    supplementary_group_count: usize,
}

impl OwnerIdentity {
    #[cfg(any(unix, test))]
    fn is_group_member(&self, gid: u32) -> bool {
        gid == self.filesystem_gid
            || self.supplementary_groups[..self.supplementary_group_count]
                .binary_search(&gid)
                .is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    mount_id: u64,
    parent_id: u64,
    device: Vec<u8>,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountSnapshot {
    entries: Vec<MountEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysicalIdentity {
    device: Vec<u8>,
    path: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelevantMount {
    mount_id: u64,
    parent_id: u64,
    device: Vec<u8>,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEvidence {
    selected: Vec<RelevantMount>,
    store_control_mounts: Vec<RelevantMount>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxProviderConfig {
    pub schema_version: String,
    pub runtime_store_root: String,
    pub wine_runtime: WineRuntimeConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WineRuntimeConfig {
    pub provider_id: String,
    pub pack_id: String,
    pub pack_digest: String,
    pub version: String,
    #[serde(deserialize_with = "deserialize_known_architecture")]
    pub architecture: CpuArchitecture,
    pub materialized_root: String,
    pub wine: VerifiedEntrypoint,
    pub wineserver: VerifiedEntrypoint,
    pub capabilities: Vec<String>,
    pub wined3d_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedEntrypoint {
    pub path: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxLocalContextRequest {
    pub schema_version: String,
    pub runtime_store_root: String,
    pub storage_root: String,
    pub materialized_root: String,
    pub wine: String,
    pub wineserver: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxLocalContextReceipt {
    pub schema_version: String,
    pub source: String,
    pub version: String,
    pub architecture: CpuArchitecture,
    pub pack_id: String,
    pub pack_digest: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinuxLocalContext {
    pub config: CoreConfig,
    pub receipt: LinuxLocalContextReceipt,
}

impl LinuxProviderConfig {
    pub fn validate(&self) -> Result<(), LinuxProviderError> {
        validate_schema_version(&self.schema_version)?;
        if !serialized_linux_absolute_path(&self.runtime_store_root) {
            return Err(LinuxProviderError::InvalidConfig("runtimeStoreRoot"));
        }
        self.wine_runtime.validate()
    }
}

impl WineRuntimeConfig {
    fn validate(&self) -> Result<(), LinuxProviderError> {
        validate_linux_id("wineRuntime.providerId", &self.provider_id)?;
        if matches!(self.provider_id.as_str(), NATIVE_PROVIDER_ID | WINED3D_PROVIDER_ID) {
            return Err(LinuxProviderError::InvalidConfig("wineRuntime.providerId"));
        }
        validate_linux_id("wineRuntime.packId", &self.pack_id)?;
        validate_linux_digest("wineRuntime.packDigest", &self.pack_digest)?;
        if !valid_version(&self.version) {
            return Err(LinuxProviderError::InvalidConfig("wineRuntime.version"));
        }
        if self.architecture != CpuArchitecture::X86_64 {
            return Err(LinuxProviderError::InvalidConfig("wineRuntime.architecture"));
        }
        if !serialized_linux_absolute_path(&self.materialized_root) {
            return Err(LinuxProviderError::InvalidConfig("wineRuntime.materializedRoot"));
        }
        self.wine.validate("wineRuntime.wine.path", "wineRuntime.wine.digest")?;
        self.wineserver
            .validate("wineRuntime.wineserver.path", "wineRuntime.wineserver.digest")?;
        if self.capabilities.as_slice() != [RUNTIME_CAPABILITY] {
            return Err(LinuxProviderError::InvalidConfig("wineRuntime.capabilities"));
        }
        if self.wined3d_capabilities.as_slice() != [WINED3D_CAPABILITY] {
            return Err(LinuxProviderError::InvalidConfig("wineRuntime.wined3dCapabilities"));
        }
        Ok(())
    }
}

impl VerifiedEntrypoint {
    fn validate(&self, path_field: &'static str, digest_field: &'static str) -> Result<(), LinuxProviderError> {
        validate_linux_relative_path(path_field, &self.path)?;
        validate_linux_digest(digest_field, &self.digest)?;
        Ok(())
    }
}

impl LinuxLocalContextRequest {
    pub fn validate(&self) -> Result<(), LinuxProviderError> {
        validate_schema_version(&self.schema_version)?;
        for (field, value) in [
            ("runtimeStoreRoot", self.runtime_store_root.as_str()),
            ("storageRoot", self.storage_root.as_str()),
            ("materializedRoot", self.materialized_root.as_str()),
        ] {
            if !serialized_linux_absolute_path(value) {
                return Err(LinuxProviderError::InvalidRequest(field));
            }
        }
        validate_linux_relative_path("wine", &self.wine)?;
        validate_linux_relative_path("wineserver", &self.wineserver)?;
        if !valid_version(&self.version) {
            return Err(LinuxProviderError::InvalidRequest("version"));
        }
        Ok(())
    }
}

fn deserialize_known_architecture<'de, D>(deserializer: D) -> Result<CpuArchitecture, D::Error>
where
    D: Deserializer<'de>,
{
    let architecture = String::deserialize(deserializer).map_err(|_| D::Error::custom("unsupported architecture"))?;
    match architecture.as_str() {
        "i386" => Ok(CpuArchitecture::I386),
        "x86_64" => Ok(CpuArchitecture::X86_64),
        "arm64" => Ok(CpuArchitecture::Arm64),
        _ => Err(D::Error::custom("unsupported architecture")),
    }
}

fn validate_linux_id(field: &'static str, value: &str) -> Result<(), ContractError> {
    validate_id(field, value)?;
    if value.len() <= MAX_ID_BYTES {
        Ok(())
    } else {
        Err(ContractError::InvalidIdentifier(field))
    }
}

fn validate_linux_digest(field: &'static str, value: &str) -> Result<(), ContractError> {
    validate_digest(field, value)?;
    if value.strip_prefix("sha256:").is_some_and(|digest| {
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        Ok(())
    } else {
        Err(ContractError::InvalidDigest(field))
    }
}

fn validate_linux_relative_path(field: &'static str, value: &str) -> Result<(), ContractError> {
    validate_portable_relative_path(field, value)?;
    if value.len() <= MAX_RELATIVE_PATH_BYTES && !value.bytes().any(|byte| matches!(byte, b'\0' | b'\r' | b'\n')) {
        Ok(())
    } else {
        Err(ContractError::UnsupportedValue(field))
    }
}

fn serialized_linux_absolute_path(value: &str) -> bool {
    let Some(relative) = value.strip_prefix('/') else {
        return false;
    };
    !relative.is_empty()
        && value.len() <= MAX_ABSOLUTE_PATH_BYTES
        && !value.contains('\\')
        && !value.bytes().any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        && relative
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn valid_version(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= MAX_VERSION_BYTES
        && bytes.next().is_some_and(|byte| byte.is_ascii_digit())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFailure {
    MaterializedRoot,
    Entrypoint,
    Digest,
    Elf,
    Architecture,
    RuntimePack,
    Version,
    Command,
}

impl fmt::Display for EvidenceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MaterializedRoot => "Linux runtime materialized root evidence failed",
            Self::Entrypoint => "Linux runtime entrypoint evidence failed",
            Self::Digest => "Linux runtime digest evidence failed",
            Self::Elf => "Linux runtime ELF evidence failed",
            Self::Architecture => "Linux runtime architecture evidence failed",
            Self::RuntimePack => "Linux runtime pack evidence failed",
            Self::Version => "Linux runtime version evidence failed",
            Self::Command => "Linux runtime command evidence failed",
        })
    }
}

impl std::error::Error for EvidenceFailure {}

pub fn verify_entrypoint(
    materialized_root: &Path,
    entrypoint: &VerifiedEntrypoint,
) -> Result<PathBuf, EvidenceFailure> {
    validate_linux_relative_path("wineRuntime.entrypoint.path", &entrypoint.path)
        .map_err(|_| EvidenceFailure::Entrypoint)?;
    validate_linux_digest("wineRuntime.entrypoint.digest", &entrypoint.digest).map_err(|_| EvidenceFailure::Digest)?;

    let canonical_root = fs::canonicalize(materialized_root).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    let root_metadata = fs::metadata(&canonical_root).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    if !root_metadata.is_dir() {
        return Err(EvidenceFailure::MaterializedRoot);
    }

    let candidate = canonical_root.join(&entrypoint.path);
    if !candidate.starts_with(&canonical_root) {
        return Err(EvidenceFailure::Entrypoint);
    }
    let canonical_entrypoint = fs::canonicalize(candidate).map_err(|_| EvidenceFailure::Entrypoint)?;
    if !canonical_entrypoint.starts_with(&canonical_root) {
        return Err(EvidenceFailure::Entrypoint);
    }

    let metadata = fs::metadata(&canonical_entrypoint).map_err(|_| EvidenceFailure::Entrypoint)?;
    if !metadata.is_file() {
        return Err(EvidenceFailure::Entrypoint);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(EvidenceFailure::Entrypoint);
        }
    }

    if sha256_file(&canonical_entrypoint)? != entrypoint.digest {
        return Err(EvidenceFailure::Digest);
    }
    let header = read_elf_header(&canonical_entrypoint)?;
    elf::parse_x86_64(&header).map_err(|error| match error {
        elf::ElfError::Invalid => EvidenceFailure::Elf,
        elf::ElfError::Architecture => EvidenceFailure::Architecture,
    })?;

    Ok(canonical_entrypoint)
}

fn sha256_file(path: &Path) -> Result<String, EvidenceFailure> {
    let mut file = File::open(path).map_err(|_| EvidenceFailure::Digest)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| EvidenceFailure::Digest)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn read_elf_header(path: &Path) -> Result<[u8; 64], EvidenceFailure> {
    let mut file = File::open(path).map_err(|_| EvidenceFailure::Elf)?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header).map_err(|_| EvidenceFailure::Elf)?;
    Ok(header)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxProviderError {
    Contract(ContractError),
    InvalidConfig(&'static str),
    InvalidRequest(&'static str),
    UnsupportedHost,
    ProviderUnavailable,
    Evidence(EvidenceFailure),
}

impl fmt::Display for LinuxProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid Linux Provider contract: {error}"),
            Self::InvalidConfig(field) => {
                write!(formatter, "invalid Linux Provider configuration: {field}")
            }
            Self::InvalidRequest(field) => {
                write!(formatter, "invalid Linux local context request: {field}")
            }
            Self::UnsupportedHost => formatter.write_str("Linux Provider requires a Linux host"),
            Self::ProviderUnavailable => formatter.write_str("Linux Provider is unavailable"),
            Self::Evidence(failure) => write!(formatter, "{failure}"),
        }
    }
}

impl std::error::Error for LinuxProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Evidence(failure) => Some(failure),
            Self::InvalidConfig(_) | Self::InvalidRequest(_) | Self::UnsupportedHost | Self::ProviderUnavailable => {
                None
            }
        }
    }
}

impl From<ContractError> for LinuxProviderError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<EvidenceFailure> for LinuxProviderError {
    fn from(failure: EvidenceFailure) -> Self {
        Self::Evidence(failure)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LinuxBootstrapError {
    Contract(ContractError),
    InvalidRequest(&'static str),
    UnsupportedHost,
    Evidence(EvidenceFailure),
    ConflictingActiveRef,
    RegistrationFailed(&'static str),
    Provider(LinuxProviderError),
}

impl fmt::Display for LinuxBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid Linux bootstrap contract: {error}"),
            Self::InvalidRequest(field) => write!(formatter, "invalid Linux bootstrap request: {field}"),
            Self::UnsupportedHost => formatter.write_str("Linux bootstrap requires a Linux x86_64 host"),
            Self::Evidence(failure) => write!(formatter, "Linux bootstrap evidence failed: {failure}"),
            Self::ConflictingActiveRef => formatter.write_str("Linux Preview Runtime has a conflicting active ref"),
            Self::RegistrationFailed(operation) => {
                write!(formatter, "Linux Preview Runtime registration failed: {operation}")
            }
            Self::Provider(error) => write!(formatter, "Linux Provider bootstrap failed: {error}"),
        }
    }
}

impl std::error::Error for LinuxBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Evidence(failure) => Some(failure),
            Self::Provider(error) => Some(error),
            Self::InvalidRequest(_)
            | Self::UnsupportedHost
            | Self::ConflictingActiveRef
            | Self::RegistrationFailed(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectedRuntimeRoots {
    runtime_store: PathBuf,
    materialized_runtime: PathBuf,
}

impl ProtectedRuntimeRoots {
    fn overlaps(&self, candidate: &Path) -> bool {
        [&self.runtime_store, &self.materialized_runtime]
            .into_iter()
            .any(|protected| {
                candidate == protected || candidate.starts_with(protected) || protected.starts_with(candidate)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundProviderEvidence {
    observation: RuntimeProbeObservation,
    protected_roots: ProtectedRuntimeRoots,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxProviderSnapshot {
    pub capabilities: CapabilityReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_binding: Option<RuntimeBinding>,
    #[serde(skip)]
    protected_roots: Option<ProtectedRuntimeRoots>,
}

impl LinuxProviderSnapshot {
    pub fn core_config(&self, storage_root: String) -> Result<CoreConfig, LinuxProviderError> {
        if !serialized_linux_absolute_path(&storage_root) {
            return Err(LinuxProviderError::InvalidConfig("storageRoot"));
        }
        let canonical_storage =
            fs::canonicalize(Path::new(&storage_root)).map_err(|_| LinuxProviderError::InvalidConfig("storageRoot"))?;
        if !canonical_storage
            .metadata()
            .map_err(|_| LinuxProviderError::InvalidConfig("storageRoot"))?
            .is_dir()
        {
            return Err(LinuxProviderError::InvalidConfig("storageRoot"));
        }
        let canonical_storage_text = validated_canonical_storage_text(&canonical_storage)?;
        let protected_roots = self
            .protected_roots
            .as_ref()
            .ok_or(LinuxProviderError::ProviderUnavailable)?;
        if protected_roots.overlaps(&canonical_storage) {
            return Err(LinuxProviderError::InvalidConfig("storage/runtime root overlap"));
        }
        let runtime_binding = self
            .runtime_binding
            .clone()
            .ok_or(LinuxProviderError::ProviderUnavailable)?;
        let config = CoreConfig {
            schema_version: compatforge_domain::SCHEMA_VERSION_V1.into(),
            capabilities: self.capabilities.clone(),
            runtime_bindings: vec![runtime_binding],
            storage_root: canonical_storage_text.to_owned(),
            sandbox_profile: compatforge_domain::SandboxProfile::Desktop,
            supervisor: compatforge_domain::SupervisorPolicy::default(),
        };
        config.validate()?;
        Ok(config)
    }
}

fn validated_canonical_storage_text(path: &Path) -> Result<&str, LinuxProviderError> {
    let value = path.to_str().ok_or(LinuxProviderError::InvalidConfig("storageRoot"))?;
    if serialized_linux_absolute_path(value) {
        Ok(value)
    } else {
        Err(LinuxProviderError::InvalidConfig("storageRoot"))
    }
}

fn associate_verified_manifest(
    runtime: &WineRuntimeConfig,
    manifest: &RuntimePackManifest,
) -> Result<(), EvidenceFailure> {
    manifest.validate().map_err(|_| EvidenceFailure::RuntimePack)?;
    if manifest.digest != runtime.pack_digest
        || manifest.id != runtime.pack_id
        || manifest.version != runtime.version
        || manifest.host.os != compatforge_domain::HostOs::Linux
        || manifest.host.architecture != CpuArchitecture::X86_64
        || manifest.host.minimum_version.is_some()
        || manifest.capabilities.as_slice() != [RUNTIME_CAPABILITY]
        || manifest.components.len() != 2
    {
        return Err(EvidenceFailure::RuntimePack);
    }

    let wine = manifest
        .components
        .iter()
        .find(|component| component.name == "wine-entrypoint")
        .ok_or(EvidenceFailure::RuntimePack)?;
    let wineserver = manifest
        .components
        .iter()
        .find(|component| component.name == "wineserver-entrypoint")
        .ok_or(EvidenceFailure::RuntimePack)?;
    let wine_matches = wine.version == runtime.version
        && wine.digest == runtime.wine.digest
        && wine.entrypoints.len() == 1
        && wine.entrypoints.get("wine") == Some(&runtime.wine.path);
    let wineserver_matches = wineserver.version == runtime.version
        && wineserver.digest == runtime.wineserver.digest
        && wineserver.entrypoints.len() == 1
        && wineserver.entrypoints.get("wineserver") == Some(&runtime.wineserver.path);
    if !wine_matches || !wineserver_matches {
        return Err(EvidenceFailure::RuntimePack);
    }
    Ok(())
}

fn load_associated_manifest(
    store: &RuntimePackStore,
    runtime: &WineRuntimeConfig,
) -> Result<RuntimePackManifest, EvidenceFailure> {
    let manifest = store
        .verified_manifest(&runtime.pack_digest)
        .map_err(|_| EvidenceFailure::RuntimePack)?;
    associate_verified_manifest(runtime, &manifest)?;
    Ok(manifest)
}

fn build_provider_snapshot(
    host_report: &CapabilityReport,
    config: &LinuxProviderConfig,
    evidence: Result<BoundProviderEvidence, EvidenceFailure>,
) -> Result<LinuxProviderSnapshot, LinuxProviderError> {
    host_report.validate()?;
    config.validate()?;
    if host_report.host.os != HostOs::Linux || host_report.host.architecture != CpuArchitecture::X86_64 {
        return Err(LinuxProviderError::UnsupportedHost);
    }

    let evidence = match evidence {
        Ok(evidence) if evidence.observation.version == config.wine_runtime.version => evidence,
        Ok(_) => return unavailable_provider_snapshot(host_report, config, EvidenceFailure::Version),
        Err(failure) => return unavailable_provider_snapshot(host_report, config, failure),
    };
    let runtime = &config.wine_runtime;
    let Some(wine) = evidence
        .observation
        .wine
        .to_str()
        .filter(|value| serialized_linux_absolute_path(value))
        .map(str::to_owned)
    else {
        return unavailable_provider_snapshot(host_report, config, EvidenceFailure::Entrypoint);
    };
    let Some(wineserver) = evidence
        .observation
        .wineserver
        .to_str()
        .filter(|value| serialized_linux_absolute_path(value))
        .map(str::to_owned)
    else {
        return unavailable_provider_snapshot(host_report, config, EvidenceFailure::Entrypoint);
    };
    let report = provider_report(host_report, runtime, None)?;
    let runtime_binding = RuntimeBinding {
        provider_id: runtime.provider_id.clone(),
        pack_id: runtime.pack_id.clone(),
        pack_digest: runtime.pack_digest.clone(),
        executable: wine,
        wineserver_executable: Some(wineserver.clone()),
        environment: BTreeMap::from([
            ("COMPATFORGE_RUNTIME_PACK".into(), runtime.pack_id.clone()),
            ("COMPATFORGE_RUNTIME_PACK_DIGEST".into(), runtime.pack_digest.clone()),
            (
                "COMPATFORGE_RUNTIME_EXECUTABLE_SHA256".into(),
                runtime.wine.digest.clone(),
            ),
            (
                "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256".into(),
                runtime.wineserver.digest.clone(),
            ),
            ("WINEDEBUG".into(), "-all".into()),
            ("WINESERVER".into(), wineserver),
            ("WINEARCH".into(), "win64".into()),
            ("WINEDLLOVERRIDES".into(), "mscoree,mshtml=".into()),
        ]),
        working_directory: None,
    };
    runtime_binding.validate()?;
    Ok(LinuxProviderSnapshot {
        capabilities: report,
        runtime_binding: Some(runtime_binding),
        protected_roots: Some(evidence.protected_roots),
    })
}

fn unavailable_provider_snapshot(
    host_report: &CapabilityReport,
    config: &LinuxProviderConfig,
    failure: EvidenceFailure,
) -> Result<LinuxProviderSnapshot, LinuxProviderError> {
    let runtime = &config.wine_runtime;
    let report = provider_report(host_report, runtime, Some(failure))?;
    Ok(LinuxProviderSnapshot {
        capabilities: report,
        runtime_binding: None,
        protected_roots: None,
    })
}

fn provider_report(
    host_report: &CapabilityReport,
    runtime: &WineRuntimeConfig,
    failure: Option<EvidenceFailure>,
) -> Result<CapabilityReport, LinuxProviderError> {
    let available = failure.is_none();
    let reason = failure.map(|failure| failure.to_string());
    let mut report = host_report.clone();
    report.runtime_providers = vec![ProviderDescriptor {
        id: runtime.provider_id.clone(),
        kind: "wine".into(),
        version: runtime.version.clone(),
        available,
        reason: reason.clone(),
        capabilities: runtime.capabilities.clone(),
    }];
    report.translators = vec![ProviderDescriptor {
        id: NATIVE_PROVIDER_ID.into(),
        kind: "native".into(),
        version: "host".into(),
        available: true,
        reason: None,
        capabilities: vec!["x86_64-on-x86_64".into()],
    }];
    report.graphics_backends = vec![ProviderDescriptor {
        id: WINED3D_PROVIDER_ID.into(),
        kind: "wined3d".into(),
        version: runtime.version.clone(),
        available,
        reason,
        capabilities: runtime.wined3d_capabilities.clone(),
    }];
    report.observations.sort_by(|left, right| left.id.cmp(&right.id));
    report.validate()?;
    Ok(report)
}

pub struct LinuxProviderSet;

impl LinuxProviderSet {
    pub fn probe(
        host_report: &CapabilityReport,
        config: &LinuxProviderConfig,
    ) -> Result<LinuxProviderSnapshot, LinuxProviderError> {
        Self::probe_with(host_report, config, &SystemProbeCommand)
    }

    pub fn probe_with(
        host_report: &CapabilityReport,
        config: &LinuxProviderConfig,
        command: &dyn ProbeCommand,
    ) -> Result<LinuxProviderSnapshot, LinuxProviderError> {
        host_report.validate()?;
        config.validate()?;
        if host_report.host.os != HostOs::Linux || host_report.host.architecture != CpuArchitecture::X86_64 {
            return Err(LinuxProviderError::UnsupportedHost);
        }

        let store = RuntimePackStore::new(&config.runtime_store_root);
        if let Err(failure) = load_associated_manifest(&store, &config.wine_runtime) {
            return build_provider_snapshot(host_report, config, Err(failure));
        }
        let observation = match probe_runtime_with(config, command) {
            Ok(observation) => observation,
            Err(error) => match classify_probe_error(error) {
                Ok(failure) => return build_provider_snapshot(host_report, config, Err(failure)),
                Err(error) => return Err(error),
            },
        };
        if let Err(failure) = load_associated_manifest(&store, &config.wine_runtime) {
            return build_provider_snapshot(host_report, config, Err(failure));
        }
        let protected_roots = match canonical_protected_roots(config, &observation) {
            Ok(roots) => roots,
            Err(failure) => return build_provider_snapshot(host_report, config, Err(failure)),
        };
        build_provider_snapshot(
            host_report,
            config,
            Ok(BoundProviderEvidence {
                observation,
                protected_roots,
            }),
        )
    }
}

fn classify_probe_error(error: LinuxProviderError) -> Result<EvidenceFailure, LinuxProviderError> {
    match error {
        LinuxProviderError::Evidence(failure) => Ok(failure),
        error => Err(error),
    }
}

fn canonical_protected_roots(
    config: &LinuxProviderConfig,
    observation: &RuntimeProbeObservation,
) -> Result<ProtectedRuntimeRoots, EvidenceFailure> {
    let runtime_store = fs::canonicalize(&config.runtime_store_root).map_err(|_| EvidenceFailure::RuntimePack)?;
    if !runtime_store
        .metadata()
        .map_err(|_| EvidenceFailure::RuntimePack)?
        .is_dir()
    {
        return Err(EvidenceFailure::RuntimePack);
    }
    let materialized_runtime =
        fs::canonicalize(&config.wine_runtime.materialized_root).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    if !materialized_runtime
        .metadata()
        .map_err(|_| EvidenceFailure::MaterializedRoot)?
        .is_dir()
        || !observation.wine.starts_with(&materialized_runtime)
        || !observation.wineserver.starts_with(&materialized_runtime)
    {
        return Err(EvidenceFailure::MaterializedRoot);
    }
    Ok(ProtectedRuntimeRoots {
        runtime_store,
        materialized_runtime,
    })
}

#[derive(Debug, Clone)]
struct ResolvedBootstrapRoots {
    runtime_store: PathBuf,
    storage: PathBuf,
}

#[derive(Debug, Clone)]
struct ResolvedDestination {
    path: PathBuf,
    existing_ancestor: PathBuf,
    existed: bool,
}

#[derive(Debug, Clone)]
struct PreparedBootstrap {
    roots: ResolvedBootstrapRoots,
    owner: OwnerIdentity,
    mount_evidence: MountEvidence,
    storage_text: String,
    wine_source: PathBuf,
    wineserver_source: PathBuf,
    provider_config: LinuxProviderConfig,
    manifest: RuntimePackManifest,
}

trait BootstrapOperations {
    fn prepare_store(&self, store_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError>;
    fn create_staging(&self, store_root: &Path, owner: OwnerIdentity) -> Result<PathBuf, LinuxBootstrapError>;
    fn populate_staging(&self, staging: &Path, prepared: &PreparedBootstrap) -> Result<(), LinuxBootstrapError>;
    fn install_pack(
        &self,
        store_root: &Path,
        staging: &Path,
        manifest: &RuntimePackManifest,
    ) -> Result<(), LinuxBootstrapError>;
    fn cleanup_staging(&self, staging: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError>;
    fn prepare_storage(&self, storage_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError>;
}

struct SystemBootstrapOperations;

impl BootstrapOperations for SystemBootstrapOperations {
    fn prepare_store(&self, store_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
        create_private_directory_tree(store_root, "runtimeStoreRoot", owner)?;
        for control in [
            store_root.join("objects"),
            store_root.join("objects/sha256"),
            store_root.join("manifests"),
            store_root.join("manifests/sha256"),
            store_root.join("refs"),
            store_root.join("refs").join(LOCAL_PREVIEW_PACK_ID),
            store_root.join(BOOTSTRAP_STAGING_PARENT),
        ] {
            create_private_directory_tree(&control, "runtimeStoreRoot", owner)?;
        }
        validate_exact_private_directory(&store_root.join(BOOTSTRAP_STAGING_PARENT), "runtimeStoreRoot", owner)?;
        validate_store_controls(store_root, owner)
    }

    fn create_staging(&self, store_root: &Path, owner: OwnerIdentity) -> Result<PathBuf, LinuxBootstrapError> {
        let staging_parent = store_root.join(BOOTSTRAP_STAGING_PARENT);
        validate_exact_private_directory(&staging_parent, "runtimeStoreRoot", owner)?;
        for _ in 0..128_u8 {
            let staging = staging_parent.join(format!("{BOOTSTRAP_STAGING_PREFIX}{}", random_staging_token()?));
            match create_new_private_directory(&staging) {
                Ok(()) => {
                    return accept_created_staging(&staging, owner, &validate_new_private_directory);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(LinuxBootstrapError::RegistrationFailed("staging create")),
            }
        }
        Err(LinuxBootstrapError::RegistrationFailed("staging create"))
    }

    fn populate_staging(&self, staging: &Path, prepared: &PreparedBootstrap) -> Result<(), LinuxBootstrapError> {
        let components = staging.join("components");
        create_new_private_directory(&components)
            .map_err(|_| LinuxBootstrapError::RegistrationFailed("staging components"))?;
        validate_new_private_directory(&components, "runtimeStoreRoot", prepared.owner)?;
        copy_to_new_private_file(&prepared.wine_source, &staging.join(WINE_BUNDLE_ARTIFACT), "wine copy")?;
        copy_to_new_private_file(
            &prepared.wineserver_source,
            &staging.join(WINESERVER_BUNDLE_ARTIFACT),
            "wineserver copy",
        )?;
        let mut manifest_bytes = serde_json::to_vec_pretty(&prepared.manifest)
            .map_err(|_| LinuxBootstrapError::RegistrationFailed("manifest serialize"))?;
        manifest_bytes.push(b'\n');
        write_new_private_file(&staging.join("manifest.json"), &manifest_bytes, "manifest write")
    }

    fn install_pack(
        &self,
        store_root: &Path,
        staging: &Path,
        manifest: &RuntimePackManifest,
    ) -> Result<(), LinuxBootstrapError> {
        let receipt = RuntimePackStore::new(store_root)
            .install_bundle(staging, "manifest.json", &RejectAllSignatures)
            .map_err(|_| LinuxBootstrapError::RegistrationFailed("Runtime Pack install"))?;
        if receipt.pack_id != manifest.id || receipt.digest != manifest.digest {
            return Err(LinuxBootstrapError::RegistrationFailed("Runtime Pack receipt"));
        }
        Ok(())
    }

    fn cleanup_staging(&self, staging: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
        remove_owned_staging_directory(staging, owner)
    }

    fn prepare_storage(&self, storage_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
        create_private_directory_tree(storage_root, "storageRoot", owner)?;
        validate_private_directory(storage_root, "storageRoot", owner)
    }
}

fn accept_created_staging(
    staging: &Path,
    owner: OwnerIdentity,
    validate: &dyn Fn(&Path, &'static str, OwnerIdentity) -> Result<(), LinuxBootstrapError>,
) -> Result<PathBuf, LinuxBootstrapError> {
    if let Err(error) = validate(staging, "runtimeStoreRoot", owner) {
        return match fs::remove_dir(staging) {
            Ok(()) => Err(error),
            Err(_) => Err(LinuxBootstrapError::RegistrationFailed("staging cleanup")),
        };
    }
    Ok(staging.to_path_buf())
}

/// Register an explicit Linux x86_64 Wine Runtime and return a context that
/// has re-entered the normal Provider evidence path.
///
/// The caller must provide single-writer ownership of `runtimeStoreRoot` for
/// the duration of this call. The current Preview Runtime Store lock is only
/// process-local and does not provide a cross-process compare-and-install.
pub fn create_local_context(
    host_report: &CapabilityReport,
    request: &LinuxLocalContextRequest,
) -> Result<LinuxLocalContext, LinuxBootstrapError> {
    create_local_context_with(host_report, request, &SystemProbeCommand)
}

/// Injected-command variant of [`create_local_context`]; it has the same
/// caller-held single-writer requirement for `runtimeStoreRoot`.
pub fn create_local_context_with(
    host_report: &CapabilityReport,
    request: &LinuxLocalContextRequest,
    command: &dyn ProbeCommand,
) -> Result<LinuxLocalContext, LinuxBootstrapError> {
    validate_then_bootstrap(host_report, request, command, &SystemBootstrapOperations)
}

fn validate_then_bootstrap(
    host_report: &CapabilityReport,
    request: &LinuxLocalContextRequest,
    command: &dyn ProbeCommand,
    operations: &dyn BootstrapOperations,
) -> Result<LinuxLocalContext, LinuxBootstrapError> {
    let owner = current_owner_identity()?;
    let prepared = prepare_bootstrap(host_report, request, owner)?;
    let initial_ref = observe_exact_active_ref(&prepared.roots.runtime_store, prepared.owner)?;
    if initial_ref
        .state
        .as_ref()
        .is_some_and(|state| state.active_digest != prepared.manifest.digest)
    {
        return Err(LinuxBootstrapError::ConflictingActiveRef);
    }
    probe_prepared(&prepared, command)?;
    let revalidated = prepare_bootstrap(host_report, request, owner)?;
    ensure_same_preflight(&prepared, &revalidated)?;
    if observe_exact_active_ref(&prepared.roots.runtime_store, prepared.owner)? != initial_ref {
        return Err(LinuxBootstrapError::ConflictingActiveRef);
    }

    operations.prepare_store(&prepared.roots.runtime_store, prepared.owner)?;
    let staging = operations.create_staging(&prepared.roots.runtime_store, prepared.owner)?;
    let install_result = operations
        .populate_staging(&staging, &prepared)
        .and_then(|()| operations.install_pack(&prepared.roots.runtime_store, &staging, &prepared.manifest));
    let cleanup_result = operations.cleanup_staging(&staging, prepared.owner);
    if let Err(error) = install_result {
        return cleanup_result.and(Err(error));
    }
    cleanup_result?;

    let installed_ref = observe_exact_active_ref(&prepared.roots.runtime_store, prepared.owner)?;
    if installed_ref
        .state
        .as_ref()
        .map_or(true, |state| state.active_digest != prepared.manifest.digest)
    {
        return Err(LinuxBootstrapError::ConflictingActiveRef);
    }

    // RuntimePackStore has now completed an exact, verified registration and
    // may have published its active ref. A later re-probe or Storage failure
    // returns no Context/receipt, but deliberately does not roll that ref back:
    // the Preview contract grants only a process-local lock and cleanup owns
    // only this invocation's unpredictable staging directory.
    let snapshot = LinuxProviderSet::probe_with(host_report, &prepared.provider_config, command)
        .map_err(LinuxBootstrapError::Provider)?;
    if snapshot.runtime_binding.is_none() {
        return Err(LinuxBootstrapError::Provider(LinuxProviderError::ProviderUnavailable));
    }

    require_unchanged_active_ref(&prepared, &installed_ref)?;

    operations.prepare_storage(&prepared.roots.storage, prepared.owner)?;
    let canonical_storage =
        fs::canonicalize(&prepared.roots.storage).map_err(|_| LinuxBootstrapError::InvalidRequest("storageRoot"))?;
    if canonical_storage != prepared.roots.storage {
        return Err(LinuxBootstrapError::InvalidRequest("storageRoot"));
    }
    if canonical_storage.as_os_str() != prepared.storage_text.as_str() {
        return Err(LinuxBootstrapError::InvalidRequest("storageRoot"));
    }
    let final_preflight = prepare_bootstrap(host_report, request, owner)?;
    ensure_same_preflight(&prepared, &final_preflight)?;
    let installed_manifest = load_associated_manifest(
        &RuntimePackStore::new(&prepared.roots.runtime_store),
        &prepared.provider_config.wine_runtime,
    )
    .map_err(|failure| LinuxBootstrapError::Provider(LinuxProviderError::Evidence(failure)))?;
    if installed_manifest != prepared.manifest {
        return Err(LinuxBootstrapError::RegistrationFailed("Runtime Pack changed"));
    }
    require_unchanged_active_ref(&prepared, &installed_ref)?;
    let config = snapshot
        .core_config(prepared.storage_text)
        .map_err(LinuxBootstrapError::Provider)?;
    Ok(LinuxLocalContext {
        config,
        receipt: LinuxLocalContextReceipt {
            schema_version: SCHEMA_VERSION_V1.into(),
            source: "explicit-override".into(),
            version: request.version.clone(),
            architecture: CpuArchitecture::X86_64,
            pack_id: LOCAL_PREVIEW_PACK_ID.into(),
            pack_digest: prepared.manifest.digest,
            capabilities: vec![RUNTIME_CAPABILITY.into()],
        },
    })
}

fn require_unchanged_active_ref(
    prepared: &PreparedBootstrap,
    expected: &ActiveRefObservation,
) -> Result<(), LinuxBootstrapError> {
    let observation = observe_exact_active_ref(&prepared.roots.runtime_store, prepared.owner)?;
    if &observation != expected {
        return Err(LinuxBootstrapError::ConflictingActiveRef);
    }
    Ok(())
}

fn prepare_bootstrap(
    host_report: &CapabilityReport,
    request: &LinuxLocalContextRequest,
    owner: OwnerIdentity,
) -> Result<PreparedBootstrap, LinuxBootstrapError> {
    request.validate().map_err(map_bootstrap_request_error)?;
    host_report.validate().map_err(LinuxBootstrapError::Contract)?;
    if !cfg!(target_os = "linux")
        || host_report.host.os != HostOs::Linux
        || host_report.host.architecture != CpuArchitecture::X86_64
    {
        return Err(LinuxBootstrapError::UnsupportedHost);
    }
    let store_request = Path::new(&request.runtime_store_root);
    validate_store_path_components(store_request)?;
    let runtime_store = resolve_destination(store_request, false, "runtimeStoreRoot")?;
    if runtime_store.existed {
        validate_private_directory(&runtime_store.path, "runtimeStoreRoot", owner)?;
    } else {
        validate_creation_ancestor(&runtime_store.existing_ancestor, owner, "runtimeStoreRoot")?;
    }
    validate_store_controls(&runtime_store.path, owner)?;

    let storage = resolve_destination(Path::new(&request.storage_root), false, "storageRoot")?;
    if storage.existed {
        validate_private_directory(&storage.path, "storageRoot", owner)?;
    } else {
        validate_creation_ancestor(&storage.existing_ancestor, owner, "storageRoot")?;
    }
    let materialized = resolve_destination(Path::new(&request.materialized_root), true, "materializedRoot")?;
    require_disjoint_roots([&runtime_store.path, &storage.path, &materialized.path])?;

    let store_text = validated_resolved_path(&runtime_store.path, "runtimeStoreRoot")?;
    let storage_text = validated_resolved_path(&storage.path, "storageRoot")?;
    let materialized_text = validated_resolved_path(&materialized.path, "materializedRoot")?;
    let (wine, wine_source) = inspect_bootstrap_entrypoint(&materialized.path, &request.wine)?;
    let (wineserver, wineserver_source) = inspect_bootstrap_entrypoint(&materialized.path, &request.wineserver)?;
    let wine_text = validated_resolved_path(&wine_source, "wine canonical path")?;
    let wineserver_text = validated_resolved_path(&wineserver_source, "wineserver canonical path")?;
    let mount_snapshot = read_mount_snapshot()?;
    let mount_evidence = derive_mount_evidence(
        [&store_text, &storage_text, &materialized_text],
        [&wine_text, &wineserver_text],
        &mount_snapshot,
    )?;

    let mut manifest = RuntimePackManifest {
        schema_version: SCHEMA_VERSION_V1.into(),
        id: LOCAL_PREVIEW_PACK_ID.into(),
        version: request.version.clone(),
        channel: Some(RuntimeChannel::Preview),
        host: RuntimeHost {
            os: HostOs::Linux,
            architecture: CpuArchitecture::X86_64,
            minimum_version: None,
        },
        components: vec![
            RuntimeComponent {
                name: "wine-entrypoint".into(),
                version: request.version.clone(),
                license: "LGPL-2.1-or-later".into(),
                source: None,
                artifact: Some(WINE_BUNDLE_ARTIFACT.into()),
                digest: wine.digest.clone(),
                entrypoints: BTreeMap::from([("wine".into(), wine.path.clone())]),
            },
            RuntimeComponent {
                name: "wineserver-entrypoint".into(),
                version: request.version.clone(),
                license: "LGPL-2.1-or-later".into(),
                source: None,
                artifact: Some(WINESERVER_BUNDLE_ARTIFACT.into()),
                digest: wineserver.digest.clone(),
                entrypoints: BTreeMap::from([("wineserver".into(), wineserver.path.clone())]),
            },
        ],
        capabilities: vec![RUNTIME_CAPABILITY.into()],
        digest: String::new(),
        signature: None,
        sbom: None,
    };
    let canonical_manifest = manifest
        .canonical_unsigned_bytes()
        .map_err(|_| LinuxBootstrapError::RegistrationFailed("manifest serialize"))?;
    manifest.digest = sha256_digest_bytes(&canonical_manifest);
    manifest.validate().map_err(LinuxBootstrapError::Contract)?;
    validate_store_artifact_paths(&runtime_store.path, &manifest, owner)?;

    let provider_config = LinuxProviderConfig {
        schema_version: SCHEMA_VERSION_V1.into(),
        runtime_store_root: store_text,
        wine_runtime: WineRuntimeConfig {
            provider_id: LOCAL_PREVIEW_PROVIDER_ID.into(),
            pack_id: LOCAL_PREVIEW_PACK_ID.into(),
            pack_digest: manifest.digest.clone(),
            version: request.version.clone(),
            architecture: CpuArchitecture::X86_64,
            materialized_root: materialized_text,
            wine,
            wineserver,
            capabilities: vec![RUNTIME_CAPABILITY.into()],
            wined3d_capabilities: vec![WINED3D_CAPABILITY.into()],
        },
    };
    provider_config.validate().map_err(LinuxBootstrapError::Provider)?;
    Ok(PreparedBootstrap {
        roots: ResolvedBootstrapRoots {
            runtime_store: runtime_store.path,
            storage: storage.path,
        },
        owner,
        mount_evidence,
        storage_text,
        wine_source,
        wineserver_source,
        provider_config,
        manifest,
    })
}

fn probe_prepared(prepared: &PreparedBootstrap, command: &dyn ProbeCommand) -> Result<(), LinuxBootstrapError> {
    let observation = probe_runtime_with(&prepared.provider_config, command).map_err(map_bootstrap_probe_error)?;
    if observation.wine != prepared.wine_source
        || observation.wineserver != prepared.wineserver_source
        || observation.version != prepared.provider_config.wine_runtime.version
    {
        return Err(LinuxBootstrapError::Evidence(EvidenceFailure::Version));
    }
    Ok(())
}

fn ensure_same_preflight(first: &PreparedBootstrap, second: &PreparedBootstrap) -> Result<(), LinuxBootstrapError> {
    if first.roots.runtime_store != second.roots.runtime_store
        || first.roots.storage != second.roots.storage
        || first.storage_text != second.storage_text
        || first.wine_source != second.wine_source
        || first.wineserver_source != second.wineserver_source
        || first.provider_config != second.provider_config
        || first.manifest != second.manifest
        || first.owner != second.owner
        || first.mount_evidence != second.mount_evidence
    {
        return Err(LinuxBootstrapError::InvalidRequest("bootstrap evidence changed"));
    }
    Ok(())
}

fn map_bootstrap_request_error(error: LinuxProviderError) -> LinuxBootstrapError {
    match error {
        LinuxProviderError::Contract(error) => LinuxBootstrapError::Contract(error),
        LinuxProviderError::InvalidRequest(field) => LinuxBootstrapError::InvalidRequest(field),
        error => LinuxBootstrapError::Provider(error),
    }
}

fn map_bootstrap_probe_error(error: LinuxProviderError) -> LinuxBootstrapError {
    match error {
        LinuxProviderError::Contract(error) => LinuxBootstrapError::Contract(error),
        LinuxProviderError::Evidence(failure) => LinuxBootstrapError::Evidence(failure),
        LinuxProviderError::UnsupportedHost => LinuxBootstrapError::UnsupportedHost,
        error => LinuxBootstrapError::Provider(error),
    }
}

fn validated_resolved_path(path: &Path, field: &'static str) -> Result<String, LinuxBootstrapError> {
    path.to_str()
        .filter(|value| serialized_linux_absolute_path(value))
        .map(str::to_owned)
        .ok_or(LinuxBootstrapError::InvalidRequest(field))
}

fn resolve_destination(
    requested: &Path,
    must_exist: bool,
    field: &'static str,
) -> Result<ResolvedDestination, LinuxBootstrapError> {
    let mut cursor = requested.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                let canonical = fs::canonicalize(&cursor).map_err(|_| LinuxBootstrapError::InvalidRequest(field))?;
                if !metadata.file_type().is_symlink() && !metadata.is_dir() {
                    return Err(LinuxBootstrapError::InvalidRequest(field));
                }
                if !canonical
                    .metadata()
                    .map_err(|_| LinuxBootstrapError::InvalidRequest(field))?
                    .is_dir()
                {
                    return Err(LinuxBootstrapError::InvalidRequest(field));
                }
                if must_exist && !missing.is_empty() {
                    return Err(LinuxBootstrapError::InvalidRequest(field));
                }
                let existed = missing.is_empty();
                let existing_ancestor = canonical.clone();
                let mut destination = canonical;
                for component in missing.into_iter().rev() {
                    destination.push(component);
                }
                return Ok(ResolvedDestination {
                    path: destination,
                    existing_ancestor,
                    existed,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = cursor
                    .file_name()
                    .ok_or(LinuxBootstrapError::InvalidRequest(field))?
                    .to_os_string();
                missing.push(component);
                cursor = cursor
                    .parent()
                    .ok_or(LinuxBootstrapError::InvalidRequest(field))?
                    .to_path_buf();
            }
            Err(_) => return Err(LinuxBootstrapError::InvalidRequest(field)),
        }
    }
}

fn validate_store_path_components(path: &Path) -> Result<(), LinuxBootstrapError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(_) => return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")),
        }
    }
    Ok(())
}

fn validate_store_controls(store_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
    for directory in [
        store_root.to_path_buf(),
        store_root.join("objects"),
        store_root.join("objects/sha256"),
        store_root.join("manifests"),
        store_root.join("manifests/sha256"),
        store_root.join("refs"),
        store_root.join("refs").join(LOCAL_PREVIEW_PACK_ID),
    ] {
        match fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
                }
                validate_private_directory(&directory, "runtimeStoreRoot", owner)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")),
        }
    }
    let staging_parent = store_root.join(BOOTSTRAP_STAGING_PARENT);
    match fs::symlink_metadata(&staging_parent) {
        Ok(_) => validate_exact_private_directory(&staging_parent, "runtimeStoreRoot", owner)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")),
    }
    let active_ref = store_root.join("refs").join(LOCAL_PREVIEW_PACK_ID).join("current.json");
    match fs::symlink_metadata(active_ref) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
            }
            validate_private_metadata(&metadata, "runtimeStoreRoot", owner)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")),
    }
}

fn observe_exact_active_ref(
    store_root: &Path,
    owner: OwnerIdentity,
) -> Result<ActiveRefObservation, LinuxBootstrapError> {
    let path = store_root.join("refs").join(LOCAL_PREVIEW_PACK_ID).join("current.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ActiveRefObservation { raw: None, state: None });
        }
        Err(_) => return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_ACTIVE_REF_BYTES {
        return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
    }
    validate_private_metadata(&metadata, "runtimeStoreRoot", owner)?;
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    File::open(&path)
        .and_then(|file| file.take(MAX_ACTIVE_REF_BYTES + 1).read_to_end(&mut raw))
        .map_err(|_| LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"))?;
    if raw.len() as u64 > MAX_ACTIVE_REF_BYTES {
        return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
    }
    let state: ExactActiveRef =
        serde_json::from_slice(&raw).map_err(|_| LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"))?;
    if state.schema_version != SCHEMA_VERSION_V1
        || state.pack_id != LOCAL_PREVIEW_PACK_ID
        || validate_digest("runtimePack.digest", &state.active_digest).is_err()
        || state.history.len() > MAX_ACTIVATION_HISTORY
        || state
            .history
            .iter()
            .any(|digest| validate_digest("runtimePack.history.digest", digest).is_err())
    {
        return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
    }
    Ok(ActiveRefObservation {
        raw: Some(raw),
        state: Some(state),
    })
}

fn validate_store_artifact_paths(
    store_root: &Path,
    manifest: &RuntimePackManifest,
    owner: OwnerIdentity,
) -> Result<(), LinuxBootstrapError> {
    let mut paths = manifest
        .components
        .iter()
        .map(|component| {
            store_root
                .join("objects/sha256")
                .join(component.digest.trim_start_matches("sha256:"))
        })
        .collect::<Vec<_>>();
    paths.push(
        store_root
            .join("manifests/sha256")
            .join(format!("{}.json", manifest.digest.trim_start_matches("sha256:"))),
    );
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
            }
            Ok(metadata) => validate_private_metadata(&metadata, "runtimeStoreRoot", owner)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")),
        }
    }
    Ok(())
}

fn validate_private_directory(
    path: &Path,
    field: &'static str,
    owner: OwnerIdentity,
) -> Result<(), LinuxBootstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LinuxBootstrapError::InvalidRequest(field))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LinuxBootstrapError::InvalidRequest(field));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o700 != 0o700 {
            return Err(LinuxBootstrapError::InvalidRequest(field));
        }
    }
    validate_private_metadata(&metadata, field, owner)
}

fn validate_private_metadata(
    metadata: &fs::Metadata,
    field: &'static str,
    owner: OwnerIdentity,
) -> Result<(), LinuxBootstrapError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o022 != 0 {
            return Err(LinuxBootstrapError::InvalidRequest(field));
        }
    }
    validate_owned_metadata(metadata, field, owner)?;
    let _ = (metadata, field, owner);
    Ok(())
}

fn validate_owned_metadata(
    metadata: &fs::Metadata,
    field: &'static str,
    owner: OwnerIdentity,
) -> Result<(), LinuxBootstrapError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.uid() != owner.filesystem_uid {
            return Err(LinuxBootstrapError::InvalidRequest(field));
        }
    }
    let _ = (metadata, field, owner);
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_owner_identity() -> Result<OwnerIdentity, LinuxBootstrapError> {
    const MAX_STATUS_BYTES: u64 = 64 * 1024;

    let status = File::open("/proc/thread-self/status")
        .map(|file| file.take(MAX_STATUS_BYTES + 1))
        .and_then(|mut file| {
            let mut status = String::new();
            file.read_to_string(&mut status).map(|_| status)
        })
        .map_err(|_| LinuxBootstrapError::InvalidRequest("private directory owner"))?;
    if status.len() as u64 > MAX_STATUS_BYTES {
        return Err(LinuxBootstrapError::InvalidRequest("private directory owner"));
    }
    parse_owner_identity(&status).ok_or(LinuxBootstrapError::InvalidRequest("private directory owner"))
}

#[cfg(not(target_os = "linux"))]
fn current_owner_identity() -> Result<OwnerIdentity, LinuxBootstrapError> {
    Ok(owner_identity_for_test(0, 0, &[]).expect("empty identity is bounded"))
}

#[cfg(any(target_os = "linux", test))]
fn parse_owner_identity(status: &str) -> Option<OwnerIdentity> {
    fn unique_line<'a>(status: &'a str, prefix: &str) -> Option<&'a str> {
        let mut lines = status.lines().filter_map(|line| line.strip_prefix(prefix));
        let line = lines.next()?;
        lines.next().is_none().then_some(line)
    }
    fn four_ids(line: &str) -> Option<[u32; 4]> {
        let values = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        values.try_into().ok()
    }
    let uid = four_ids(unique_line(status, "Uid:")?)?;
    let gid = four_ids(unique_line(status, "Gid:")?)?;
    let mut groups = unique_line(status, "Groups:")?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    groups.sort_unstable();
    groups.dedup();
    owner_identity_for_test(uid[3], gid[3], &groups)
}

fn owner_identity_for_test(fs_uid: u32, fs_gid: u32, groups: &[u32]) -> Option<OwnerIdentity> {
    if groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        return None;
    }
    let mut supplementary_groups = [0; MAX_SUPPLEMENTARY_GROUPS];
    supplementary_groups[..groups.len()].copy_from_slice(groups);
    Some(OwnerIdentity {
        filesystem_uid: fs_uid,
        filesystem_gid: fs_gid,
        supplementary_groups,
        supplementary_group_count: groups.len(),
    })
}

fn validate_creation_ancestor(
    ancestor: &Path,
    owner: OwnerIdentity,
    field: &'static str,
) -> Result<(), LinuxBootstrapError> {
    let metadata = fs::metadata(ancestor).map_err(|_| LinuxBootstrapError::InvalidRequest(field))?;
    if !metadata.is_dir() {
        return Err(LinuxBootstrapError::InvalidRequest(field));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if !creation_permission_allows(metadata.mode(), metadata.uid(), metadata.gid(), owner) {
            return Err(LinuxBootstrapError::InvalidRequest(field));
        }
    }
    let _ = (metadata, owner);
    Ok(())
}

#[cfg(any(unix, test))]
fn creation_permission_allows(mode: u32, uid: u32, gid: u32, owner: OwnerIdentity) -> bool {
    let class_bits = if uid == owner.filesystem_uid {
        (mode >> 6) & 0o7
    } else if owner.is_group_member(gid) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    class_bits & 0o3 == 0o3
}

fn require_disjoint_roots(roots: [&Path; 3]) -> Result<(), LinuxBootstrapError> {
    for left in 0..roots.len() {
        for right in (left + 1)..roots.len() {
            if roots[left] == roots[right]
                || roots[left].starts_with(roots[right])
                || roots[right].starts_with(roots[left])
            {
                return Err(LinuxBootstrapError::InvalidRequest("runtime/storage root overlap"));
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn decode_mountinfo_path(value: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'\\' {
            let octal = value.get(index + 1..index + 4)?;
            if !matches!(octal, b"011" | b"012" | b"040" | b"134") {
                return None;
            }
            decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
            index += 4;
        } else {
            decoded.push(value[index]);
            index += 1;
        }
    }
    (decoded.first() == Some(&b'/') && !decoded.contains(&0)).then_some(decoded)
}

#[cfg(any(target_os = "linux", test))]
fn parse_mountinfo(contents: &[u8]) -> Option<Vec<MountEntry>> {
    let mut entries = Vec::new();
    for line in contents.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let fields = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let separator = fields.iter().position(|field| *field == b"-")?;
        if separator < 6 || separator + 3 >= fields.len() {
            return None;
        }
        let mount_id = parse_ascii_u64(fields[0])?;
        let parent_id = parse_ascii_u64(fields[1])?;
        let (major, minor) = split_once_byte(fields[2], b':')?;
        parse_ascii_u64(major)?;
        parse_ascii_u64(minor)?;
        let root = decode_mountinfo_path(fields[3])?;
        let mount_point = decode_mountinfo_path(fields[4])?;
        entries.push(MountEntry {
            mount_id,
            parent_id,
            device: fields[2].to_vec(),
            root,
            mount_point,
            read_only: ascii_option(fields[5], b"ro") || ascii_option(fields[separator + 3], b"ro"),
        });
    }
    (!entries.is_empty()).then_some(entries)
}

#[cfg(any(target_os = "linux", test))]
fn parse_ascii_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.iter().try_fold(0_u64, |number, digit| {
        number.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

#[cfg(any(target_os = "linux", test))]
fn split_once_byte(value: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let index = value.iter().position(|byte| *byte == separator)?;
    Some((&value[..index], &value[index + 1..]))
}

#[cfg(any(target_os = "linux", test))]
fn ascii_option(options: &[u8], expected: &[u8]) -> bool {
    options.split(|byte| *byte == b',').any(|option| option == expected)
}

fn linux_path_contains(parent: &[u8], child: &[u8]) -> bool {
    parent == b"/"
        || child == parent
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn visible_mounts(entries: &[MountEntry]) -> Option<Vec<MountEntry>> {
    let mut by_id = BTreeMap::new();
    for entry in entries {
        if by_id.insert(entry.mount_id, entry).is_some()
            || (entry.mount_id == entry.parent_id && entry.mount_point != b"/")
        {
            return None;
        }
    }
    if entries.iter().any(|candidate| {
        entries
            .iter()
            .filter(|entry| {
                entry.mount_id != candidate.mount_id
                    && entry.parent_id == candidate.mount_id
                    && entry.mount_point == candidate.mount_point
            })
            .count()
            > 1
    }) {
        return None;
    }
    for entry in entries {
        let mut seen = BTreeSet::new();
        let mut cursor = entry;
        loop {
            if cursor.mount_id == cursor.parent_id && cursor.mount_point == b"/" {
                break;
            }
            let Some(parent) = by_id.get(&cursor.parent_id) else {
                break;
            };
            if !seen.insert(cursor.mount_id) {
                return None;
            }
            cursor = parent;
        }
    }
    let hidden_at_same_point = entries
        .iter()
        .filter(|candidate| {
            entries.iter().any(|entry| {
                entry.mount_id != candidate.mount_id
                    && entry.parent_id == candidate.mount_id
                    && entry.mount_point == candidate.mount_point
            })
        })
        .map(|entry| entry.mount_id)
        .collect::<BTreeSet<_>>();
    let covered_by_later_ancestor = entries
        .iter()
        .filter(|candidate| {
            entries.iter().any(|cover| {
                cover.parent_id == candidate.parent_id
                    && cover.mount_id > candidate.mount_id
                    && cover.mount_point != candidate.mount_point
                    && linux_path_contains(&cover.mount_point, &candidate.mount_point)
            })
        })
        .map(|entry| entry.mount_id)
        .collect::<BTreeSet<_>>();
    let mut visible = Vec::new();
    for entry in entries {
        if hidden_at_same_point.contains(&entry.mount_id) || covered_by_later_ancestor.contains(&entry.mount_id) {
            continue;
        }
        let mut cursor = entry;
        let mut hidden = false;
        loop {
            if cursor.mount_id == cursor.parent_id && cursor.mount_point == b"/" {
                break;
            }
            let Some(parent) = by_id.get(&cursor.parent_id) else {
                break;
            };
            if parent.mount_point != cursor.mount_point
                && (hidden_at_same_point.contains(&parent.mount_id)
                    || covered_by_later_ancestor.contains(&parent.mount_id))
            {
                hidden = true;
                break;
            }
            cursor = parent;
        }
        if !hidden {
            visible.push(entry.clone());
        }
    }
    visible.sort_by_key(|entry| entry.mount_id);
    Some(visible)
}

fn selected_mount<'a>(path: &[u8], entries: &'a [MountEntry]) -> Option<&'a MountEntry> {
    let mut matches = entries
        .iter()
        .filter(|entry| linux_path_contains(&entry.mount_point, path));
    let first = matches.next()?;
    matches.try_fold(first, |selected, entry| {
        if entry.mount_point.len() > selected.mount_point.len() {
            Some(entry)
        } else if entry.mount_point.len() == selected.mount_point.len() {
            None
        } else {
            Some(selected)
        }
    })
}

fn physical_identity(path: &[u8], entries: &[MountEntry]) -> Option<PhysicalIdentity> {
    let mount = selected_mount(path, entries)?;
    let relative = if mount.mount_point == b"/" {
        path.strip_prefix(b"/")?
    } else {
        path.strip_prefix(mount.mount_point.as_slice())?
            .strip_prefix(b"/")
            .unwrap_or_default()
    };
    let physical_path = if relative.is_empty() {
        mount.root.clone()
    } else {
        let mut joined = mount.root.clone();
        if joined != b"/" {
            joined.push(b'/');
        }
        joined.extend_from_slice(relative);
        joined
    };
    Some(PhysicalIdentity {
        device: mount.device.clone(),
        path: physical_path,
    })
}

fn read_mount_snapshot() -> Result<MountSnapshot, LinuxBootstrapError> {
    #[cfg(target_os = "linux")]
    {
        const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
        let mut raw = Vec::new();
        File::open("/proc/self/mountinfo")
            .map(|file| file.take(MAX_MOUNTINFO_BYTES + 1))
            .and_then(|mut file| file.read_to_end(&mut raw))
            .map_err(|_| LinuxBootstrapError::InvalidRequest("mount topology"))?;
        if raw.len() as u64 > MAX_MOUNTINFO_BYTES {
            return Err(LinuxBootstrapError::InvalidRequest("mount topology"));
        }
        let entries = parse_mountinfo(&raw).ok_or(LinuxBootstrapError::InvalidRequest("mount topology"))?;
        Ok(MountSnapshot { entries })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(MountSnapshot { entries: Vec::new() })
    }
}

fn relevant_mount(entry: &MountEntry) -> RelevantMount {
    RelevantMount {
        mount_id: entry.mount_id,
        parent_id: entry.parent_id,
        device: entry.device.clone(),
        root: entry.root.clone(),
        mount_point: entry.mount_point.clone(),
        read_only: entry.read_only,
    }
}

fn derive_mount_evidence(
    roots: [&str; 3],
    entrypoints: [&str; 2],
    mount_snapshot: &MountSnapshot,
) -> Result<MountEvidence, LinuxBootstrapError> {
    if mount_snapshot.entries.is_empty() {
        return Ok(MountEvidence {
            selected: Vec::new(),
            store_control_mounts: Vec::new(),
        });
    }
    let visible =
        visible_mounts(&mount_snapshot.entries).ok_or(LinuxBootstrapError::InvalidRequest("mount topology"))?;
    let identities = roots
        .map(|root| physical_identity(root.as_bytes(), &visible))
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(LinuxBootstrapError::InvalidRequest("mount topology"))?;
    if roots[..2]
        .iter()
        .any(|root| selected_mount(root.as_bytes(), &visible).map_or(true, |entry| entry.read_only))
    {
        return Err(LinuxBootstrapError::InvalidRequest("read-only destination"));
    }
    for left in 0..identities.len() {
        for right in (left + 1)..identities.len() {
            if identities[left].device == identities[right].device
                && (linux_path_contains(&identities[left].path, &identities[right].path)
                    || linux_path_contains(&identities[right].path, &identities[left].path))
            {
                return Err(LinuxBootstrapError::InvalidRequest("runtime/storage root overlap"));
            }
        }
    }
    let store = roots[0].as_bytes();
    let mut store_control_mounts = Vec::new();
    for entry in &visible {
        if entry.mount_point != store && linux_path_contains(store, &entry.mount_point) {
            let relative = entry.mount_point[store.len()..].strip_prefix(b"/").unwrap_or_default();
            if [
                b"objects".as_slice(),
                b"manifests",
                b"refs",
                BOOTSTRAP_STAGING_PARENT.as_bytes(),
            ]
            .iter()
            .any(|control| relative == *control || linux_path_contains(control, relative))
            {
                store_control_mounts.push(relevant_mount(entry));
            }
        }
    }
    if !store_control_mounts.is_empty() {
        return Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"));
    }
    let mut selected = roots
        .iter()
        .chain(entrypoints.iter())
        .map(|path| selected_mount(path.as_bytes(), &visible).map(relevant_mount))
        .collect::<Option<Vec<_>>>()
        .ok_or(LinuxBootstrapError::InvalidRequest("mount topology"))?;
    if selected.iter().any(|entry| entry.root.ends_with(b"//deleted")) {
        return Err(LinuxBootstrapError::InvalidRequest("mount topology"));
    }
    selected.sort_by_key(|entry| entry.mount_id);
    selected.dedup();
    store_control_mounts.sort_by_key(|entry| entry.mount_id);
    Ok(MountEvidence {
        selected,
        store_control_mounts,
    })
}

fn inspect_bootstrap_entrypoint(
    materialized_root: &Path,
    relative: &str,
) -> Result<(VerifiedEntrypoint, PathBuf), LinuxBootstrapError> {
    validate_linux_relative_path("entrypoint", relative).map_err(LinuxBootstrapError::Contract)?;
    let candidate = relative
        .split('/')
        .fold(materialized_root.to_path_buf(), |path, component| path.join(component));
    let canonical =
        fs::canonicalize(candidate).map_err(|_| LinuxBootstrapError::Evidence(EvidenceFailure::Entrypoint))?;
    if !canonical.starts_with(materialized_root)
        || !canonical
            .metadata()
            .map_err(|_| LinuxBootstrapError::Evidence(EvidenceFailure::Entrypoint))?
            .is_file()
    {
        return Err(LinuxBootstrapError::Evidence(EvidenceFailure::Entrypoint));
    }
    let entrypoint = VerifiedEntrypoint {
        path: relative.into(),
        digest: sha256_file(&canonical).map_err(LinuxBootstrapError::Evidence)?,
    };
    let verified = verify_entrypoint(materialized_root, &entrypoint).map_err(LinuxBootstrapError::Evidence)?;
    if verified != canonical {
        return Err(LinuxBootstrapError::Evidence(EvidenceFailure::Entrypoint));
    }
    Ok((entrypoint, canonical))
}

fn create_private_directory_tree(
    path: &Path,
    field: &'static str,
    owner: OwnerIdentity,
) -> Result<(), LinuxBootstrapError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_private_directory(path, field, owner),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(LinuxBootstrapError::InvalidRequest(field)),
    }

    let mut cursor = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(LinuxBootstrapError::InvalidRequest(field));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                cursor = cursor
                    .parent()
                    .ok_or(LinuxBootstrapError::InvalidRequest(field))?
                    .to_path_buf();
            }
            Err(_) => return Err(LinuxBootstrapError::InvalidRequest(field)),
        }
    }
    for directory in missing.into_iter().rev() {
        match create_new_private_directory(&directory) {
            Ok(()) => validate_new_private_directory(&directory, field, owner)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                validate_private_directory(&directory, field, owner)?
            }
            Err(_) => return Err(LinuxBootstrapError::RegistrationFailed("private directory create")),
        }
    }
    validate_private_directory(path, field, owner)
}

fn create_new_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn validate_new_private_directory(
    path: &Path,
    field: &'static str,
    owner: OwnerIdentity,
) -> Result<(), LinuxBootstrapError> {
    validate_exact_private_directory(path, field, owner)
}

fn validate_exact_private_directory(
    path: &Path,
    field: &'static str,
    owner: OwnerIdentity,
) -> Result<(), LinuxBootstrapError> {
    validate_private_directory(path, field, owner)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mode = fs::symlink_metadata(path)
            .map_err(|_| LinuxBootstrapError::InvalidRequest(field))?
            .mode()
            & 0o777;
        if mode != 0o700 {
            return Err(LinuxBootstrapError::InvalidRequest(field));
        }
    }
    Ok(())
}

fn copy_to_new_private_file(
    source: &Path,
    destination: &Path,
    operation: &'static str,
) -> Result<(), LinuxBootstrapError> {
    let mut input = File::open(source).map_err(|_| LinuxBootstrapError::RegistrationFailed(operation))?;
    let mut output = new_private_file(destination).map_err(|_| LinuxBootstrapError::RegistrationFailed(operation))?;
    let result = io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|_| LinuxBootstrapError::RegistrationFailed(operation));
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn write_new_private_file(
    destination: &Path,
    contents: &[u8],
    operation: &'static str,
) -> Result<(), LinuxBootstrapError> {
    let mut output = new_private_file(destination).map_err(|_| LinuxBootstrapError::RegistrationFailed(operation))?;
    let result = output
        .write_all(contents)
        .and_then(|()| output.sync_all())
        .map_err(|_| LinuxBootstrapError::RegistrationFailed(operation));
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn new_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    options.open(path)
}

fn remove_owned_staging_directory(staging: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
    let name = staging
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.starts_with(BOOTSTRAP_STAGING_PREFIX))
        .ok_or(LinuxBootstrapError::RegistrationFailed("staging cleanup"))?;
    let _ = name;
    let metadata =
        fs::symlink_metadata(staging).map_err(|_| LinuxBootstrapError::RegistrationFailed("staging cleanup"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LinuxBootstrapError::RegistrationFailed("staging cleanup"));
    }
    let canonical =
        fs::canonicalize(staging).map_err(|_| LinuxBootstrapError::RegistrationFailed("staging cleanup"))?;
    let requested_parent = staging
        .parent()
        .ok_or(LinuxBootstrapError::RegistrationFailed("staging cleanup"))?;
    if requested_parent.file_name().and_then(|name| name.to_str()) != Some(BOOTSTRAP_STAGING_PARENT) {
        return Err(LinuxBootstrapError::RegistrationFailed("staging cleanup"));
    }
    let parent =
        fs::canonicalize(requested_parent).map_err(|_| LinuxBootstrapError::RegistrationFailed("staging cleanup"))?;
    let canonical_parent = canonical
        .parent()
        .ok_or(LinuxBootstrapError::RegistrationFailed("staging cleanup"))?;
    validate_exact_private_directory(&parent, "runtimeStoreRoot", owner)?;
    if canonical_parent != parent || canonical.file_name() != staging.file_name() {
        return Err(LinuxBootstrapError::RegistrationFailed("staging cleanup"));
    }
    fs::remove_dir_all(&canonical).map_err(|_| LinuxBootstrapError::RegistrationFailed("staging cleanup"))
}

fn random_staging_token() -> Result<String, LinuxBootstrapError> {
    use std::fmt::Write as _;

    let mut entropy = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut entropy))
        .map_err(|_| LinuxBootstrapError::RegistrationFailed("staging entropy"))?;
    let mut token = String::with_capacity(entropy.len() * 2);
    for byte in entropy {
        write!(&mut token, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::{
        CapabilityReport, CpuArchitecture, ExecutableMode, ExecutableRequest, GraphicsBackendKind, HostDescriptor,
        HostOs, LaunchConstraints, LaunchRequest, NetworkPolicy, ProviderDescriptor, RuntimeChannel, RuntimeComponent,
        RuntimeHost, RuntimeKind, RuntimePackManifest, SandboxProfile, SupervisorPolicy, TranslatorKind,
        SCHEMA_VERSION_V1,
    };
    use compatforge_orchestrator::PolicyEngine;
    use compatforge_runtime::{sha256_digest_bytes, RejectAllSignatures, RuntimePackStore};
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    type VerificationCase = (PathBuf, VerifiedEntrypoint);

    struct EntryFixture {
        base: PathBuf,
        root: PathBuf,
    }

    impl EntryFixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir().join(format!(
                "compatforge-linux-entrypoint-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&base).expect("create unique entrypoint fixture root");
            let fixture = Self {
                root: base.join("runtime"),
                base,
            };
            fixture.write_entry("bin/wine", &test_elf64_x86_64(2));
            fixture
        }

        fn write_entry(&self, relative_path: &str, contents: &[u8]) -> VerifiedEntrypoint {
            let path = self.root.join(relative_path);
            fs::create_dir_all(path.parent().expect("entrypoint parent")).expect("create entrypoint parent");
            fs::write(&path, contents).expect("write entrypoint fixture");
            set_executable(&path);
            VerifiedEntrypoint {
                path: relative_path.to_owned(),
                digest: digest_file(&path),
            }
        }

        fn verified(&self, relative_path: &str) -> VerifiedEntrypoint {
            VerifiedEntrypoint {
                path: relative_path.to_owned(),
                digest: digest_file(&self.root.join(relative_path)),
            }
        }

        fn case(&self, entrypoint: VerifiedEntrypoint) -> VerificationCase {
            (self.root.clone(), entrypoint)
        }

        fn digest_mismatch(&self) -> VerificationCase {
            let mut entrypoint = self.verified("bin/wine");
            entrypoint.digest = format!("sha256:{}", "0".repeat(64));
            self.case(entrypoint)
        }

        fn directory_entry(&self) -> VerificationCase {
            fs::create_dir_all(self.root.join("bin/directory")).expect("create directory entrypoint");
            self.case(VerifiedEntrypoint {
                path: "bin/directory".to_owned(),
                digest: format!("sha256:{}", "0".repeat(64)),
            })
        }

        fn non_elf_entry(&self) -> VerificationCase {
            let entrypoint = self.write_entry("bin/not-elf", &[b'x'; 64]);
            self.case(entrypoint)
        }

        fn truncated_entry(&self) -> VerificationCase {
            let entrypoint = self.write_entry("bin/truncated", b"\x7fELF");
            self.case(entrypoint)
        }
    }

    impl Drop for EntryFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.base).expect("remove entrypoint fixture root");
        }
    }

    fn test_elf64_x86_64(object_type: u16) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&object_type.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes
    }

    fn digest_file(path: &Path) -> String {
        let contents = fs::read(path).expect("read entrypoint fixture for digest");
        format!("sha256:{:x}", Sha256::digest(contents))
    }

    #[cfg(unix)]
    fn set_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).expect("entrypoint metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("set entrypoint executable permissions");
    }

    #[cfg(not(unix))]
    fn set_executable(_path: &Path) {}

    fn assert_rejected((root, entrypoint): VerificationCase) {
        assert!(verify_entrypoint(&root, &entrypoint).is_err());
    }

    fn valid_config_json() -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": "1",
            "runtimeStoreRoot": "/runtime-store",
            "wineRuntime": {
                "providerId": "linux-wine",
                "packId": "wine-linux-x86_64",
                "packDigest": format!("sha256:{}", "a".repeat(64)),
                "version": "9.0",
                "architecture": "x86_64",
                "materializedRoot": "/runtime",
                "wine": {
                    "path": "bin/wine",
                    "digest": format!("sha256:{}", "b".repeat(64)),
                },
                "wineserver": {
                    "path": "bin/wineserver",
                    "digest": format!("sha256:{}", "c".repeat(64)),
                },
                "capabilities": ["guest-x86_64"],
                "wined3dCapabilities": ["opengl"],
            },
        })
    }

    fn valid_request_json() -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": "1",
            "runtimeStoreRoot": "/runtime-store",
            "storageRoot": "/storage",
            "materializedRoot": "/runtime",
            "wine": "bin/wine",
            "wineserver": "bin/wineserver",
            "version": "9.0",
        })
    }

    fn assert_config_error(value: serde_json::Value, expected: LinuxProviderError) {
        let config: LinuxProviderConfig = serde_json::from_value(value).unwrap();
        assert_eq!(config.validate(), Err(expected));
    }

    fn assert_request_error(value: serde_json::Value, expected: LinuxProviderError) {
        let request: LinuxLocalContextRequest = serde_json::from_value(value).unwrap();
        assert_eq!(request.validate(), Err(expected));
    }

    struct DirectoryFixture {
        root: PathBuf,
    }

    impl DirectoryFixture {
        fn new(label: &str) -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "compatforge-linux-provider-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create unique Provider fixture root");
            Self { root }
        }
    }

    impl Drop for DirectoryFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("remove Provider fixture root");
        }
    }

    fn valid_config() -> LinuxProviderConfig {
        serde_json::from_value(valid_config_json()).expect("valid Linux Provider configuration")
    }

    fn linux_host_report() -> CapabilityReport {
        CapabilityReport {
            schema_version: SCHEMA_VERSION_V1.into(),
            host: HostDescriptor {
                os: HostOs::Linux,
                os_version: "test".into(),
                architecture: CpuArchitecture::X86_64,
                kernel: None,
                device_model: None,
            },
            runtime_providers: vec![ProviderDescriptor {
                id: "unrelated-runtime".into(),
                kind: "remote".into(),
                version: "unrelated".into(),
                available: true,
                reason: None,
                capabilities: vec!["guest-x86_64".into()],
            }],
            translators: vec![ProviderDescriptor {
                id: "unrelated-translator".into(),
                kind: "qemu".into(),
                version: "unrelated".into(),
                available: true,
                reason: None,
                capabilities: vec!["x86_64-on-arm64".into()],
            }],
            graphics_backends: vec![ProviderDescriptor {
                id: "unrelated-graphics".into(),
                kind: "dxvk".into(),
                version: "unrelated".into(),
                available: true,
                reason: None,
                capabilities: vec!["vulkan".into()],
            }],
            observations: Vec::new(),
            features: BTreeMap::new(),
        }
    }

    fn matching_manifest(runtime: &WineRuntimeConfig) -> RuntimePackManifest {
        let mut manifest = RuntimePackManifest {
            schema_version: SCHEMA_VERSION_V1.into(),
            id: runtime.pack_id.clone(),
            version: runtime.version.clone(),
            channel: Some(RuntimeChannel::Preview),
            host: RuntimeHost {
                os: HostOs::Linux,
                architecture: CpuArchitecture::X86_64,
                minimum_version: None,
            },
            components: vec![
                RuntimeComponent {
                    name: "wine-entrypoint".into(),
                    version: runtime.version.clone(),
                    license: "LGPL-2.1-or-later".into(),
                    source: None,
                    artifact: Some("components/wine-entrypoint.bin".into()),
                    digest: runtime.wine.digest.clone(),
                    entrypoints: BTreeMap::from([("wine".into(), runtime.wine.path.clone())]),
                },
                RuntimeComponent {
                    name: "wineserver-entrypoint".into(),
                    version: runtime.version.clone(),
                    license: "LGPL-2.1-or-later".into(),
                    source: None,
                    artifact: Some("components/wineserver-entrypoint.bin".into()),
                    digest: runtime.wineserver.digest.clone(),
                    entrypoints: BTreeMap::from([("wineserver".into(), runtime.wineserver.path.clone())]),
                },
            ],
            capabilities: vec![RUNTIME_CAPABILITY.into()],
            digest: format!("sha256:{}", "0".repeat(64)),
            signature: None,
            sbom: None,
        };
        resign_manifest(&mut manifest);
        manifest
    }

    fn resign_manifest(manifest: &mut RuntimePackManifest) {
        manifest.digest = sha256_digest_bytes(
            &manifest
                .canonical_unsigned_bytes()
                .expect("serialize canonical Runtime Pack manifest"),
        );
    }

    fn matching_config_and_manifest() -> (LinuxProviderConfig, RuntimePackManifest) {
        let mut config = valid_config();
        let manifest = matching_manifest(&config.wine_runtime);
        config.wine_runtime.pack_digest = manifest.digest.clone();
        (config, manifest)
    }

    fn resign_for_config(config: &mut LinuxProviderConfig, manifest: &mut RuntimePackManifest) {
        resign_manifest(manifest);
        config.wine_runtime.pack_digest = manifest.digest.clone();
    }

    fn component_mut<'a>(manifest: &'a mut RuntimePackManifest, name: &str) -> &'a mut RuntimeComponent {
        manifest
            .components
            .iter_mut()
            .find(|component| component.name == name)
            .expect("named fixture component")
    }

    #[test]
    fn unrelated_verified_pack_cannot_authorize_external_entrypoints() {
        let (mut config, mut manifest) = matching_config_and_manifest();
        assert_eq!(associate_verified_manifest(&config.wine_runtime, &manifest), Ok(()));
        component_mut(&mut manifest, "wine-entrypoint").digest = format!("sha256:{}", "d".repeat(64));
        resign_for_config(&mut config, &mut manifest);

        assert!(associate_verified_manifest(&config.wine_runtime, &manifest).is_err());
    }

    #[derive(Debug, Clone, Copy)]
    enum ManifestMutation {
        Id,
        Version,
        HostOs,
        HostArchitecture,
        HostMinimumVersion,
        CapabilityMissing,
        CapabilityContent,
        CapabilityDuplicate,
        CapabilityExtraAfter,
        CapabilityExtraBefore,
        MissingComponent,
        ExtraComponent,
        WineComponentName,
        WineserverComponentName,
        WineComponentVersion,
        WineserverComponentVersion,
        WineObjectDigest,
        WineserverObjectDigest,
        WineEntrypointKey,
        WineserverEntrypointKey,
        WineEntrypointMissing,
        WineserverEntrypointMissing,
        WineEntrypointPath,
        WineserverEntrypointPath,
        WineExtraEntrypoint,
        WineserverExtraEntrypoint,
    }

    #[test]
    fn pack_association_rejects_every_manifest_mutation() {
        let mutations = [
            ManifestMutation::Id,
            ManifestMutation::Version,
            ManifestMutation::HostOs,
            ManifestMutation::HostArchitecture,
            ManifestMutation::HostMinimumVersion,
            ManifestMutation::CapabilityMissing,
            ManifestMutation::CapabilityContent,
            ManifestMutation::CapabilityDuplicate,
            ManifestMutation::CapabilityExtraAfter,
            ManifestMutation::CapabilityExtraBefore,
            ManifestMutation::MissingComponent,
            ManifestMutation::ExtraComponent,
            ManifestMutation::WineComponentName,
            ManifestMutation::WineserverComponentName,
            ManifestMutation::WineComponentVersion,
            ManifestMutation::WineserverComponentVersion,
            ManifestMutation::WineObjectDigest,
            ManifestMutation::WineserverObjectDigest,
            ManifestMutation::WineEntrypointKey,
            ManifestMutation::WineserverEntrypointKey,
            ManifestMutation::WineEntrypointMissing,
            ManifestMutation::WineserverEntrypointMissing,
            ManifestMutation::WineEntrypointPath,
            ManifestMutation::WineserverEntrypointPath,
            ManifestMutation::WineExtraEntrypoint,
            ManifestMutation::WineserverExtraEntrypoint,
        ];

        let (config, manifest) = matching_config_and_manifest();
        assert_eq!(associate_verified_manifest(&config.wine_runtime, &manifest), Ok(()));

        for mutation in mutations {
            let (mut config, mut manifest) = matching_config_and_manifest();
            match mutation {
                ManifestMutation::Id => manifest.id = "other-linux-pack".into(),
                ManifestMutation::Version => manifest.version = "10.0".into(),
                ManifestMutation::HostOs => manifest.host.os = HostOs::MacOs,
                ManifestMutation::HostArchitecture => manifest.host.architecture = CpuArchitecture::Arm64,
                ManifestMutation::HostMinimumVersion => manifest.host.minimum_version = Some("6.0".into()),
                ManifestMutation::CapabilityMissing => manifest.capabilities.clear(),
                ManifestMutation::CapabilityContent => manifest.capabilities = vec!["guest-arm64".into()],
                ManifestMutation::CapabilityDuplicate => {
                    manifest.capabilities = vec![RUNTIME_CAPABILITY.into(), RUNTIME_CAPABILITY.into()]
                }
                ManifestMutation::CapabilityExtraAfter => {
                    manifest.capabilities = vec![RUNTIME_CAPABILITY.into(), "guest-arm64".into()]
                }
                ManifestMutation::CapabilityExtraBefore => {
                    manifest.capabilities = vec!["guest-arm64".into(), RUNTIME_CAPABILITY.into()]
                }
                ManifestMutation::MissingComponent => {
                    manifest.components.pop();
                }
                ManifestMutation::ExtraComponent => {
                    let mut extra = manifest.components[0].clone();
                    extra.name = "extra-entrypoint".into();
                    extra.entrypoints = BTreeMap::from([("extra".into(), "bin/extra".into())]);
                    manifest.components.push(extra);
                }
                ManifestMutation::WineComponentName => {
                    component_mut(&mut manifest, "wine-entrypoint").name = "other-wine-entrypoint".into()
                }
                ManifestMutation::WineserverComponentName => {
                    component_mut(&mut manifest, "wineserver-entrypoint").name = "other-wineserver-entrypoint".into()
                }
                ManifestMutation::WineComponentVersion => {
                    component_mut(&mut manifest, "wine-entrypoint").version = "10.0".into()
                }
                ManifestMutation::WineserverComponentVersion => {
                    component_mut(&mut manifest, "wineserver-entrypoint").version = "10.0".into()
                }
                ManifestMutation::WineObjectDigest => {
                    component_mut(&mut manifest, "wine-entrypoint").digest = format!("sha256:{}", "d".repeat(64))
                }
                ManifestMutation::WineserverObjectDigest => {
                    component_mut(&mut manifest, "wineserver-entrypoint").digest = format!("sha256:{}", "e".repeat(64))
                }
                ManifestMutation::WineEntrypointKey => {
                    component_mut(&mut manifest, "wine-entrypoint").entrypoints =
                        BTreeMap::from([("other-wine".into(), config.wine_runtime.wine.path.clone())])
                }
                ManifestMutation::WineserverEntrypointKey => {
                    component_mut(&mut manifest, "wineserver-entrypoint").entrypoints =
                        BTreeMap::from([("other-wineserver".into(), config.wine_runtime.wineserver.path.clone())])
                }
                ManifestMutation::WineEntrypointMissing => {
                    component_mut(&mut manifest, "wine-entrypoint").entrypoints.clear()
                }
                ManifestMutation::WineserverEntrypointMissing => component_mut(&mut manifest, "wineserver-entrypoint")
                    .entrypoints
                    .clear(),
                ManifestMutation::WineEntrypointPath => {
                    component_mut(&mut manifest, "wine-entrypoint").entrypoints =
                        BTreeMap::from([("wine".into(), "bin/other-wine".into())])
                }
                ManifestMutation::WineserverEntrypointPath => {
                    component_mut(&mut manifest, "wineserver-entrypoint").entrypoints =
                        BTreeMap::from([("wineserver".into(), "bin/other-wineserver".into())])
                }
                ManifestMutation::WineExtraEntrypoint => {
                    component_mut(&mut manifest, "wine-entrypoint")
                        .entrypoints
                        .insert("extra-wine".into(), "bin/extra-wine".into());
                }
                ManifestMutation::WineserverExtraEntrypoint => {
                    component_mut(&mut manifest, "wineserver-entrypoint")
                        .entrypoints
                        .insert("extra-wineserver".into(), "bin/extra-wineserver".into());
                }
            }
            resign_for_config(&mut config, &mut manifest);
            assert!(
                associate_verified_manifest(&config.wine_runtime, &manifest).is_err(),
                "mutation {mutation:?} bypassed exact Pack association"
            );
        }
    }

    fn bundle_for_bytes(
        parent: &Path,
        label: &str,
        store_root: &Path,
        wine_bytes: &[u8],
        wineserver_bytes: &[u8],
    ) -> (PathBuf, LinuxProviderConfig, RuntimePackManifest) {
        let bundle = parent.join(label);
        fs::create_dir_all(bundle.join("components")).expect("create Runtime Pack bundle components");
        fs::write(bundle.join("components/wine-entrypoint.bin"), wine_bytes).expect("write Wine Pack object");
        fs::write(bundle.join("components/wineserver-entrypoint.bin"), wineserver_bytes)
            .expect("write Wineserver Pack object");
        let mut config = valid_config();
        config.runtime_store_root = store_root.to_string_lossy().into_owned();
        config.wine_runtime.wine.digest = sha256_digest_bytes(wine_bytes);
        config.wine_runtime.wineserver.digest = sha256_digest_bytes(wineserver_bytes);
        let manifest = matching_manifest(&config.wine_runtime);
        config.wine_runtime.pack_digest = manifest.digest.clone();
        (bundle, config, manifest)
    }

    #[test]
    fn configured_digest_ignores_a_different_active_ref() {
        let fixture = DirectoryFixture::new("active-ref");
        let store_root = fixture.root.join("store");
        let store = RuntimePackStore::new(&store_root);
        let (first_bundle, first_config, first_manifest) =
            bundle_for_bytes(&fixture.root, "first", &store_root, b"first-wine", b"first-wineserver");
        store
            .install(&first_bundle, &first_manifest, &RejectAllSignatures)
            .expect("install explicitly configured Pack");
        let (second_bundle, _second_config, second_manifest) = bundle_for_bytes(
            &fixture.root,
            "second",
            &store_root,
            b"second-wine",
            b"second-wineserver",
        );
        store
            .install(&second_bundle, &second_manifest, &RejectAllSignatures)
            .expect("install and activate different Pack digest");
        assert_eq!(
            store.active_digest(&first_config.wine_runtime.pack_id).unwrap(),
            Some(second_manifest.digest)
        );

        let manifest = load_associated_manifest(&store, &first_config.wine_runtime)
            .expect("load only explicitly configured Pack digest");
        assert_eq!(manifest.digest, first_manifest.digest);
    }

    fn successful_bound_evidence(config: &LinuxProviderConfig) -> BoundProviderEvidence {
        BoundProviderEvidence {
            observation: RuntimeProbeObservation {
                wine: PathBuf::from("/private/provider-runtime/bin/wine"),
                wineserver: PathBuf::from("/private/provider-runtime/bin/wineserver"),
                version: config.wine_runtime.version.clone(),
            },
            protected_roots: ProtectedRuntimeRoots {
                runtime_store: PathBuf::from("/private/provider-store"),
                materialized_runtime: PathBuf::from("/private/provider-runtime"),
            },
        }
    }

    struct PanicProbeCommand;

    impl ProbeCommand for PanicProbeCommand {
        fn run(&self, _specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
            panic!("Provider validation must finish before any command is attempted")
        }
    }

    #[test]
    fn provider_failure_semantics_are_closed_and_path_redacted() {
        let host = linux_host_report();
        let mut config = valid_config();
        config.runtime_store_root = "/private/PROVIDER_PATH_MUST_NOT_ESCAPE-store".into();
        config.wine_runtime.materialized_root = "/private/PROVIDER_PATH_MUST_NOT_ESCAPE-runtime".into();

        let mut malformed = config.clone();
        malformed.wine_runtime.pack_id = "!invalid".into();
        let error = build_provider_snapshot(&host, &malformed, Ok(successful_bound_evidence(&malformed)))
            .expect_err("malformed configuration must be an error");
        assert!(!error.to_string().contains("PROVIDER_PATH_MUST_NOT_ESCAPE"));
        assert!(LinuxProviderSet::probe_with(&host, &malformed, &PanicProbeCommand).is_err());

        for (os, architecture) in [
            (HostOs::Windows, CpuArchitecture::X86_64),
            (HostOs::Linux, CpuArchitecture::Arm64),
        ] {
            let mut unsupported = host.clone();
            unsupported.host.os = os;
            unsupported.host.architecture = architecture;
            assert_eq!(
                build_provider_snapshot(&unsupported, &config, Ok(successful_bound_evidence(&config))),
                Err(LinuxProviderError::UnsupportedHost)
            );
            assert_eq!(
                LinuxProviderSet::probe_with(&unsupported, &config, &PanicProbeCommand),
                Err(LinuxProviderError::UnsupportedHost)
            );
        }

        let failures = [
            ("missing Store object", EvidenceFailure::RuntimePack),
            ("mutated Store object", EvidenceFailure::RuntimePack),
            ("missing entrypoint", EvidenceFailure::Entrypoint),
            ("mutated entrypoint", EvidenceFailure::Digest),
            ("invalid ELF", EvidenceFailure::Elf),
            ("wrong architecture", EvidenceFailure::Architecture),
            ("missing execute permission", EvidenceFailure::Entrypoint),
            ("command failure", EvidenceFailure::Command),
            ("version failure", EvidenceFailure::Version),
        ];
        for (case, failure) in failures {
            let snapshot = build_provider_snapshot(&host, &config, Err(failure))
                .unwrap_or_else(|error| panic!("{case} must yield an unavailable report, got {error}"));
            assert!(snapshot.runtime_binding.is_none(), "{case}");
            assert_eq!(snapshot.capabilities.runtime_providers.len(), 1, "{case}");
            assert!(!snapshot.capabilities.runtime_providers[0].available, "{case}");
            assert_eq!(
                snapshot.capabilities.runtime_providers[0].reason.as_deref(),
                Some(failure.to_string().as_str()),
                "{case}"
            );
            assert_eq!(snapshot.capabilities.graphics_backends.len(), 1, "{case}");
            assert!(!snapshot.capabilities.graphics_backends[0].available, "{case}");
            assert!(snapshot.capabilities.translators[0].available, "{case}");
            let public = serde_json::to_string(&snapshot.capabilities).unwrap();
            assert!(!public.contains("PROVIDER_PATH_MUST_NOT_ESCAPE"), "{case}");
            assert!(!public.contains("/private/"), "{case}");
        }

        let mut wrong_version = successful_bound_evidence(&config);
        wrong_version.observation.version = "10.0".into();
        let snapshot = build_provider_snapshot(&host, &config, Ok(wrong_version)).unwrap();
        assert!(snapshot.runtime_binding.is_none());
        assert_eq!(
            snapshot.capabilities.runtime_providers[0].reason.as_deref(),
            Some(EvidenceFailure::Version.to_string().as_str())
        );
    }

    #[test]
    fn provider_rejects_non_serializable_observation_paths_without_binding() {
        let host = linux_host_report();
        let config = valid_config();
        for field in ["wine", "wineserver"] {
            let mut evidence = successful_bound_evidence(&config);
            let invalid = PathBuf::from("/private/provider-runtime/bin/bad\\entrypoint");
            if field == "wine" {
                evidence.observation.wine = invalid;
            } else {
                evidence.observation.wineserver = invalid;
            }

            let snapshot = build_provider_snapshot(&host, &config, Ok(evidence))
                .expect("invalid observed path must yield an unavailable Provider");
            assert!(snapshot.runtime_binding.is_none(), "{field}");
            assert!(!snapshot.capabilities.runtime_providers[0].available, "{field}");
            assert_eq!(
                snapshot.capabilities.runtime_providers[0].reason.as_deref(),
                Some(EvidenceFailure::Entrypoint.to_string().as_str()),
                "{field}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_rejects_non_utf8_observation_paths_without_binding() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let host = linux_host_report();
        let config = valid_config();
        for field in ["wine", "wineserver"] {
            let mut evidence = successful_bound_evidence(&config);
            let invalid = PathBuf::from(OsString::from_vec(b"/private/runtime/non-utf8-\xff".to_vec()));
            if field == "wine" {
                evidence.observation.wine = invalid;
            } else {
                evidence.observation.wineserver = invalid;
            }

            let snapshot = build_provider_snapshot(&host, &config, Ok(evidence))
                .expect("non-UTF-8 observed path must yield an unavailable Provider");
            assert!(snapshot.runtime_binding.is_none(), "{field}");
            assert!(!snapshot.capabilities.runtime_providers[0].available, "{field}");
        }
    }

    #[test]
    fn provider_preserves_non_evidence_probe_errors() {
        assert_eq!(
            classify_probe_error(LinuxProviderError::Evidence(EvidenceFailure::Command)),
            Ok(EvidenceFailure::Command)
        );
        assert_eq!(
            classify_probe_error(LinuxProviderError::UnsupportedHost),
            Err(LinuxProviderError::UnsupportedHost)
        );
        assert_eq!(
            classify_probe_error(LinuxProviderError::InvalidConfig("wineRuntime.version")),
            Err(LinuxProviderError::InvalidConfig("wineRuntime.version"))
        );
    }

    #[test]
    fn reserved_descriptor_ids_fail_before_provider_evidence() {
        let host = linux_host_report();
        for provider_id in [NATIVE_PROVIDER_ID, WINED3D_PROVIDER_ID] {
            let mut config = valid_config();
            config.wine_runtime.provider_id = provider_id.into();
            assert_eq!(
                config.validate(),
                Err(LinuxProviderError::InvalidConfig("wineRuntime.providerId"))
            );
            assert_eq!(
                LinuxProviderSet::probe_with(&host, &config, &PanicProbeCommand),
                Err(LinuxProviderError::InvalidConfig("wineRuntime.providerId"))
            );
            assert_eq!(
                build_provider_snapshot(&host, &config, Err(EvidenceFailure::Command)),
                Err(LinuxProviderError::InvalidConfig("wineRuntime.providerId")),
                "an evidence failure must not be replaced by a duplicate Provider ID contract error"
            );
        }
    }

    fn successful_snapshot() -> (LinuxProviderConfig, LinuxProviderSnapshot) {
        let config = valid_config();
        let snapshot = build_provider_snapshot(&linux_host_report(), &config, Ok(successful_bound_evidence(&config)))
            .expect("build successful injected Provider snapshot");
        (config, snapshot)
    }

    #[test]
    fn planning_descriptors_are_exact_and_preview_limited() {
        let (config, snapshot) = successful_snapshot();
        assert_eq!(
            snapshot.capabilities.runtime_providers,
            vec![ProviderDescriptor {
                id: config.wine_runtime.provider_id.clone(),
                kind: "wine".into(),
                version: config.wine_runtime.version.clone(),
                available: true,
                reason: None,
                capabilities: vec!["guest-x86_64".into()],
            }]
        );
        assert_eq!(
            snapshot.capabilities.translators,
            vec![ProviderDescriptor {
                id: "native-host".into(),
                kind: "native".into(),
                version: "host".into(),
                available: true,
                reason: None,
                capabilities: vec!["x86_64-on-x86_64".into()],
            }]
        );
        assert_eq!(
            snapshot.capabilities.graphics_backends,
            vec![ProviderDescriptor {
                id: "linux-wined3d".into(),
                kind: "wined3d".into(),
                version: config.wine_runtime.version.clone(),
                available: true,
                reason: None,
                capabilities: vec!["opengl".into()],
            }]
        );
        assert!(snapshot.capabilities.features.is_empty());
        let public = serde_json::to_string(&snapshot.capabilities).unwrap();
        assert!(!public.to_ascii_lowercase().contains("graphicsvalidated"));
        assert!(!public.to_ascii_lowercase().contains("gui"));
    }

    #[test]
    fn provider_planner_compiles_one_exact_wine_native_wined3d_plan() {
        let (config, snapshot) = successful_snapshot();
        let binding = snapshot.runtime_binding.clone().expect("available runtime binding");
        let core = CoreConfig {
            schema_version: SCHEMA_VERSION_V1.into(),
            capabilities: snapshot.capabilities,
            runtime_bindings: vec![binding],
            storage_root: "/private/storage".into(),
            sandbox_profile: SandboxProfile::Desktop,
            supervisor: SupervisorPolicy::default(),
        };
        let request = LaunchRequest {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: "linux-provider-planner".into(),
            bottle_id: "linux-preview".into(),
            recipe_id: None,
            executable: ExecutableRequest {
                path: "C:\\compatforge-console.exe".into(),
                architecture: CpuArchitecture::X86_64,
                mode: ExecutableMode::ImmutableArtifact,
                sha256: None,
            },
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            constraints: LaunchConstraints {
                allow_virtual_machine: false,
                allow_remote: false,
                requires_kernel_driver: false,
                requires_direct_x12: false,
                network_policy: NetworkPolicy::Deny,
                required_capabilities: Vec::new(),
            },
        };
        let plan = PolicyEngine::compile(&core, &request).expect("compile Linux Wine/native/wined3d plan");
        assert_eq!(plan.runtime.provider, RuntimeKind::Wine);
        assert_eq!(plan.runtime.pack_id, config.wine_runtime.pack_id);
        assert_eq!(plan.runtime.pack_digest, config.wine_runtime.pack_digest);
        assert_eq!(plan.translator.provider, TranslatorKind::Native);
        assert_eq!(plan.graphics.backend, GraphicsBackendKind::WineD3d);
        assert_eq!(
            plan.graphics.version.as_deref(),
            Some(config.wine_runtime.version.as_str())
        );
        PolicyEngine::authorize(&core, &plan).expect("authorize exact Linux Provider plan");
    }

    #[test]
    fn runtime_binding_contains_only_fixed_linux_runtime_values() {
        let (config, snapshot) = successful_snapshot();
        let binding = snapshot.runtime_binding.as_ref().expect("available RuntimeBinding");
        assert_eq!(binding.provider_id, config.wine_runtime.provider_id);
        assert_eq!(binding.pack_id, config.wine_runtime.pack_id);
        assert_eq!(binding.pack_digest, config.wine_runtime.pack_digest);
        assert_eq!(binding.executable, "/private/provider-runtime/bin/wine");
        assert_eq!(
            binding.wineserver_executable.as_deref(),
            Some("/private/provider-runtime/bin/wineserver")
        );
        assert_eq!(binding.working_directory, None);
        assert_eq!(
            binding.environment,
            BTreeMap::from([
                ("COMPATFORGE_RUNTIME_PACK".into(), config.wine_runtime.pack_id.clone()),
                (
                    "COMPATFORGE_RUNTIME_PACK_DIGEST".into(),
                    config.wine_runtime.pack_digest.clone(),
                ),
                (
                    "COMPATFORGE_RUNTIME_EXECUTABLE_SHA256".into(),
                    config.wine_runtime.wine.digest.clone(),
                ),
                (
                    "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256".into(),
                    config.wine_runtime.wineserver.digest.clone(),
                ),
                ("WINEDEBUG".into(), "-all".into()),
                ("WINESERVER".into(), "/private/provider-runtime/bin/wineserver".into(),),
                ("WINEARCH".into(), "win64".into()),
                ("WINEDLLOVERRIDES".into(), "mscoree,mshtml=".into()),
            ])
        );
        assert_eq!(
            snapshot.protected_roots.as_ref(),
            Some(&ProtectedRuntimeRoots {
                runtime_store: PathBuf::from("/private/provider-store"),
                materialized_runtime: PathBuf::from("/private/provider-runtime"),
            })
        );
        let protected = snapshot.protected_roots.as_ref().unwrap();
        for overlap in [
            "/private/provider-store",
            "/private/provider-store/storage",
            "/private",
            "/private/provider-runtime",
            "/private/provider-runtime/storage",
        ] {
            assert!(protected.overlaps(Path::new(overlap)), "{overlap}");
        }
        assert!(!protected.overlaps(Path::new("/separate/storage")));
        let public_report = serde_json::to_string(&snapshot.capabilities).unwrap();
        assert!(!public_report.contains("/private/provider-store"));
        assert!(!public_report.contains("/private/provider-runtime"));
        let receipt = LinuxLocalContextReceipt {
            schema_version: SCHEMA_VERSION_V1.into(),
            source: "explicit-override".into(),
            version: config.wine_runtime.version,
            architecture: CpuArchitecture::X86_64,
            pack_id: config.wine_runtime.pack_id,
            pack_digest: config.wine_runtime.pack_digest,
            capabilities: vec![RUNTIME_CAPABILITY.into()],
        };
        let public_receipt = serde_json::to_string(&receipt).unwrap();
        assert!(!public_receipt.contains("/private/provider-store"));
        assert!(!public_receipt.contains("/private/provider-runtime"));
    }

    #[test]
    fn canonical_storage_text_rejects_linux_separator_confusion() {
        assert_eq!(
            validated_canonical_storage_text(Path::new("/private/storage\\alias")),
            Err(LinuxProviderError::InvalidConfig("storageRoot"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_config_rejects_non_utf8_and_backslash_canonical_storage() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        let fixture = DirectoryFixture::new("canonical-storage-text");
        let (_config, snapshot) = successful_snapshot();

        let non_utf8_target = fixture.root.join(OsString::from_vec(b"storage-non-utf8-\xff".to_vec()));
        fs::create_dir(&non_utf8_target).expect("create non-UTF-8 storage target");
        let non_utf8_link = fixture.root.join("non-utf8-storage-link");
        symlink(&non_utf8_target, &non_utf8_link).expect("link non-UTF-8 storage target");
        assert_eq!(
            snapshot.core_config(non_utf8_link.to_string_lossy().into_owned()),
            Err(LinuxProviderError::InvalidConfig("storageRoot"))
        );

        let backslash_target = fixture.root.join("storage\\alias");
        fs::create_dir(&backslash_target).expect("create backslash storage target");
        let backslash_link = fixture.root.join("backslash-storage-link");
        symlink(&backslash_target, &backslash_link).expect("link backslash storage target");
        assert_eq!(
            snapshot.core_config(backslash_link.to_string_lossy().into_owned()),
            Err(LinuxProviderError::InvalidConfig("storageRoot"))
        );
    }

    #[cfg(target_os = "linux")]
    struct LinuxPublicProviderFixture {
        directory: DirectoryFixture,
        config: LinuxProviderConfig,
        host: CapabilityReport,
        wine_object: PathBuf,
        wine_entrypoint: PathBuf,
        wineserver_entrypoint: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl LinuxPublicProviderFixture {
        fn new() -> Self {
            use std::process::Command;

            let directory = DirectoryFixture::new("public-provider");
            let source = directory.root.join("runtime-helper.c");
            let materialized = directory.root.join("materialized");
            let bundle = directory.root.join("bundle");
            let store_root = directory.root.join("store");
            fs::create_dir_all(materialized.join("bin")).expect("create materialized bin");
            fs::create_dir_all(bundle.join("components")).expect("create bundle components");
            fs::write(
                &source,
                br#"#include <stdio.h>
int main(void) {
#ifdef ROLE_WINESERVER
    return fputs("Wine 9.0\n", stderr) < 0;
#else
    return puts("wine-9.0") < 0;
#endif
}
"#,
            )
            .expect("write Provider helper source");
            let wine_entrypoint = materialized.join("bin/wine");
            let wineserver_entrypoint = materialized.join("bin/wineserver");
            let wine_status = Command::new("/usr/bin/cc")
                .arg(&source)
                .arg("-o")
                .arg(&wine_entrypoint)
                .status()
                .expect("compile Wine helper");
            assert!(wine_status.success(), "compile Wine helper successfully");
            let wineserver_status = Command::new("/usr/bin/cc")
                .arg("-DROLE_WINESERVER=1")
                .arg(&source)
                .arg("-o")
                .arg(&wineserver_entrypoint)
                .status()
                .expect("compile Wineserver helper");
            assert!(wineserver_status.success(), "compile Wineserver helper successfully");
            fs::copy(&wine_entrypoint, bundle.join("components/wine-entrypoint.bin"))
                .expect("copy Wine helper into Pack bundle");
            fs::copy(
                &wineserver_entrypoint,
                bundle.join("components/wineserver-entrypoint.bin"),
            )
            .expect("copy Wineserver helper into Pack bundle");

            let mut config = valid_config();
            config.runtime_store_root = store_root.to_string_lossy().into_owned();
            config.wine_runtime.materialized_root = materialized.to_string_lossy().into_owned();
            config.wine_runtime.wine.digest = digest_file(&wine_entrypoint);
            config.wine_runtime.wineserver.digest = digest_file(&wineserver_entrypoint);
            let manifest = matching_manifest(&config.wine_runtime);
            config.wine_runtime.pack_digest = manifest.digest.clone();
            RuntimePackStore::new(&store_root)
                .install(&bundle, &manifest, &RejectAllSignatures)
                .expect("install Linux Provider test Pack");
            let wine_object = store_root
                .join("objects/sha256")
                .join(config.wine_runtime.wine.digest.trim_start_matches("sha256:"));
            Self {
                directory,
                config,
                host: linux_host_report(),
                wine_object,
                wine_entrypoint,
                wineserver_entrypoint,
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_public_provider_uses_real_store_entrypoints_and_system_probe() {
        let fixture = LinuxPublicProviderFixture::new();
        let snapshot = LinuxProviderSet::probe(&fixture.host, &fixture.config).expect("probe installed Linux Runtime");
        assert!(snapshot.capabilities.runtime_providers[0].available);
        assert!(snapshot.runtime_binding.is_some());
        assert!(matches!(
            snapshot.core_config(fixture.config.runtime_store_root.clone()),
            Err(LinuxProviderError::InvalidConfig("storage/runtime root overlap"))
        ));
        let storage = fixture.directory.root.join("storage");
        fs::create_dir(&storage).expect("create disjoint storage root");
        let core = snapshot
            .core_config(storage.to_string_lossy().into_owned())
            .expect("bind Provider snapshot to disjoint Storage");
        assert_eq!(core.runtime_bindings.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_public_provider_rejects_missing_and_mutated_store_objects() {
        for mutation in ["missing", "mutated"] {
            let fixture = LinuxPublicProviderFixture::new();
            if mutation == "missing" {
                fs::remove_file(&fixture.wine_object).expect("remove installed Pack object");
            } else {
                fs::write(&fixture.wine_object, b"mutated Pack object").expect("mutate installed Pack object");
            }
            let snapshot = LinuxProviderSet::probe_with(&fixture.host, &fixture.config, &PanicProbeCommand)
                .unwrap_or_else(|error| panic!("{mutation} object must produce unavailable report: {error}"));
            assert!(!snapshot.capabilities.runtime_providers[0].available, "{mutation}");
            assert!(snapshot.runtime_binding.is_none(), "{mutation}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_public_provider_rejects_an_installed_but_unrelated_pack() {
        let mut fixture = LinuxPublicProviderFixture::new();
        let unrelated_bundle = fixture.directory.root.join("unrelated-bundle");
        fs::create_dir_all(unrelated_bundle.join("components")).expect("create unrelated bundle");
        fs::copy(
            &fixture.wineserver_entrypoint,
            unrelated_bundle.join("components/wine-entrypoint.bin"),
        )
        .expect("copy unrelated Wine object");
        fs::copy(
            &fixture.wineserver_entrypoint,
            unrelated_bundle.join("components/wineserver-entrypoint.bin"),
        )
        .expect("copy Wineserver object");
        let mut unrelated = matching_manifest(&fixture.config.wine_runtime);
        component_mut(&mut unrelated, "wine-entrypoint").digest = fixture.config.wine_runtime.wineserver.digest.clone();
        resign_manifest(&mut unrelated);
        fixture.config.wine_runtime.pack_digest = unrelated.digest.clone();
        RuntimePackStore::new(&fixture.config.runtime_store_root)
            .install(&unrelated_bundle, &unrelated, &RejectAllSignatures)
            .expect("install self-consistent unrelated Pack");

        let snapshot = LinuxProviderSet::probe_with(&fixture.host, &fixture.config, &PanicProbeCommand)
            .expect("unrelated Pack must produce unavailable report");
        assert!(!snapshot.capabilities.runtime_providers[0].available);
        assert!(snapshot.runtime_binding.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_public_provider_rejects_missing_entrypoint_and_execute_permission() {
        use std::os::unix::fs::PermissionsExt;

        let missing = LinuxPublicProviderFixture::new();
        fs::remove_file(&missing.wine_entrypoint).expect("remove materialized entrypoint");
        let snapshot = LinuxProviderSet::probe_with(&missing.host, &missing.config, &PanicProbeCommand)
            .expect("closed missing-entrypoint report");
        assert!(!snapshot.capabilities.runtime_providers[0].available);
        assert!(snapshot.runtime_binding.is_none());

        let permissions = LinuxPublicProviderFixture::new();
        let mut mode = fs::metadata(&permissions.wine_entrypoint)
            .expect("entrypoint metadata")
            .permissions();
        mode.set_mode(0o644);
        fs::set_permissions(&permissions.wine_entrypoint, mode).expect("remove entrypoint execute permission");
        let snapshot = LinuxProviderSet::probe_with(&permissions.host, &permissions.config, &PanicProbeCommand)
            .expect("closed permission report");
        assert!(!snapshot.capabilities.runtime_providers[0].available);
        assert!(snapshot.runtime_binding.is_none());
    }

    #[cfg(target_os = "linux")]
    struct LinuxFailureCommand {
        failure: Option<ProbeCommandFailure>,
        observed_version: &'static str,
    }

    #[cfg(target_os = "linux")]
    impl ProbeCommand for LinuxFailureCommand {
        fn run(&self, specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
            if let Some(failure) = self.failure {
                return Err(failure);
            }
            let wineserver = specification
                .executable
                .file_name()
                .is_some_and(|name| name == "wineserver");
            Ok(ProbeCommandOutput {
                status: ProbeCommandStatus::Success,
                stdout: if wineserver {
                    Vec::new()
                } else {
                    format!("wine-{}\n", self.observed_version).into_bytes()
                },
                stderr: if wineserver {
                    format!("Wine {}\n", self.observed_version).into_bytes()
                } else {
                    Vec::new()
                },
            })
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_public_provider_closes_command_and_version_failures() {
        let command_failure = LinuxPublicProviderFixture::new();
        let snapshot = LinuxProviderSet::probe_with(
            &command_failure.host,
            &command_failure.config,
            &LinuxFailureCommand {
                failure: Some(ProbeCommandFailure::Spawn),
                observed_version: "9.0",
            },
        )
        .expect("closed command-failure report");
        assert_eq!(
            snapshot.capabilities.runtime_providers[0].reason.as_deref(),
            Some(EvidenceFailure::Command.to_string().as_str())
        );
        assert!(snapshot.runtime_binding.is_none());

        let version_failure = LinuxPublicProviderFixture::new();
        let snapshot = LinuxProviderSet::probe_with(
            &version_failure.host,
            &version_failure.config,
            &LinuxFailureCommand {
                failure: None,
                observed_version: "10.0",
            },
        )
        .expect("closed version-failure report");
        assert_eq!(
            snapshot.capabilities.runtime_providers[0].reason.as_deref(),
            Some(EvidenceFailure::Version.to_string().as_str())
        );
        assert!(snapshot.runtime_binding.is_none());
    }

    #[test]
    fn configuration_is_closed_and_x86_64_only() {
        let mut value = valid_config_json();
        value["wineRuntime"]["architecture"] = serde_json::json!("arm64");
        let config: LinuxProviderConfig = serde_json::from_value(value).unwrap();
        assert!(matches!(
            config.validate(),
            Err(LinuxProviderError::InvalidConfig("wineRuntime.architecture"))
        ));

        let mut value = valid_config_json();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LinuxProviderConfig>(value).is_err());
    }

    #[test]
    fn unknown_architecture_error_is_closed_and_redacted() {
        let marker = "ARCHITECTURE_INPUT_MUST_NOT_ESCAPE";
        let mut value = valid_config_json();
        value["wineRuntime"]["architecture"] = serde_json::json!(format!("future-architecture\n{marker}"));
        let error = serde_json::from_value::<LinuxProviderConfig>(value)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(marker), "architecture error leaked input");
        assert_eq!(error, "unsupported architecture");

        let mut value = valid_config_json();
        value["wineRuntime"]["architecture"] = serde_json::json!({"secret": marker});
        let error = serde_json::from_value::<LinuxProviderConfig>(value)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(marker), "architecture type error leaked input");
        assert_eq!(error, "unsupported architecture");
    }

    #[test]
    fn linux_absolute_path_rejects_noncanonical_serialized_forms() {
        for invalid in [
            "/",
            r"C:\wine",
            "C:/wine",
            r"\\server\share",
            "//server/share",
            "/opt//wine",
            "/opt/wine/",
            "/opt/./wine",
            "/opt/../wine",
            "/bad\npath",
            "/bad\rpath",
            "/bad\0path",
        ] {
            let mut value = valid_config_json();
            value["runtimeStoreRoot"] = serde_json::json!(invalid);
            assert_config_error(value, LinuxProviderError::InvalidConfig("runtimeStoreRoot"));
        }

        let longest = format!("/{}", "a".repeat(4095));
        let mut value = valid_config_json();
        value["runtimeStoreRoot"] = serde_json::json!(longest);
        assert!(serde_json::from_value::<LinuxProviderConfig>(value)
            .unwrap()
            .validate()
            .is_ok());

        let oversized = format!("/{}", "a".repeat(4096));
        let mut value = valid_config_json();
        value["runtimeStoreRoot"] = serde_json::json!(oversized);
        assert_config_error(value, LinuxProviderError::InvalidConfig("runtimeStoreRoot"));
    }

    #[test]
    fn mountinfo_identity_detects_bind_aliases_and_descendants() {
        let entries = parse_mountinfo(
            b"24 1 8:1 / / rw - ext4 /dev/root rw\n\
             25 24 8:1 /runtime/source /private/runtime rw - ext4 /dev/root rw\n\
             26 24 8:1 /runtime/source /private/store rw - ext4 /dev/root rw\n\
             27 24 8:1 /runtime/source/child /private/storage rw - ext4 /dev/root rw\n",
        )
        .expect("parse bounded mountinfo fixture");
        let snapshot = MountSnapshot { entries };
        assert!(derive_mount_evidence(
            ["/private/store", "/private/other", "/private/runtime"],
            ["/private/runtime/bin/wine", "/private/runtime/bin/wineserver"],
            &snapshot
        )
        .is_err());
        assert!(derive_mount_evidence(
            ["/private/store", "/private/storage", "/private/other"],
            ["/private/other/bin/wine", "/private/other/bin/wineserver"],
            &snapshot
        )
        .is_err());
    }

    #[test]
    fn mountinfo_parser_is_bounded_and_fail_closed() {
        assert!(parse_mountinfo(b"not mountinfo").is_none());
        for (escape, decoded) in [("040", ' '), ("011", '\t'), ("012", '\n'), ("134", '\\')] {
            let line = format!("24 1 8:1 /source\\{escape}dir /mount\\{escape}point rw - ext4 /dev/root rw\n");
            let escaped = parse_mountinfo(line.as_bytes()).expect("parse legal escaped mount paths");
            assert_eq!(escaped[0].root, format!("/source{decoded}dir").into_bytes());
            assert_eq!(escaped[0].mount_point, format!("/mount{decoded}point").into_bytes());
        }
        for malformed in [
            "24 1 8:1 relative /mount rw - ext4 /dev/root rw\n",
            "24 1 8:1 /source /mount\\000bad rw - ext4 /dev/root rw\n",
            "24 1 8:1 /source /mount\\777bad rw - ext4 /dev/root rw\n",
        ] {
            assert!(parse_mountinfo(malformed.as_bytes()).is_none(), "{malformed:?}");
        }
    }

    #[test]
    fn mount_writability_applies_only_to_store_and_storage() {
        fn snapshot(read_only_mount: &str) -> MountSnapshot {
            let contents = format!(
                "24 1 8:1 / / rw - ext4 /dev/root rw\n\
                 25 24 8:2 / /private/store {} - ext4 /dev/store {}\n\
                 26 24 8:3 / /private/storage {} - ext4 /dev/storage {}\n\
                 27 24 8:4 / /private/runtime {} - squashfs runtime {}\n",
                if read_only_mount == "store" { "ro" } else { "rw" },
                if read_only_mount == "store" { "ro" } else { "rw" },
                if read_only_mount == "storage" { "ro" } else { "rw" },
                if read_only_mount == "storage" { "ro" } else { "rw" },
                if read_only_mount == "runtime" { "ro" } else { "rw" },
                if read_only_mount == "runtime" { "ro" } else { "rw" },
            );
            MountSnapshot {
                entries: parse_mountinfo(contents.as_bytes()).unwrap(),
            }
        }
        assert!(derive_mount_evidence(
            ["/private/store", "/private/storage", "/private/runtime"],
            ["/private/runtime/bin/wine", "/private/runtime/bin/wineserver"],
            &snapshot("runtime")
        )
        .is_ok());
        assert!(derive_mount_evidence(
            ["/private/store", "/private/storage", "/private/runtime"],
            ["/private/runtime/bin/wine", "/private/runtime/bin/wineserver"],
            &snapshot("store")
        )
        .is_err());
        assert!(derive_mount_evidence(
            ["/private/store", "/private/storage", "/private/runtime"],
            ["/private/runtime/bin/wine", "/private/runtime/bin/wineserver"],
            &snapshot("storage")
        )
        .is_err());
    }

    #[test]
    fn mount_visibility_resolves_stacks_independent_of_record_order() {
        let records = [
            b"40 30 8:4 /hidden-child /private/runtime/child rw - ext4 /dev/a rw\n".as_slice(),
            b"31 30 8:3 /top /private/runtime rw - ext4 /dev/b rw\n",
            b"1 0 8:1 / / rw - ext4 /dev/root rw\n",
            b"30 1 8:2 /under /private/runtime rw - ext4 /dev/a rw\n",
            b"41 31 8:3 /visible-child /private/runtime/visible rw - ext4 /dev/b rw\n",
        ];
        let bytes = records.concat();
        let parsed = parse_mountinfo(&bytes).unwrap();
        let visible = visible_mounts(&parsed).unwrap();
        assert!(visible.iter().any(|entry| entry.mount_id == 31));
        assert!(!visible.iter().any(|entry| entry.mount_id == 30));
        assert!(!visible.iter().any(|entry| entry.mount_id == 40));
        assert!(visible.iter().any(|entry| entry.mount_id == 41));
        assert_eq!(
            selected_mount(b"/private/runtime/child/file", &visible)
                .unwrap()
                .mount_id,
            31
        );
        assert_eq!(
            selected_mount(b"/private/runtime/visible/file", &visible)
                .unwrap()
                .mount_id,
            41
        );

        let mut reversed = parsed;
        reversed.reverse();
        assert_eq!(visible_mounts(&reversed), Some(visible));

        let duplicate =
            parse_mountinfo(b"1 0 8:1 / / rw - ext4 /dev/root rw\n1 0 8:2 / /other rw - ext4 /dev/other rw\n").unwrap();
        assert!(visible_mounts(&duplicate).is_none());
        let cycle =
            parse_mountinfo(b"1 2 8:1 / / rw - ext4 /dev/root rw\n2 1 8:2 / /other rw - ext4 /dev/other rw\n").unwrap();
        assert!(visible_mounts(&cycle).is_none());

        let top_store_read_only = MountSnapshot {
            entries: parse_mountinfo(
                b"1 0 8:1 / / rw - ext4 /dev/root rw\n\
                  2 1 8:2 /under /private/store rw - ext4 /dev/a rw\n\
                  3 2 8:3 /top /private/store ro - squashfs top ro\n",
            )
            .unwrap(),
        };
        assert!(derive_mount_evidence(
            ["/private/store", "/private/storage", "/private/runtime"],
            ["/private/runtime/bin/wine", "/private/runtime/bin/wineserver"],
            &top_store_read_only
        )
        .is_err());

        let top_runtime_read_only = MountSnapshot {
            entries: parse_mountinfo(
                b"1 0 8:1 / / rw - ext4 /dev/root rw\n\
                  2 1 8:2 /under /private/runtime rw - ext4 /dev/a rw\n\
                  3 2 8:3 /top /private/runtime ro - squashfs top ro\n",
            )
            .unwrap(),
        };
        assert!(derive_mount_evidence(
            ["/private/store", "/private/storage", "/private/runtime"],
            ["/private/runtime/bin/wine", "/private/runtime/bin/wineserver"],
            &top_runtime_read_only
        )
        .is_ok());
    }

    #[test]
    fn mount_visibility_accepts_only_root_self_parent_and_keeps_stacks_deterministic() {
        let bytes = b"1 1 8:1 / / rw - ext4 /dev/root rw\n\
                      2 1 8:2 /old /private/runtime rw - ext4 /dev/a rw\n\
                      3 2 8:3 /middle /private/runtime rw - ext4 /dev/b rw\n\
                      4 3 8:4 /top /private/runtime rw - ext4 /dev/c rw\n\
                      5 2 8:2 /hidden /private/runtime/child rw - ext4 /dev/a rw\n";
        let parsed = parse_mountinfo(bytes).unwrap();
        let visible = visible_mounts(&parsed).expect("self-parent namespace root is a valid terminus");
        assert!(visible.iter().any(|entry| entry.mount_id == 1));
        assert!(visible.iter().any(|entry| entry.mount_id == 4));
        assert!(!visible.iter().any(|entry| matches!(entry.mount_id, 2 | 3 | 5)));
        assert_eq!(
            selected_mount(b"/private/runtime/child/file", &visible)
                .unwrap()
                .mount_id,
            4
        );
        let mut reversed = parsed;
        reversed.reverse();
        assert_eq!(visible_mounts(&reversed), Some(visible));

        let non_root_self =
            parse_mountinfo(b"1 1 8:1 / / rw - ext4 /dev/root rw\n2 2 8:2 / /private rw - ext4 /dev/a rw\n").unwrap();
        assert!(visible_mounts(&non_root_self).is_none());

        let branch = parse_mountinfo(
            b"1 1 8:1 / / rw - ext4 /dev/root rw\n\
              2 1 8:2 /old /private/runtime rw - ext4 /dev/a rw\n\
              3 2 8:3 /left /private/runtime rw - ext4 /dev/b rw\n\
              4 2 8:4 /right /private/runtime rw - ext4 /dev/c rw\n",
        )
        .unwrap();
        assert!(visible_mounts(&branch).is_none());
    }

    #[test]
    fn mount_visibility_hides_older_descendant_siblings_under_later_ancestor_cover() {
        fn snapshot(cover_mode: &[u8]) -> MountSnapshot {
            let mut bytes = b"1 1 8:1 / / rw - ext4 /dev/root rw\n\
                              2 1 8:2 /old /storage/sub rw - ext4 /dev/a rw\n\
                              3 1 8:3 /source /storage "
                .to_vec();
            bytes.extend_from_slice(cover_mode);
            bytes.extend_from_slice(b" - ext4 /dev/b ");
            bytes.extend_from_slice(cover_mode);
            bytes.extend_from_slice(
                b"\n4 1 8:3 /source/sub /store rw - ext4 /dev/b rw\n\
                  5 2 8:2 /old-child /storage/sub/child rw - ext4 /dev/a rw\n",
            );
            MountSnapshot {
                entries: parse_mountinfo(&bytes).unwrap(),
            }
        }
        let roots = ["/store", "/storage/sub", "/runtime"];
        let entrypoints = ["/runtime/bin/wine", "/runtime/bin/wineserver"];
        let rw = snapshot(b"rw");
        let visible = visible_mounts(&rw.entries).unwrap();
        assert!(!visible.iter().any(|entry| matches!(entry.mount_id, 2 | 5)));
        assert!(derive_mount_evidence(roots, entrypoints, &rw).is_err());
        let mut reversed = rw.entries;
        reversed.reverse();
        assert!(derive_mount_evidence(roots, entrypoints, &MountSnapshot { entries: reversed }).is_err());
        assert!(derive_mount_evidence(roots, entrypoints, &snapshot(b"ro")).is_err());
    }

    #[test]
    fn mount_evidence_rejects_deleted_selected_bind_but_ignores_unrelated_deleted_mount() {
        let roots = ["/store", "/storage", "/runtime"];
        let entrypoints = ["/runtime/bin/wine", "/runtime/bin/wineserver"];
        let related = MountSnapshot {
            entries: parse_mountinfo(
                b"1 1 8:1 / / rw - ext4 /dev/root rw\n\
                  2 1 8:2 /source//deleted /storage rw - ext4 /dev/a rw\n",
            )
            .unwrap(),
        };
        assert!(derive_mount_evidence(roots, entrypoints, &related).is_err());

        let unrelated = MountSnapshot {
            entries: parse_mountinfo(
                b"1 1 8:1 / / rw - ext4 /dev/root rw\n\
                  2 1 8:2 /source//deleted /unrelated rw - ext4 /dev/a rw\n",
            )
            .unwrap(),
        };
        assert!(derive_mount_evidence(roots, entrypoints, &unrelated).is_ok());
    }

    #[test]
    fn mount_evidence_ignores_unrelated_records_but_freezes_related_identity() {
        let base = parse_mountinfo(b"1 0 8:1 / / rw - ext4 /dev/root rw\n").unwrap();
        let roots = ["/private/store", "/private/storage", "/private/runtime"];
        let entrypoints = ["/private/runtime/bin/wine", "/private/runtime/bin/wineserver"];
        let baseline = derive_mount_evidence(roots, entrypoints, &MountSnapshot { entries: base.clone() }).unwrap();
        let mut unrelated = base.clone();
        unrelated.push(
            parse_mountinfo(b"2 1 9:1 / /unrelated rw - tmpfs tmpfs rw\n")
                .unwrap()
                .remove(0),
        );
        unrelated.reverse();
        assert_eq!(
            derive_mount_evidence(roots, entrypoints, &MountSnapshot { entries: unrelated }).unwrap(),
            baseline
        );
        let related =
            parse_mountinfo(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 9:1 / /private/storage rw - tmpfs tmpfs rw\n")
                .unwrap();
        assert_ne!(
            derive_mount_evidence(roots, entrypoints, &MountSnapshot { entries: related }).unwrap(),
            baseline
        );
    }

    #[test]
    fn mountinfo_byte_parser_accepts_unrelated_non_utf8_and_non_ascii_whitespace() {
        let mut bytes = b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 9:1 / /unrelated-".to_vec();
        bytes.extend_from_slice(&[0xff, 0x0b, 0x0d, 0xc2, 0xa0]);
        bytes.extend_from_slice(b" rw - tmpfs tmpfs rw\n");
        let parsed = parse_mountinfo(&bytes).expect("non-UTF-8 and non-ASCII whitespace stay inside path field");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn configuration_rejects_every_closed_contract_mutation() {
        let mut value = valid_config_json();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LinuxProviderConfig>(value).is_err());

        let mut value = valid_config_json();
        value["wineRuntime"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LinuxProviderConfig>(value).is_err());

        for entrypoint in ["wine", "wineserver"] {
            let mut value = valid_config_json();
            value["wineRuntime"][entrypoint]["unexpected"] = serde_json::json!(true);
            assert!(serde_json::from_value::<LinuxProviderConfig>(value).is_err());
        }

        let mut value = valid_request_json();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LinuxLocalContextRequest>(value).is_err());

        let mut value = valid_config_json();
        value["schemaVersion"] = serde_json::json!("2");
        assert_config_error(
            value,
            LinuxProviderError::Contract(ContractError::UnsupportedSchemaVersion),
        );

        let mut value = valid_request_json();
        value["schemaVersion"] = serde_json::json!("2");
        assert_request_error(
            value,
            LinuxProviderError::Contract(ContractError::UnsupportedSchemaVersion),
        );

        for invalid in ["/runtime/../escape", "/runtime//wine", "/runtime/"] {
            let mut value = valid_config_json();
            value["wineRuntime"]["materializedRoot"] = serde_json::json!(invalid);
            assert_config_error(value, LinuxProviderError::InvalidConfig("wineRuntime.materializedRoot"));
        }

        for field in ["runtimeStoreRoot", "storageRoot", "materializedRoot"] {
            let mut value = valid_request_json();
            value[field] = serde_json::json!("/runtime/../escape");
            assert_request_error(value, LinuxProviderError::InvalidRequest(field));

            let mut value = valid_request_json();
            value[field] = serde_json::json!(format!("/{}", "a".repeat(4096)));
            assert_request_error(value, LinuxProviderError::InvalidRequest(field));
        }

        let max_absolute = format!("/{}", "a".repeat(4095));
        for field in ["runtimeStoreRoot", "storageRoot", "materializedRoot"] {
            let mut value = valid_request_json();
            value[field] = serde_json::json!(max_absolute);
            assert!(
                serde_json::from_value::<LinuxLocalContextRequest>(value)
                    .unwrap()
                    .validate()
                    .is_ok(),
                "{field} should accept 4096 bytes"
            );
        }

        let invalid_entrypoints = [
            "/bin/wine",
            "../wine",
            "bin/../wine",
            r"bin\wine",
            "C:wine",
            "bin//wine",
            "bin/./wine",
            "bin/wine\0",
            "bin/wine\r",
            "bin/wine\n",
        ];
        for entrypoint in ["wine", "wineserver"] {
            for invalid in invalid_entrypoints {
                let mut value = valid_config_json();
                value["wineRuntime"][entrypoint]["path"] = serde_json::json!(invalid);
                let field = if entrypoint == "wine" {
                    "wineRuntime.wine.path"
                } else {
                    "wineRuntime.wineserver.path"
                };
                assert_config_error(
                    value,
                    LinuxProviderError::Contract(ContractError::UnsupportedValue(field)),
                );
            }

            let mut value = valid_config_json();
            value["wineRuntime"][entrypoint]["path"] = serde_json::json!("a".repeat(1025));
            let field = if entrypoint == "wine" {
                "wineRuntime.wine.path"
            } else {
                "wineRuntime.wineserver.path"
            };
            assert_config_error(
                value,
                LinuxProviderError::Contract(ContractError::UnsupportedValue(field)),
            );

            let mut value = valid_config_json();
            value["wineRuntime"][entrypoint]["path"] = serde_json::json!("a".repeat(1024));
            assert!(
                serde_json::from_value::<LinuxProviderConfig>(value)
                    .unwrap()
                    .validate()
                    .is_ok(),
                "{entrypoint} should accept 1024 bytes"
            );
        }

        for field in ["wine", "wineserver"] {
            for invalid in invalid_entrypoints {
                let mut value = valid_request_json();
                value[field] = serde_json::json!(invalid);
                assert_request_error(
                    value,
                    LinuxProviderError::Contract(ContractError::UnsupportedValue(field)),
                );
            }

            let mut value = valid_request_json();
            value[field] = serde_json::json!("a".repeat(1025));
            assert_request_error(
                value,
                LinuxProviderError::Contract(ContractError::UnsupportedValue(field)),
            );

            let mut value = valid_request_json();
            value[field] = serde_json::json!("a".repeat(1024));
            assert!(
                serde_json::from_value::<LinuxLocalContextRequest>(value)
                    .unwrap()
                    .validate()
                    .is_ok(),
                "{field} should accept 1024 bytes"
            );
        }

        let invalid_digests = [
            format!("sha256:{}", "A".repeat(64)),
            format!("SHA256:{}", "a".repeat(64)),
            format!("md5:{}", "a".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha256:{}", "z".repeat(64)),
        ];
        for invalid in &invalid_digests {
            let mut value = valid_config_json();
            value["wineRuntime"]["packDigest"] = serde_json::json!(invalid);
            assert_config_error(
                value,
                LinuxProviderError::Contract(ContractError::InvalidDigest("wineRuntime.packDigest")),
            );

            for entrypoint in ["wine", "wineserver"] {
                let mut value = valid_config_json();
                value["wineRuntime"][entrypoint]["digest"] = serde_json::json!(invalid);
                let field = if entrypoint == "wine" {
                    "wineRuntime.wine.digest"
                } else {
                    "wineRuntime.wineserver.digest"
                };
                assert_config_error(value, LinuxProviderError::Contract(ContractError::InvalidDigest(field)));
            }
        }

        let invalid_ids = [
            String::new(),
            "a".into(),
            "A1".into(),
            "-bad".into(),
            "bad+id".into(),
            "a".repeat(129),
        ];
        for (json_field, error_field) in [
            ("providerId", "wineRuntime.providerId"),
            ("packId", "wineRuntime.packId"),
        ] {
            for invalid in &invalid_ids {
                let mut value = valid_config_json();
                value["wineRuntime"][json_field] = serde_json::json!(invalid);
                assert_config_error(
                    value,
                    LinuxProviderError::Contract(ContractError::InvalidIdentifier(error_field)),
                );
            }

            let mut value = valid_config_json();
            value["wineRuntime"][json_field] = serde_json::json!("a".repeat(128));
            assert!(
                serde_json::from_value::<LinuxProviderConfig>(value)
                    .unwrap()
                    .validate()
                    .is_ok(),
                "{json_field} should accept 128 bytes"
            );
        }

        for invalid in [
            String::new(),
            "9/0".into(),
            "v9".into(),
            format!("1{}", "a".repeat(128)),
        ] {
            let mut value = valid_config_json();
            value["wineRuntime"]["version"] = serde_json::json!(invalid);
            assert_config_error(value, LinuxProviderError::InvalidConfig("wineRuntime.version"));

            let mut value = valid_request_json();
            value["version"] = serde_json::json!(invalid);
            assert_request_error(value, LinuxProviderError::InvalidRequest("version"));
        }

        let max_version = format!("1{}", "a".repeat(127));
        let mut value = valid_config_json();
        value["wineRuntime"]["version"] = serde_json::json!(max_version);
        assert!(serde_json::from_value::<LinuxProviderConfig>(value)
            .unwrap()
            .validate()
            .is_ok());
        let mut value = valid_request_json();
        value["version"] = serde_json::json!(max_version);
        assert!(serde_json::from_value::<LinuxLocalContextRequest>(value)
            .unwrap()
            .validate()
            .is_ok());

        let mut value = valid_config_json();
        value["wineRuntime"]["architecture"] = serde_json::json!("arm64");
        assert_config_error(value, LinuxProviderError::InvalidConfig("wineRuntime.architecture"));

        let mut value = valid_config_json();
        value["wineRuntime"]["architecture"] = serde_json::json!("unknown");
        assert!(serde_json::from_value::<LinuxProviderConfig>(value).is_err());

        for (field, expected) in [("capabilities", "guest-x86_64"), ("wined3dCapabilities", "opengl")] {
            let mut value = valid_config_json();
            value["wineRuntime"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<LinuxProviderConfig>(value).is_err());

            for mutation in [
                serde_json::json!([]),
                serde_json::json!([expected, expected]),
                serde_json::json!(["wrong"]),
                serde_json::json!([expected, "extra"]),
                serde_json::json!(["extra", expected]),
            ] {
                let mut value = valid_config_json();
                value["wineRuntime"][field] = mutation;
                let error_field = if field == "capabilities" {
                    "wineRuntime.capabilities"
                } else {
                    "wineRuntime.wined3dCapabilities"
                };
                assert_config_error(value, LinuxProviderError::InvalidConfig(error_field));
            }
        }

        let marker = "DO_NOT_ECHO";
        let mut value = valid_config_json();
        value["runtimeStoreRoot"] = serde_json::json!(format!("/bad\n{marker}"));
        let error = serde_json::from_value::<LinuxProviderConfig>(value)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(!error.to_string().contains(marker));

        let mut value = valid_request_json();
        value["wine"] = serde_json::json!(format!("bin/wine\n{marker}"));
        let error = serde_json::from_value::<LinuxLocalContextRequest>(value)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(!error.to_string().contains(marker));

        assert!(serde_json::from_value::<LinuxProviderConfig>(valid_config_json())
            .unwrap()
            .validate()
            .is_ok());
        assert!(serde_json::from_value::<LinuxLocalContextRequest>(valid_request_json())
            .unwrap()
            .validate()
            .is_ok());
    }

    #[test]
    fn entrypoint_requires_containment_digest_regular_file_and_elf() {
        let fixture = EntryFixture::new();
        assert!(verify_entrypoint(&fixture.root, &fixture.verified("bin/wine")).is_ok());

        assert_rejected(fixture.digest_mismatch());
        assert_rejected(fixture.directory_entry());
        assert_rejected(fixture.non_elf_entry());
        assert_rejected(fixture.truncated_entry());

        let (root, entrypoint) = fixture.digest_mismatch();
        assert_eq!(verify_entrypoint(&root, &entrypoint), Err(EvidenceFailure::Digest));
        let (root, entrypoint) = fixture.directory_entry();
        assert_eq!(verify_entrypoint(&root, &entrypoint), Err(EvidenceFailure::Entrypoint));
        let (root, entrypoint) = fixture.non_elf_entry();
        assert_eq!(verify_entrypoint(&root, &entrypoint), Err(EvidenceFailure::Elf));
        let (root, entrypoint) = fixture.truncated_entry();
        assert_eq!(verify_entrypoint(&root, &entrypoint), Err(EvidenceFailure::Elf));

        let mut arm64 = test_elf64_x86_64(2);
        arm64[18..20].copy_from_slice(&183_u16.to_le_bytes());
        let arm64_entrypoint = fixture.write_entry("bin/arm64", &arm64);
        assert_eq!(
            verify_entrypoint(&fixture.root, &arm64_entrypoint),
            Err(EvidenceFailure::Architecture)
        );
    }

    #[test]
    fn entrypoint_rejects_invalid_roots_paths_and_digests() {
        let fixture = EntryFixture::new();
        let missing_root = fixture.base.join("missing-root");
        assert_eq!(
            verify_entrypoint(&missing_root, &fixture.verified("bin/wine")),
            Err(EvidenceFailure::MaterializedRoot)
        );

        let root_file = fixture.base.join("root-file");
        fs::write(&root_file, b"not a directory").expect("write root file");
        assert_eq!(
            verify_entrypoint(
                &root_file,
                &VerifiedEntrypoint {
                    path: "bin/wine".to_owned(),
                    digest: format!("sha256:{}", "0".repeat(64)),
                }
            ),
            Err(EvidenceFailure::MaterializedRoot)
        );

        for invalid_path in ["bin/missing", "/bin/wine", "../wine", "bin/../wine", "C:/wine"] {
            assert_eq!(
                verify_entrypoint(
                    &fixture.root,
                    &VerifiedEntrypoint {
                        path: invalid_path.to_owned(),
                        digest: format!("sha256:{}", "0".repeat(64)),
                    }
                ),
                Err(EvidenceFailure::Entrypoint),
                "{invalid_path}"
            );
        }

        let mut malformed_digest = fixture.verified("bin/wine");
        malformed_digest.digest = format!("sha256:{}", "A".repeat(64));
        assert_eq!(
            verify_entrypoint(&fixture.root, &malformed_digest),
            Err(EvidenceFailure::Digest)
        );
    }

    #[test]
    fn entrypoint_error_display_redacts_untrusted_values_and_paths() {
        let fixture = EntryFixture::new();
        let marker = "ENTRYPOINT_INPUT_MUST_NOT_ESCAPE";
        let error = verify_entrypoint(
            &fixture.root,
            &VerifiedEntrypoint {
                path: format!("bin/{marker}\n"),
                digest: format!("sha256:{}", "0".repeat(64)),
            },
        )
        .unwrap_err();
        let rendered = error.to_string();
        assert_eq!(error, EvidenceFailure::Entrypoint);
        assert!(!rendered.contains(marker));
        assert!(!rendered.contains(&fixture.root.to_string_lossy().to_string()));

        for failure in [
            EvidenceFailure::MaterializedRoot,
            EvidenceFailure::Entrypoint,
            EvidenceFailure::Digest,
            EvidenceFailure::Elf,
            EvidenceFailure::Architecture,
            EvidenceFailure::RuntimePack,
            EvidenceFailure::Version,
            EvidenceFailure::Command,
        ] {
            let rendered = failure.to_string();
            assert!(!rendered.contains(marker));
            assert!(!rendered.contains(&fixture.root.to_string_lossy().to_string()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn entrypoint_requires_a_unix_execute_bit() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = EntryFixture::new();
        let path = fixture.root.join("bin/wine");
        let mut permissions = fs::metadata(&path).expect("entrypoint metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&path, permissions).expect("clear execute bits");
        assert_eq!(
            verify_entrypoint(&fixture.root, &fixture.verified("bin/wine")),
            Err(EvidenceFailure::Entrypoint)
        );
    }

    #[cfg(unix)]
    #[test]
    fn entrypoint_resolves_symlinks_only_within_root() {
        use std::os::unix::fs::symlink;

        let fixture = EntryFixture::new();

        let outside = fixture.base.join("outside-wine");
        fs::write(&outside, test_elf64_x86_64(2)).expect("write outside entrypoint");
        set_executable(&outside);
        symlink(&outside, fixture.root.join("bin/escape")).expect("create escaping symlink");
        assert_eq!(
            verify_entrypoint(
                &fixture.root,
                &VerifiedEntrypoint {
                    path: "bin/escape".to_owned(),
                    digest: digest_file(&outside),
                }
            ),
            Err(EvidenceFailure::Entrypoint)
        );

        let internal = fixture.write_entry("libexec/wine-real", &test_elf64_x86_64(3));
        symlink(
            fixture.root.join("libexec/wine-real"),
            fixture.root.join("bin/internal"),
        )
        .expect("create internal symlink");
        let resolved = verify_entrypoint(
            &fixture.root,
            &VerifiedEntrypoint {
                path: "bin/internal".to_owned(),
                digest: internal.digest,
            },
        )
        .expect("internal symlink should resolve");
        assert_eq!(
            resolved,
            fs::canonicalize(fixture.root.join("libexec/wine-real")).expect("canonical internal target")
        );
    }

    struct RecordingBootstrapOperations {
        recorded: RefCell<Vec<&'static str>>,
    }

    impl Default for RecordingBootstrapOperations {
        fn default() -> Self {
            Self {
                recorded: RefCell::new(Vec::new()),
            }
        }
    }

    impl RecordingBootstrapOperations {
        fn record<T>(&self, operation: &'static str) -> Result<T, LinuxBootstrapError> {
            self.recorded.borrow_mut().push(operation);
            Err(LinuxBootstrapError::RegistrationFailed(operation))
        }

        fn recorded(&self) -> Vec<&'static str> {
            self.recorded.borrow().clone()
        }
    }

    impl BootstrapOperations for RecordingBootstrapOperations {
        fn prepare_store(&self, _store_root: &Path, _owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.record("store-create")
        }

        fn create_staging(&self, _store_root: &Path, _owner: OwnerIdentity) -> Result<PathBuf, LinuxBootstrapError> {
            self.record("staging-create")
        }

        fn populate_staging(&self, _staging: &Path, _prepared: &PreparedBootstrap) -> Result<(), LinuxBootstrapError> {
            self.record("staging-write")
        }

        fn install_pack(
            &self,
            _store_root: &Path,
            _staging: &Path,
            _manifest: &RuntimePackManifest,
        ) -> Result<(), LinuxBootstrapError> {
            self.record("pack-install")
        }

        fn cleanup_staging(&self, _staging: &Path, _owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.record("staging-cleanup")
        }

        fn prepare_storage(&self, _storage_root: &Path, _owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.record("storage-create")
        }
    }

    fn invalid_bootstrap_request() -> LinuxLocalContextRequest {
        LinuxLocalContextRequest {
            schema_version: "2".into(),
            runtime_store_root: "/private/bootstrap-store".into(),
            storage_root: "/private/bootstrap-storage".into(),
            materialized_root: "/private/bootstrap-runtime".into(),
            wine: "bin/wine".into(),
            wineserver: "bin/wineserver".into(),
            version: "9.0".into(),
        }
    }

    #[test]
    fn bootstrap_validation_precedes_every_mutation() {
        let operations = RecordingBootstrapOperations::default();
        let result = validate_then_bootstrap(
            &linux_host_report(),
            &invalid_bootstrap_request(),
            &PanicProbeCommand,
            &operations,
        );
        assert!(result.is_err());
        assert!(operations.recorded().is_empty());
    }

    #[test]
    fn bootstrap_rejects_non_file_store_artifacts_before_install() {
        for kind in ["object", "manifest"] {
            let fixture = DirectoryFixture::new(kind);
            let (config, manifest) = matching_config_and_manifest();
            let store = fixture.root.join("store");
            let target = if kind == "object" {
                store
                    .join("objects/sha256")
                    .join(config.wine_runtime.wine.digest.trim_start_matches("sha256:"))
            } else {
                store
                    .join("manifests/sha256")
                    .join(format!("{}.json", manifest.digest.trim_start_matches("sha256:")))
            };
            fs::create_dir_all(&target).expect("create non-file Store artifact");

            assert!(
                validate_store_artifact_paths(&store, &manifest, current_owner_identity().unwrap(),).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn bootstrap_effective_uid_parser_is_closed() {
        let parsed =
            parse_owner_identity("Name:\ttest\nUid:\t1000\t1001\t1002\t1003\nGid:\t5\t6\t7\t8\nGroups:\t11 9 11\n")
                .unwrap();
        assert_eq!(parsed.filesystem_uid, 1003);
        assert_eq!(parsed.filesystem_gid, 8);
        assert_eq!(
            &parsed.supplementary_groups[..parsed.supplementary_group_count],
            &[9, 11]
        );
        for malformed in [
            "Name:\ttest\n",
            "Uid:\t1000\t1001\t1002\nGid:\t1\t2\t3\t4\nGroups:\t1\n",
            "Uid:\t1000\t1001\t1002\t1003\textra\nGid:\t1\t2\t3\t4\nGroups:\t1\n",
            "Uid:\t1000\tnot-a-number\t1002\t1003\nGid:\t1\t2\t3\t4\nGroups:\t1\n",
            "Uid:\t1\t2\t3\t4\nGid:\t1\t2\t3\t4\nGid:\t1\t2\t3\t4\nGroups:\t1\n",
            "Uid:\t1\t2\t3\t4\nGid:\t1\t2\t3\t4\nGroups:\t1\nGroups:\t2\n",
        ] {
            assert!(parse_owner_identity(malformed).is_none(), "{malformed:?}");
        }
    }

    #[test]
    fn creation_permissions_select_the_effective_unix_class() {
        let owner = owner_identity_for_test(1000, 2000, &[3000]).unwrap();
        assert!(creation_permission_allows(0o700, 1000, 9999, owner));
        assert!(!creation_permission_allows(0o500, 1000, 9999, owner));
        assert!(creation_permission_allows(0o070, 9999, 3000, owner));
        assert!(!creation_permission_allows(0o050, 9999, 3000, owner));
        assert!(creation_permission_allows(0o1777, 0, 0, owner));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_missing_destination_below_non_writable_ancestor_before_probe() {
        use std::os::unix::fs::PermissionsExt;

        for field in ["runtimeStoreRoot", "storageRoot"] {
            let fixture = LinuxPublicProviderFixture::new();
            let blocked_parent = fixture.directory.root.join(format!("blocked-{field}"));
            fs::create_dir(&blocked_parent).unwrap();
            fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o500)).unwrap();
            let store = if field == "runtimeStoreRoot" {
                blocked_parent.join("missing/store")
            } else {
                fixture.directory.root.join("writable-store")
            };
            let storage = if field == "storageRoot" {
                blocked_parent.join("missing/storage")
            } else {
                fixture.directory.root.join("writable-storage")
            };
            let request = bootstrap_request(&fixture, &store, &storage);
            let before = snapshot_tree(&fixture.directory.root);

            assert!(create_local_context_with(&fixture.host, &request, &PanicProbeCommand).is_err());
            assert_eq!(snapshot_tree(&fixture.directory.root), before, "{field}");
            assert!(!store.exists());
            assert!(!storage.exists());
            fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn bootstrap_exact_active_ref_rejects_wrong_pack_and_duplicate_fields() {
        for (label, contents) in [
            (
                "wrong-pack",
                format!(
                    r#"{{"schemaVersion":"1","packId":"wrong-pack","activeDigest":"sha256:{}","history":[]}}"#,
                    "a".repeat(64)
                ),
            ),
            (
                "duplicate",
                format!(
                    r#"{{"schemaVersion":"1","packId":"{LOCAL_PREVIEW_PACK_ID}","packId":"{LOCAL_PREVIEW_PACK_ID}","activeDigest":"sha256:{}","history":[]}}"#,
                    "a".repeat(64)
                ),
            ),
        ] {
            let fixture = DirectoryFixture::new(label);
            let store = fixture.root.join("store");
            let reference = store.join("refs").join(LOCAL_PREVIEW_PACK_ID).join("current.json");
            fs::create_dir_all(reference.parent().unwrap()).expect("create ref parent");
            fs::write(&reference, contents).expect("write malformed exact ref");
            assert!(
                observe_exact_active_ref(&store, current_owner_identity().unwrap(),).is_err(),
                "{label}"
            );
        }
    }

    #[test]
    fn bootstrap_staging_post_create_failure_removes_only_the_empty_directory() {
        let fixture = DirectoryFixture::new("staging-post-create");
        let staging = fixture.root.join(".compatforge-bootstrap-injected");
        fs::create_dir(&staging).expect("create exclusive staging fixture");
        let result = accept_created_staging(&staging, current_owner_identity().unwrap(), &|_, _, _| {
            Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"))
        });
        assert_eq!(result, Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")));
        assert!(!staging.exists());
        assert!(fixture.root.exists());

        let nonempty = fixture.root.join(".compatforge-bootstrap-nonempty");
        fs::create_dir(&nonempty).expect("create second exclusive staging fixture");
        fs::write(nonempty.join("attacker-file"), b"do not recursively remove").unwrap();
        assert_eq!(
            accept_created_staging(&nonempty, current_owner_identity().unwrap(), &|_, _, _| Err(
                LinuxBootstrapError::InvalidRequest("runtimeStoreRoot")
            ),),
            Err(LinuxBootstrapError::RegistrationFailed("staging cleanup"))
        );
        assert!(nonempty.join("attacker-file").exists());
    }

    #[test]
    fn receipt_contract_is_exact_and_path_free_portably() {
        let receipt = LinuxLocalContextReceipt {
            schema_version: SCHEMA_VERSION_V1.into(),
            source: "explicit-override".into(),
            version: "9.0".into(),
            architecture: CpuArchitecture::X86_64,
            pack_id: "wine-linux-x86-64-local-preview".into(),
            pack_digest: format!("sha256:{}", "a".repeat(64)),
            capabilities: vec![RUNTIME_CAPABILITY.into()],
        };
        let value = serde_json::to_value(receipt).expect("serialize portable receipt");
        let mut keys = value
            .as_object()
            .expect("receipt object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "architecture",
                "capabilities",
                "packDigest",
                "packId",
                "schemaVersion",
                "source",
                "version",
            ]
        );
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains("/private/runtime"));
        assert!(!serialized.contains("/private/storage"));
        assert!(!serialized.contains("bin/wine"));
    }

    #[cfg(target_os = "linux")]
    fn bootstrap_request(
        fixture: &LinuxPublicProviderFixture,
        store_root: &Path,
        storage_root: &Path,
    ) -> LinuxLocalContextRequest {
        LinuxLocalContextRequest {
            schema_version: SCHEMA_VERSION_V1.into(),
            runtime_store_root: store_root.to_string_lossy().into_owned(),
            storage_root: storage_root.to_string_lossy().into_owned(),
            materialized_root: fixture.config.wine_runtime.materialized_root.clone(),
            wine: fixture.config.wine_runtime.wine.path.clone(),
            wineserver: fixture.config.wine_runtime.wineserver.path.clone(),
            version: fixture.config.wine_runtime.version.clone(),
        }
    }

    #[cfg(target_os = "linux")]
    fn snapshot_tree(root: &Path) -> Vec<(String, char, Vec<u8>)> {
        fn visit(base: &Path, path: &Path, entries: &mut Vec<(String, char, Vec<u8>)>) {
            let mut children = fs::read_dir(path)
                .expect("read bootstrap fixture tree")
                .map(|entry| entry.expect("read bootstrap fixture entry"))
                .collect::<Vec<_>>();
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                let path = child.path();
                let relative = path
                    .strip_prefix(base)
                    .expect("fixture entry stays below base")
                    .to_string_lossy()
                    .replace('\\', "/");
                let metadata = fs::symlink_metadata(&path).expect("bootstrap fixture metadata");
                if metadata.file_type().is_symlink() {
                    entries.push((relative, 'l', Vec::new()));
                } else if metadata.is_dir() {
                    entries.push((relative, 'd', Vec::new()));
                    visit(base, &path, entries);
                } else {
                    entries.push((relative, 'f', fs::read(&path).expect("read bootstrap fixture file")));
                }
            }
        }

        if !root.exists() {
            return Vec::new();
        }
        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_receipt_is_exact_and_path_free() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("bootstrap-store");
        let storage = fixture.directory.root.join("bootstrap-storage");
        let request = bootstrap_request(&fixture, &store, &storage);

        let local = create_local_context(&fixture.host, &request).expect("bootstrap explicit Linux Runtime");
        let receipt = serde_json::to_value(&local.receipt).expect("serialize public bootstrap receipt");
        let object = receipt.as_object().expect("receipt is an object");
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "architecture",
                "capabilities",
                "packDigest",
                "packId",
                "schemaVersion",
                "source",
                "version",
            ]
        );
        assert_eq!(receipt["source"], "explicit-override");
        assert_eq!(receipt["architecture"], "x86_64");
        assert_eq!(receipt["packId"], "wine-linux-x86-64-local-preview");
        assert_eq!(receipt["capabilities"], serde_json::json!(["guest-x86_64"]));
        let serialized = serde_json::to_string(&receipt).unwrap();
        for private_path in [
            request.runtime_store_root.as_str(),
            request.storage_root.as_str(),
            request.materialized_root.as_str(),
            request.wine.as_str(),
            request.wineserver.as_str(),
        ] {
            assert!(!serialized.contains(private_path), "receipt leaked {private_path}");
        }
        assert_eq!(local.config.runtime_bindings.len(), 1);
        assert_eq!(
            local.config.runtime_bindings[0].provider_id,
            "wine-linux-x86-64-preview"
        );
        assert_eq!(local.config.runtime_bindings[0].pack_id, local.receipt.pack_id);
        assert_eq!(local.config.runtime_bindings[0].pack_digest, local.receipt.pack_digest);
        let private_directories = [
            store.clone(),
            store.join("objects"),
            store.join("objects/sha256"),
            store.join("manifests"),
            store.join("manifests/sha256"),
            store.join("refs"),
            store.join("refs/wine-linux-x86-64-local-preview"),
            store.join(BOOTSTRAP_STAGING_PARENT),
            storage.clone(),
        ];
        let effective_uid = current_owner_identity()
            .expect("read Linux owner identity")
            .filesystem_uid;
        for private_directory in private_directories {
            let metadata = fs::metadata(&private_directory).unwrap();
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                0o700,
                "{}",
                private_directory.display()
            );
            assert_eq!(metadata.uid(), effective_uid, "{}", private_directory.display());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_is_idempotent_for_the_same_digest() {
        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("idempotent-store");
        let storage = fixture.directory.root.join("idempotent-storage");
        let request = bootstrap_request(&fixture, &store, &storage);

        let first = create_local_context(&fixture.host, &request).expect("first bootstrap");
        let first_tree = snapshot_tree(&store);
        let second = create_local_context(&fixture.host, &request).expect("second bootstrap");

        assert_eq!(first.receipt, second.receipt);
        assert_eq!(first.config, second.config);
        assert_eq!(snapshot_tree(&store), first_tree);
        assert_eq!(
            RuntimePackStore::new(&store)
                .active_digest("wine-linux-x86-64-local-preview")
                .expect("read active Preview ref"),
            Some(first.receipt.pack_digest)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_refuses_conflicting_active_ref_before_install() {
        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("conflict-store");
        let storage = fixture.directory.root.join("conflict-storage");
        let bundle = fixture.directory.root.join("conflict-bundle");
        fs::create_dir_all(bundle.join("components")).expect("create conflicting bundle");
        fs::copy(&fixture.wine_entrypoint, bundle.join("components/wine-entrypoint.bin"))
            .expect("copy conflicting Wine object");
        fs::copy(
            &fixture.wineserver_entrypoint,
            bundle.join("components/wineserver-entrypoint.bin"),
        )
        .expect("copy conflicting Wineserver object");
        let mut conflicting_runtime = fixture.config.wine_runtime.clone();
        conflicting_runtime.provider_id = "wine-linux-x86-64-preview".into();
        conflicting_runtime.pack_id = "wine-linux-x86-64-local-preview".into();
        conflicting_runtime.version = "8.0".into();
        let conflicting_manifest = matching_manifest(&conflicting_runtime);
        RuntimePackStore::new(&store)
            .install(&bundle, &conflicting_manifest, &RejectAllSignatures)
            .expect("install conflicting active ref");
        let before = snapshot_tree(&store);
        let request = bootstrap_request(&fixture, &store, &storage);

        let result = create_local_context(&fixture.host, &request);

        assert!(matches!(result, Err(LinuxBootstrapError::ConflictingActiveRef)));
        assert_eq!(snapshot_tree(&store), before);
        assert!(!storage.exists());
        assert_eq!(
            RuntimePackStore::new(&store)
                .active_digest("wine-linux-x86-64-local-preview")
                .unwrap(),
            Some(conflicting_manifest.digest)
        );
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    enum BootstrapFault {
        Install,
        RefWrite,
        StagingCleanup,
        Storage,
    }

    #[cfg(target_os = "linux")]
    struct FaultingBootstrapOperations {
        fault: BootstrapFault,
        system: SystemBootstrapOperations,
    }

    #[cfg(target_os = "linux")]
    impl FaultingBootstrapOperations {
        fn new(fault: BootstrapFault) -> Self {
            Self {
                fault,
                system: SystemBootstrapOperations,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl BootstrapOperations for FaultingBootstrapOperations {
        fn prepare_store(&self, store_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.system.prepare_store(store_root, owner)
        }

        fn create_staging(&self, store_root: &Path, owner: OwnerIdentity) -> Result<PathBuf, LinuxBootstrapError> {
            self.system.create_staging(store_root, owner)
        }

        fn populate_staging(&self, staging: &Path, prepared: &PreparedBootstrap) -> Result<(), LinuxBootstrapError> {
            self.system.populate_staging(staging, prepared)
        }

        fn install_pack(
            &self,
            store_root: &Path,
            staging: &Path,
            manifest: &RuntimePackManifest,
        ) -> Result<(), LinuxBootstrapError> {
            match self.fault {
                BootstrapFault::Install => {
                    fs::write(
                        staging.join("components/wineserver-entrypoint.bin"),
                        b"corrupt after validation",
                    )
                    .expect("inject staged object corruption");
                }
                BootstrapFault::RefWrite => {
                    fs::create_dir_all(store_root.join("refs/wine-linux-x86-64-local-preview/current.json"))
                        .expect("inject active-ref write failure");
                }
                BootstrapFault::StagingCleanup | BootstrapFault::Storage => {}
            }
            self.system.install_pack(store_root, staging, manifest)
        }

        fn cleanup_staging(&self, staging: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            if matches!(self.fault, BootstrapFault::StagingCleanup) {
                Err(LinuxBootstrapError::RegistrationFailed("staging cleanup"))
            } else {
                self.system.cleanup_staging(staging, owner)
            }
        }

        fn prepare_storage(&self, storage_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            if matches!(self.fault, BootstrapFault::Storage) {
                Err(LinuxBootstrapError::RegistrationFailed("storage create"))
            } else {
                self.system.prepare_storage(storage_root, owner)
            }
        }
    }

    #[cfg(target_os = "linux")]
    struct MutateEntrypointAfterInstallOperations {
        system: SystemBootstrapOperations,
        entrypoint: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl BootstrapOperations for MutateEntrypointAfterInstallOperations {
        fn prepare_store(&self, store_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.system.prepare_store(store_root, owner)
        }

        fn create_staging(&self, store_root: &Path, owner: OwnerIdentity) -> Result<PathBuf, LinuxBootstrapError> {
            self.system.create_staging(store_root, owner)
        }

        fn populate_staging(&self, staging: &Path, prepared: &PreparedBootstrap) -> Result<(), LinuxBootstrapError> {
            self.system.populate_staging(staging, prepared)
        }

        fn install_pack(
            &self,
            store_root: &Path,
            staging: &Path,
            manifest: &RuntimePackManifest,
        ) -> Result<(), LinuxBootstrapError> {
            self.system.install_pack(store_root, staging, manifest)
        }

        fn cleanup_staging(&self, staging: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.system.cleanup_staging(staging, owner)?;
            fs::write(&self.entrypoint, b"mutated after Pack installation")
                .map_err(|_| LinuxBootstrapError::RegistrationFailed("test mutation"))
        }

        fn prepare_storage(&self, storage_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.system.prepare_storage(storage_root, owner)
        }
    }

    #[cfg(target_os = "linux")]
    enum StorageMutation {
        RefRaw(PathBuf),
        File(PathBuf),
        ControlMode(PathBuf),
    }

    #[cfg(target_os = "linux")]
    struct MutateRefDuringStorageOperations {
        system: SystemBootstrapOperations,
        mutation: StorageMutation,
    }

    #[cfg(target_os = "linux")]
    impl BootstrapOperations for MutateRefDuringStorageOperations {
        fn prepare_store(&self, store_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.system.prepare_store(store_root, owner)
        }

        fn create_staging(&self, store_root: &Path, owner: OwnerIdentity) -> Result<PathBuf, LinuxBootstrapError> {
            self.system.create_staging(store_root, owner)
        }

        fn populate_staging(&self, staging: &Path, prepared: &PreparedBootstrap) -> Result<(), LinuxBootstrapError> {
            self.system.populate_staging(staging, prepared)
        }

        fn install_pack(
            &self,
            store_root: &Path,
            staging: &Path,
            manifest: &RuntimePackManifest,
        ) -> Result<(), LinuxBootstrapError> {
            self.system.install_pack(store_root, staging, manifest)
        }

        fn cleanup_staging(&self, staging: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.system.cleanup_staging(staging, owner)
        }

        fn prepare_storage(&self, storage_root: &Path, owner: OwnerIdentity) -> Result<(), LinuxBootstrapError> {
            self.system.prepare_storage(storage_root, owner)?;
            match &self.mutation {
                StorageMutation::RefRaw(active_ref) => {
                    let mut raw = fs::read(active_ref).expect("Storage fault reads active ref");
                    raw.extend_from_slice(b" \n");
                    fs::write(active_ref, raw).expect("Storage fault reformats active ref");
                }
                StorageMutation::File(path) => {
                    fs::write(path, b"mutated during Storage preparation")
                        .expect("Storage fault mutates evidence file");
                }
                StorageMutation::ControlMode(path) => {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o500))
                        .expect("Storage fault mutates control mode");
                }
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_allows_only_documented_immutable_leftovers_after_install_failure() {
        for fault in [BootstrapFault::Install, BootstrapFault::RefWrite] {
            let fixture = LinuxPublicProviderFixture::new();
            let store = fixture.directory.root.join(match fault {
                BootstrapFault::Install => "failed-install-store",
                BootstrapFault::RefWrite => "failed-ref-store",
                BootstrapFault::StagingCleanup | BootstrapFault::Storage => unreachable!(),
            });
            let storage = fixture.directory.root.join("failed-install-storage");
            let request = bootstrap_request(&fixture, &store, &storage);
            let result = validate_then_bootstrap(
                &fixture.host,
                &request,
                &SystemProbeCommand,
                &FaultingBootstrapOperations::new(fault),
            );

            assert!(result.is_err());
            assert!(!storage.exists(), "Storage must not be created on install failure");
            let entries = snapshot_tree(&store);
            assert!(
                entries
                    .iter()
                    .all(|(path, _, _)| !path
                        .starts_with(&format!("{BOOTSTRAP_STAGING_PARENT}/{BOOTSTRAP_STAGING_PREFIX}"))),
                "invocation staging must be removed: {entries:?}"
            );
            let regular_files = entries
                .iter()
                .filter(|(_, kind, _)| *kind == 'f')
                .map(|(path, _, bytes)| (path.as_str(), bytes.as_slice()))
                .collect::<Vec<_>>();
            for (path, bytes) in &regular_files {
                if let Some(hex) = path.strip_prefix("objects/sha256/") {
                    assert_eq!(sha256_digest_bytes(bytes), format!("sha256:{hex}"));
                } else if let Some(hex_json) = path.strip_prefix("manifests/sha256/") {
                    let hex = hex_json.strip_suffix(".json").expect("manifest JSON suffix");
                    let manifest: RuntimePackManifest =
                        serde_json::from_slice(bytes).expect("parse immutable leftover manifest");
                    assert_eq!(manifest.digest, format!("sha256:{hex}"));
                    assert_eq!(
                        sha256_digest_bytes(&manifest.canonical_unsigned_bytes().unwrap()),
                        manifest.digest
                    );
                } else {
                    panic!("non-content-addressed bootstrap leftover: {path}");
                }
            }
            match fault {
                BootstrapFault::Install => {
                    assert_eq!(regular_files.len(), 1, "{regular_files:?}");
                    assert!(regular_files[0].0.starts_with("objects/sha256/"));
                }
                BootstrapFault::RefWrite => {
                    assert_eq!(regular_files.len(), 3, "{regular_files:?}");
                    assert_eq!(
                        regular_files
                            .iter()
                            .filter(|(path, _)| path.starts_with("objects/sha256/"))
                            .count(),
                        2
                    );
                    assert_eq!(
                        regular_files
                            .iter()
                            .filter(|(path, _)| path.starts_with("manifests/sha256/") && path.ends_with(".json"))
                            .count(),
                        1
                    );
                    assert!(
                        entries
                            .iter()
                            .any(|(path, kind, _)| path.ends_with("/current.json") && *kind == 'd'),
                        "fault injection must be the only non-immutable ref artifact"
                    );
                }
                BootstrapFault::StagingCleanup | BootstrapFault::Storage => unreachable!(),
            }
        }

        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("failed-cleanup-store");
        let storage = fixture.directory.root.join("failed-cleanup-storage");
        let request = bootstrap_request(&fixture, &store, &storage);
        let result = validate_then_bootstrap(
            &fixture.host,
            &request,
            &SystemProbeCommand,
            &FaultingBootstrapOperations::new(BootstrapFault::StagingCleanup),
        );
        assert!(matches!(
            result,
            Err(LinuxBootstrapError::RegistrationFailed("staging cleanup"))
        ));
        assert!(!storage.exists());
        let entries = snapshot_tree(&store);
        let staging_path_prefix = format!("{BOOTSTRAP_STAGING_PARENT}/{BOOTSTRAP_STAGING_PREFIX}");
        let staging_roots = entries
            .iter()
            .filter(|(path, kind, _)| {
                *kind == 'd' && path.starts_with(&staging_path_prefix) && path.split('/').count() == 2
            })
            .map(|(path, _, _)| path.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            staging_roots.len(),
            1,
            "failed cleanup leaves its own staging: {entries:?}"
        );
        let staging_prefix = format!("{}/", staging_roots[0]);
        assert!(entries.iter().all(|(path, _, _)| {
            !path.starts_with(&staging_path_prefix) || path == &staging_roots[0] || path.starts_with(&staging_prefix)
        }));
        let mut staged_entries = entries
            .iter()
            .filter_map(|(path, kind, _)| {
                path.strip_prefix(&staging_prefix)
                    .map(|relative| (relative.to_owned(), *kind))
            })
            .collect::<Vec<_>>();
        staged_entries.sort();
        assert_eq!(
            staged_entries,
            [
                ("components".into(), 'd'),
                ("components/wine-entrypoint.bin".into(), 'f'),
                ("components/wineserver-entrypoint.bin".into(), 'f'),
                ("manifest.json".into(), 'f'),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_post_install_failure_returns_no_context_and_keeps_only_the_exact_active_ref() {
        fn assert_exact_registration_without_context(
            fixture: &LinuxPublicProviderFixture,
            store: &Path,
            storage: &Path,
            operations: &dyn BootstrapOperations,
        ) {
            let request = bootstrap_request(fixture, store, storage);
            assert!(
                validate_then_bootstrap(&fixture.host, &request, &SystemProbeCommand, operations).is_err(),
                "post-install failure must not return Context or receipt"
            );
            assert!(!storage.exists());
            let runtime_store = RuntimePackStore::new(store);
            let digest = runtime_store
                .active_digest("wine-linux-x86-64-local-preview")
                .expect("read completed exact registration")
                .expect("successful install published its exact ref");
            let manifest = runtime_store
                .verified_manifest(&digest)
                .expect("post-install failure retains a verified Pack");
            assert_eq!(manifest.id, "wine-linux-x86-64-local-preview");
            assert!(snapshot_tree(store).iter().all(
                |(path, _, _)| !path.starts_with(&format!("{BOOTSTRAP_STAGING_PARENT}/{BOOTSTRAP_STAGING_PREFIX}"))
            ));
        }

        let storage_failure = LinuxPublicProviderFixture::new();
        let store = storage_failure.directory.root.join("post-install-storage-store");
        let storage = storage_failure.directory.root.join("post-install-storage");
        assert_exact_registration_without_context(
            &storage_failure,
            &store,
            &storage,
            &FaultingBootstrapOperations::new(BootstrapFault::Storage),
        );

        let provider_failure = LinuxPublicProviderFixture::new();
        let store = provider_failure.directory.root.join("post-install-provider-store");
        let storage = provider_failure.directory.root.join("post-install-provider-storage");
        assert_exact_registration_without_context(
            &provider_failure,
            &store,
            &storage,
            &MutateEntrypointAfterInstallOperations {
                system: SystemBootstrapOperations,
                entrypoint: provider_failure.wine_entrypoint.clone(),
            },
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_revalidates_all_evidence_after_storage_preparation() {
        for kind in ["ref-raw", "wine", "wineserver-object", "manifest", "control-mode"] {
            let fixture = LinuxPublicProviderFixture::new();
            let store = fixture.directory.root.join(format!("storage-{kind}-store"));
            let storage = fixture.directory.root.join(format!("storage-{kind}"));
            let request = bootstrap_request(&fixture, &store, &storage);
            let owner = current_owner_identity().unwrap();
            let prepared = prepare_bootstrap(&fixture.host, &request, owner).expect("derive expected Pack paths");
            let mutation = match kind {
                "ref-raw" => {
                    StorageMutation::RefRaw(store.join("refs").join(LOCAL_PREVIEW_PACK_ID).join("current.json"))
                }
                "wine" => StorageMutation::File(fixture.wine_entrypoint.clone()),
                "wineserver-object" => StorageMutation::File(
                    store.join("objects/sha256").join(
                        prepared
                            .manifest
                            .components
                            .iter()
                            .find(|component| component.name == "wineserver-entrypoint")
                            .unwrap()
                            .digest
                            .trim_start_matches("sha256:"),
                    ),
                ),
                "manifest" => StorageMutation::File(store.join("manifests/sha256").join(format!(
                    "{}.json",
                    prepared.manifest.digest.trim_start_matches("sha256:")
                ))),
                "control-mode" => StorageMutation::ControlMode(store.join("objects")),
                _ => unreachable!(),
            };

            let result = validate_then_bootstrap(
                &fixture.host,
                &request,
                &SystemProbeCommand,
                &MutateRefDuringStorageOperations {
                    system: SystemBootstrapOperations,
                    mutation,
                },
            );

            assert!(result.is_err(), "{kind} must not return Context or receipt");
            assert!(storage.exists(), "Storage seam ran for {kind}");
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    enum ActiveRefMutation {
        Delete,
        WrongPack,
        History,
        RawFormatting,
    }

    #[cfg(target_os = "linux")]
    struct RefDeletingProbeCommand {
        system: SystemProbeCommand,
        calls: RefCell<usize>,
        mutate_after_call: usize,
        active_ref: PathBuf,
        mutation: ActiveRefMutation,
    }

    #[cfg(target_os = "linux")]
    struct ControlChmodProbeCommand {
        system: SystemProbeCommand,
        calls: RefCell<usize>,
        control: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl ProbeCommand for ControlChmodProbeCommand {
        fn run(&self, specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
            use std::os::unix::fs::PermissionsExt;

            let output = self.system.run(specification)?;
            let mut calls = self.calls.borrow_mut();
            *calls += 1;
            if *calls == 1 {
                fs::set_permissions(&self.control, fs::Permissions::from_mode(0o500))
                    .expect("malicious helper removes owner write from control");
            }
            Ok(output)
        }
    }

    #[cfg(target_os = "linux")]
    impl ProbeCommand for RefDeletingProbeCommand {
        fn run(&self, specification: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
            let output = self.system.run(specification)?;
            let mut calls = self.calls.borrow_mut();
            *calls += 1;
            if *calls == self.mutate_after_call {
                match self.mutation {
                    ActiveRefMutation::Delete => {
                        fs::remove_file(&self.active_ref).expect("malicious helper deletes active ref");
                    }
                    ActiveRefMutation::WrongPack | ActiveRefMutation::History => {
                        let mut value: serde_json::Value = serde_json::from_slice(
                            &fs::read(&self.active_ref).expect("malicious helper reads active ref"),
                        )
                        .unwrap();
                        if matches!(self.mutation, ActiveRefMutation::WrongPack) {
                            value["packId"] = serde_json::json!("wrong-pack");
                        } else {
                            value["history"] = serde_json::json!([value["activeDigest"].clone()]);
                        }
                        fs::write(&self.active_ref, serde_json::to_vec(&value).unwrap())
                            .expect("malicious helper replaces active ref");
                    }
                    ActiveRefMutation::RawFormatting => {
                        let mut raw = fs::read(&self.active_ref).expect("malicious helper reads active ref");
                        raw.extend_from_slice(b" \n");
                        fs::write(&self.active_ref, raw).expect("malicious helper reformats active ref");
                    }
                }
            }
            Ok(output)
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_detects_active_ref_deletion_during_either_probe_round() {
        for (label, mutate_after_call, seed_ref, mutation) in [
            ("first-delete", 1, true, ActiveRefMutation::Delete),
            ("second-wrong-pack", 3, false, ActiveRefMutation::WrongPack),
            ("second-history", 3, false, ActiveRefMutation::History),
            ("second-raw", 3, false, ActiveRefMutation::RawFormatting),
        ] {
            let fixture = LinuxPublicProviderFixture::new();
            let store = fixture.directory.root.join(format!("{label}-probe-ref-store"));
            let storage = fixture.directory.root.join(format!("{label}-probe-ref-storage"));
            let request = bootstrap_request(&fixture, &store, &storage);
            if seed_ref {
                create_local_context(&fixture.host, &request).expect("seed same-digest active ref");
            }
            let active_ref = store.join("refs").join(LOCAL_PREVIEW_PACK_ID).join("current.json");
            let command = RefDeletingProbeCommand {
                system: SystemProbeCommand,
                calls: RefCell::new(0),
                mutate_after_call,
                active_ref: active_ref.clone(),
                mutation,
            };

            let result = create_local_context_with(&fixture.host, &request, &command);

            assert!(result.is_err(), "{label} probe mutation must not return Context");
            assert_eq!(
                active_ref.exists(),
                !matches!(mutation, ActiveRefMutation::Delete),
                "malicious mutation occurred in {label} round"
            );
            if !seed_ref {
                assert!(!storage.exists(), "second-round mutation must not produce Storage");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_revalidates_control_permissions_after_first_probe_round() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("probe-chmod-store");
        let control = store.join("refs").join(LOCAL_PREVIEW_PACK_ID);
        fs::create_dir_all(&control).expect("create late control");
        let storage = fixture.directory.root.join("probe-chmod-storage");
        let request = bootstrap_request(&fixture, &store, &storage);
        let command = ControlChmodProbeCommand {
            system: SystemProbeCommand,
            calls: RefCell::new(0),
            control: control.clone(),
        };

        let result = create_local_context_with(&fixture.host, &request, &command);

        assert!(result.is_err());
        assert!(!storage.exists());
        assert_eq!(fs::metadata(control).unwrap().permissions().mode() & 0o777, 0o500);
        assert!(
            !store.join("objects").exists(),
            "Store mutation must not begin after chmod"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_same_digest_ref_with_wrong_pack_before_probe_or_mutation() {
        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("wrong-pack-ref-store");
        let storage = fixture.directory.root.join("wrong-pack-ref-storage");
        let request = bootstrap_request(&fixture, &store, &storage);
        create_local_context(&fixture.host, &request).expect("seed exact active ref");
        let active_ref = store.join("refs").join(LOCAL_PREVIEW_PACK_ID).join("current.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&active_ref).expect("read seeded active ref")).unwrap();
        value["packId"] = serde_json::json!("wrong-pack");
        fs::write(&active_ref, serde_json::to_vec_pretty(&value).unwrap()).expect("replace ref packId");
        let before = snapshot_tree(&fixture.directory.root);

        let result = create_local_context_with(&fixture.host, &request, &PanicProbeCommand);

        assert!(matches!(
            result,
            Err(LinuxBootstrapError::InvalidRequest("runtimeStoreRoot"))
        ));
        assert_eq!(snapshot_tree(&fixture.directory.root), before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_unsafe_store_control_paths() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        for control in ["objects", "manifests", "refs"] {
            for kind in ["symlink", "file", "wide"] {
                let fixture = LinuxPublicProviderFixture::new();
                let store = fixture.directory.root.join(format!("unsafe-{control}-{kind}"));
                let storage = fixture.directory.root.join("unsafe-storage");
                fs::create_dir(&store).expect("create unsafe Store root");
                let target = store.join(control);
                match kind {
                    "symlink" => {
                        let outside = fixture.directory.root.join("outside-control");
                        fs::create_dir(&outside).expect("create symlink target");
                        symlink(&outside, &target).expect("create Store control symlink");
                    }
                    "file" => fs::write(&target, b"not a directory").expect("create Store control file"),
                    "wide" => {
                        fs::create_dir(&target).expect("create wide Store control directory");
                        let mut permissions = fs::metadata(&target).unwrap().permissions();
                        permissions.set_mode(0o770);
                        fs::set_permissions(&target, permissions).unwrap();
                    }
                    _ => unreachable!(),
                }
                let request = bootstrap_request(&fixture, &store, &storage);
                let before = snapshot_tree(&fixture.directory.root);
                let result = create_local_context_with(&fixture.host, &request, &PanicProbeCommand);
                assert!(result.is_err(), "{control} {kind}");
                assert_eq!(snapshot_tree(&fixture.directory.root), before, "{control} {kind}");
                assert!(!storage.exists(), "{control} {kind}");
            }
        }

        let fixture = LinuxPublicProviderFixture::new();
        let store_target = fixture.directory.root.join("store-target");
        fs::create_dir(&store_target).expect("create Store symlink target");
        let store_alias = fixture.directory.root.join("store-alias");
        symlink(&store_target, &store_alias).expect("create Store root symlink");
        let storage = fixture.directory.root.join("store-alias-storage");
        let request = bootstrap_request(&fixture, &store_alias, &storage);
        let before = snapshot_tree(&fixture.directory.root);
        assert!(create_local_context_with(&fixture.host, &request, &PanicProbeCommand).is_err());
        assert_eq!(snapshot_tree(&fixture.directory.root), before);

        let missing_materialized = fixture.directory.root.join("missing-materialized");
        let mut request = bootstrap_request(
            &fixture,
            &fixture.directory.root.join("missing-root-store"),
            &fixture.directory.root.join("missing-root-storage"),
        );
        request.materialized_root = missing_materialized.to_string_lossy().into_owned();
        let before = snapshot_tree(&fixture.directory.root);
        assert!(create_local_context_with(&fixture.host, &request, &PanicProbeCommand).is_err());
        assert_eq!(snapshot_tree(&fixture.directory.root), before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_every_non_owner_writable_control_before_probe_or_mkdir() {
        use std::os::unix::fs::PermissionsExt;

        let controls = [
            "",
            "objects",
            "objects/sha256",
            "manifests",
            "manifests/sha256",
            "refs",
            "refs/wine-linux-x86-64-local-preview",
        ];
        for control in controls {
            for mode in [0o500, 0o555] {
                let fixture = LinuxPublicProviderFixture::new();
                let store = fixture
                    .directory
                    .root
                    .join(format!("control-{}-{mode:o}", control.replace('/', "-")));
                fs::create_dir_all(store.join(control)).expect("create selected control");
                fs::set_permissions(store.join(control), fs::Permissions::from_mode(mode))
                    .expect("remove owner write from selected control");
                let storage = fixture.directory.root.join("control-storage");
                let request = bootstrap_request(&fixture, &store, &storage);
                let before = snapshot_tree(&fixture.directory.root);

                assert!(
                    create_local_context_with(&fixture.host, &request, &PanicProbeCommand).is_err(),
                    "{control} {mode:o}"
                );
                assert_eq!(snapshot_tree(&fixture.directory.root), before, "{control} {mode:o}");
                assert!(!storage.exists());
            }
        }

        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("missing-early-control");
        let late = store.join("refs").join(LOCAL_PREVIEW_PACK_ID);
        fs::create_dir_all(&late).expect("create only a later control");
        fs::set_permissions(&late, fs::Permissions::from_mode(0o500)).unwrap();
        let storage = fixture.directory.root.join("missing-early-storage");
        let request = bootstrap_request(&fixture, &store, &storage);
        let before = snapshot_tree(&fixture.directory.root);
        assert!(create_local_context_with(&fixture.host, &request, &PanicProbeCommand).is_err());
        assert_eq!(snapshot_tree(&fixture.directory.root), before);
        assert!(
            !store.join("objects").exists(),
            "preflight must not fill earlier controls"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_non_serializable_canonical_storage_before_mutation() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        for (label, target_name) in [
            ("non-utf8", OsString::from_vec(b"storage-\xff".to_vec())),
            ("backslash", OsString::from("storage\\private")),
        ] {
            let fixture = LinuxPublicProviderFixture::new();
            let target = fixture.directory.root.join(target_name);
            fs::create_dir(&target).expect("create private storage target");
            let storage_alias = fixture.directory.root.join(format!("{label}-storage-alias"));
            symlink(&target, &storage_alias).expect("create storage alias");
            let store = fixture.directory.root.join(format!("{label}-bootstrap-store"));
            let request = bootstrap_request(&fixture, &store, &storage_alias);
            let before = snapshot_tree(&fixture.directory.root);

            assert_eq!(
                create_local_context(&fixture.host, &request),
                Err(LinuxBootstrapError::InvalidRequest("storageRoot")),
                "{label}"
            );
            assert_eq!(snapshot_tree(&fixture.directory.root), before, "{label}");
            assert!(!store.exists(), "{label}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_non_writable_storage_and_writable_store_files_before_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = LinuxPublicProviderFixture::new();
        let store = fixture.directory.root.join("permission-store");
        let storage = fixture.directory.root.join("permission-storage");
        fs::create_dir(&storage).expect("create storage");
        fs::set_permissions(&storage, fs::Permissions::from_mode(0o500)).expect("make storage non-writable");
        let request = bootstrap_request(&fixture, &store, &storage);
        let before = snapshot_tree(&fixture.directory.root);
        assert!(create_local_context(&fixture.host, &request).is_err());
        assert_eq!(snapshot_tree(&fixture.directory.root), before);
        assert!(!store.exists());

        for artifact in ["ref", "object", "manifest"] {
            let fixture = LinuxPublicProviderFixture::new();
            let store = fixture.directory.root.join(format!("writable-{artifact}-store"));
            let storage = fixture.directory.root.join(format!("writable-{artifact}-storage"));
            let request = bootstrap_request(&fixture, &store, &storage);
            let local = create_local_context(&fixture.host, &request).expect("seed exact bootstrap");
            let path = match artifact {
                "ref" => store.join("refs").join(LOCAL_PREVIEW_PACK_ID).join("current.json"),
                "object" => store
                    .join("objects/sha256")
                    .join(fixture.config.wine_runtime.wine.digest.trim_start_matches("sha256:")),
                "manifest" => store.join("manifests/sha256").join(format!(
                    "{}.json",
                    local.receipt.pack_digest.trim_start_matches("sha256:")
                )),
                _ => unreachable!(),
            };
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("make Store file writable");
            let before = snapshot_tree(&fixture.directory.root);
            assert!(create_local_context(&fixture.host, &request).is_err(), "{artifact}");
            assert_eq!(snapshot_tree(&fixture.directory.root), before, "{artifact}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_non_serializable_canonical_entrypoints_before_mutation() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        for field in ["wine", "wineserver"] {
            for (label, target_name) in [
                (
                    "non-utf8",
                    OsString::from_vec(format!("{field}-").into_bytes().into_iter().chain([0xff]).collect()),
                ),
                ("backslash", OsString::from(format!("{field}\\private"))),
                ("carriage-return", OsString::from(format!("{field}\rprivate"))),
                ("line-feed", OsString::from(format!("{field}\nprivate"))),
            ] {
                let fixture = LinuxPublicProviderFixture::new();
                let (entrypoint, relative) = if field == "wine" {
                    (&fixture.wine_entrypoint, fixture.config.wine_runtime.wine.path.clone())
                } else {
                    (
                        &fixture.wineserver_entrypoint,
                        fixture.config.wine_runtime.wineserver.path.clone(),
                    )
                };
                let target = entrypoint.parent().unwrap().join(target_name);
                fs::rename(entrypoint, &target).expect("move entrypoint to non-serializable target");
                symlink(&target, entrypoint).expect("restore requested entrypoint as symlink");
                let store = fixture.directory.root.join(format!("{field}-{label}-bootstrap-store"));
                let storage = fixture
                    .directory
                    .root
                    .join(format!("{field}-{label}-bootstrap-storage"));
                let mut request = bootstrap_request(&fixture, &store, &storage);
                if field == "wine" {
                    request.wine = relative;
                } else {
                    request.wineserver = relative;
                }
                let before = snapshot_tree(&fixture.directory.root);

                assert_eq!(
                    create_local_context(&fixture.host, &request),
                    Err(LinuxBootstrapError::InvalidRequest(if field == "wine" {
                        "wine canonical path"
                    } else {
                        "wineserver canonical path"
                    })),
                    "{field} {label}"
                );
                assert_eq!(snapshot_tree(&fixture.directory.root), before, "{field} {label}");
                assert!(!store.exists(), "{field} {label}");
                assert!(!storage.exists(), "{field} {label}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_rejects_every_physical_root_overlap_without_mutation() {
        use std::os::unix::fs::symlink;

        let relationships = [
            ("store-storage-equal", "shared", "shared", "runtime"),
            ("store-storage-store-parent", "shared", "shared/storage", "runtime"),
            ("store-storage-storage-parent", "shared/store", "shared", "runtime"),
            ("store-runtime-equal", "shared", "storage", "shared"),
            ("store-runtime-store-parent", "shared", "storage", "shared/runtime"),
            ("store-runtime-runtime-parent", "shared/store", "storage", "shared"),
            ("storage-runtime-equal", "store", "shared", "shared"),
            ("storage-runtime-storage-parent", "store", "shared", "shared/runtime"),
            ("storage-runtime-runtime-parent", "store", "shared/runtime", "shared"),
        ];
        for (label, store_relative, storage_relative, runtime_relative) in relationships {
            let case = DirectoryFixture::new(label);
            let store = case.root.join(store_relative);
            let storage = case.root.join(storage_relative);
            let runtime = case.root.join(runtime_relative);
            for path in [&store, &storage, &runtime] {
                fs::create_dir_all(path).expect("create overlap root");
            }
            let request = LinuxLocalContextRequest {
                schema_version: SCHEMA_VERSION_V1.into(),
                runtime_store_root: store.to_string_lossy().into_owned(),
                storage_root: storage.to_string_lossy().into_owned(),
                materialized_root: runtime.to_string_lossy().into_owned(),
                wine: "bin/wine".into(),
                wineserver: "bin/wineserver".into(),
                version: "9.0".into(),
            };
            let before = snapshot_tree(&case.root);
            assert!(
                create_local_context_with(&linux_host_report(), &request, &PanicProbeCommand).is_err(),
                "{label}"
            );
            assert_eq!(snapshot_tree(&case.root), before, "{label}");
        }

        let case = DirectoryFixture::new("lexical-overlap");
        let runtime = case.root.join("runtime");
        fs::create_dir(&runtime).expect("create lexical Runtime root");
        for (label, store, storage) in [
            ("dot-dot", case.root.join("store/../store"), case.root.join("storage")),
            ("dot", case.root.join("store"), case.root.join("storage/./nested")),
        ] {
            let request = LinuxLocalContextRequest {
                schema_version: SCHEMA_VERSION_V1.into(),
                runtime_store_root: store.to_string_lossy().into_owned(),
                storage_root: storage.to_string_lossy().into_owned(),
                materialized_root: runtime.to_string_lossy().into_owned(),
                wine: "bin/wine".into(),
                wineserver: "bin/wineserver".into(),
                version: "9.0".into(),
            };
            let before = snapshot_tree(&case.root);
            assert!(
                create_local_context_with(&linux_host_report(), &request, &PanicProbeCommand).is_err(),
                "{label}"
            );
            assert_eq!(snapshot_tree(&case.root), before, "{label}");
        }

        for alias_pair in ["store-storage", "store-materialized", "storage-materialized"] {
            let case = DirectoryFixture::new(alias_pair);
            let target = case.root.join("physical");
            fs::create_dir(&target).expect("create symlink alias target");
            let alias = case.root.join("alias");
            symlink(&target, &alias).expect("create root alias");
            let other = case.root.join("other");
            fs::create_dir(&other).expect("create disjoint root");
            let (store, storage, materialized) = match alias_pair {
                "store-storage" => (target, alias, other),
                "store-materialized" => (target, other, alias),
                "storage-materialized" => (other, target, alias),
                _ => unreachable!(),
            };
            let request = LinuxLocalContextRequest {
                schema_version: SCHEMA_VERSION_V1.into(),
                runtime_store_root: store.to_string_lossy().into_owned(),
                storage_root: storage.to_string_lossy().into_owned(),
                materialized_root: materialized.to_string_lossy().into_owned(),
                wine: "bin/wine".into(),
                wineserver: "bin/wineserver".into(),
                version: "9.0".into(),
            };
            let before = snapshot_tree(&case.root);
            assert!(create_local_context_with(&linux_host_report(), &request, &PanicProbeCommand).is_err());
            assert_eq!(snapshot_tree(&case.root), before);
        }
    }
}
