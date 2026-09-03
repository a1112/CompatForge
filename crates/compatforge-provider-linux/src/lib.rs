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
    ContractError, CoreConfig, CpuArchitecture, HostOs, ProviderDescriptor, RuntimeBinding, RuntimePackManifest,
};
use compatforge_runtime::RuntimePackStore;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File},
    io::Read,
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
            storage_root: canonical_storage.to_string_lossy().into_owned(),
            sandbox_profile: compatforge_domain::SandboxProfile::Desktop,
            supervisor: compatforge_domain::SupervisorPolicy::default(),
        };
        config.validate()?;
        Ok(config)
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
    let Some(wine) = evidence.observation.wine.to_str().map(str::to_owned) else {
        return unavailable_provider_snapshot(host_report, config, EvidenceFailure::Entrypoint);
    };
    let Some(wineserver) = evidence.observation.wineserver.to_str().map(str::to_owned) else {
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
}
