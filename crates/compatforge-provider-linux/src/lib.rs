//! Linux x86_64 Wine Provider contracts.

#![deny(unsafe_op_in_unsafe_fn)]

mod elf;

use compatforge_domain::{
    validate_digest, validate_id, validate_portable_relative_path, validate_schema_version, ContractError, CoreConfig,
    CpuArchitecture,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
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
        }
    }
}

impl std::error::Error for LinuxProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::InvalidConfig(_) | Self::InvalidRequest(_) => None,
        }
    }
}

impl From<ContractError> for LinuxProviderError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
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
