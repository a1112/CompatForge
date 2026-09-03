//! Linux x86_64 Wine Provider contracts.

#![deny(unsafe_op_in_unsafe_fn)]

use compatforge_domain::{
    validate_digest, validate_id, validate_portable_relative_path, validate_schema_version, ContractError, CoreConfig,
    CpuArchitecture,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::fmt;

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
}
