//! Versioned CLI protocol negotiation, independent of the compatibility engine.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const CONTRACT_VERSION: &str = "2.0.0";
pub const MAX_CONTRACT_BYTES: usize = 64 * 1024;
pub mod binding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ProviderUnavailable,
    SchemaMismatch,
    UnsupportedVersion,
    CapabilityMissing,
    SourceMismatch,
}

impl ErrorCode {
    /// Explicit adapter to the independent R-SDK interop v1 error vocabulary.
    pub fn public_code(self) -> &'static str {
        match self {
            Self::ProviderUnavailable | Self::CapabilityMissing => "CAPABILITY_UNAVAILABLE",
            Self::SchemaMismatch => "SCHEMA_INVALID",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::SourceMismatch => "BINDING_MISMATCH",
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider-unavailable",
            Self::SchemaMismatch => "schema-mismatch",
            Self::UnsupportedVersion => "unsupported-version",
            Self::CapabilityMissing => "capability-missing",
            Self::SourceMismatch => "source-mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub code: ErrorCode,
    pub message: String,
}

impl ContractError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "forge.provider.{}: {}", self.code.as_str(), self.message)
    }
}
impl std::error::Error for ContractError {}

// serde's ordinary map reader accepts duplicate keys. Protocol identities must
// have one interpretation in both the Rust and Python adapters.
fn unique_map<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map with unique protocol names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.len() >= 64 || result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate or oversized protocol map"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Visitor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderInfo {
    pub schema_version: String,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub source_commit: String,
    pub source_dirty: bool,
    pub target: String,
    pub service_name: String,
    #[serde(deserialize_with = "unique_map")]
    pub commands: BTreeMap<String, String>,
    #[serde(deserialize_with = "unique_map")]
    pub schemas: BTreeMap<String, String>,
    pub capabilities: Vec<String>,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRequirements {
    pub schema_version: String,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub source_commit: String,
    pub target: String,
    pub service_name: String,
    #[serde(deserialize_with = "unique_map")]
    pub commands: BTreeMap<String, String>,
    #[serde(deserialize_with = "unique_map")]
    pub schemas: BTreeMap<String, String>,
    pub capabilities: Vec<String>,
    pub operations: Vec<String>,
}

impl ProviderInfo {
    pub fn identity(&self) -> ProviderRequirements {
        ProviderRequirements {
            schema_version: self.schema_version.clone(),
            contract_version: self.contract_version.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version.clone(),
            source_commit: self.source_commit.clone(),
            target: self.target.clone(),
            service_name: self.service_name.clone(),
            commands: self.commands.clone(),
            schemas: self.schemas.clone(),
            capabilities: self.capabilities.clone(),
            operations: self.operations.clone(),
        }
    }
}

fn schema(message: impl Into<String>) -> ContractError {
    ContractError::new(ErrorCode::SchemaMismatch, message)
}

fn token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'_'))
}

fn version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 9
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
        })
}

fn validate(value: &ProviderRequirements) -> Result<(), ContractError> {
    if value.schema_version != "1"
        || !version(&value.contract_version)
        || !version(&value.provider_version)
        || !token(&value.provider_id, 64)
        || !token(&value.target, 80)
        || !(value.service_name.is_empty() || token(&value.service_name, 80))
        || value.source_commit.len() != 40
        || !value
            .source_commit
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(schema(
            "invalid provider identity or schemaVersion; expected provider contract v1",
        ));
    }
    for map in [&value.commands, &value.schemas] {
        if map.len() > 64
            || map.iter().any(|(name, major)| {
                !token(name, 64)
                    || major.is_empty()
                    || major.len() > 4
                    || major.starts_with('0')
                    || !major.bytes().all(|b| b.is_ascii_digit())
            })
        {
            return Err(schema("invalid bounded command/schema version map"));
        }
    }
    for list in [&value.capabilities, &value.operations] {
        if list.len() > 64 || list.iter().any(|name| !token(name, 80)) || list.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(schema("capabilities/operations must be bounded, sorted and unique"));
        }
    }
    Ok(())
}

fn bounded<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, ContractError> {
    if raw.len() > MAX_CONTRACT_BYTES {
        return Err(schema("provider contract exceeds 64 KiB"));
    }
    serde_json::from_slice(raw)
        .map_err(|_| schema("provider contract is malformed, has duplicate/unknown fields or wrong types"))
}

pub fn decode_info(raw: &[u8]) -> Result<ProviderInfo, ContractError> {
    let value: ProviderInfo = bounded(raw)?;
    validate(&value.identity())?;
    Ok(value)
}

pub fn decode_requirements(raw: &[u8]) -> Result<ProviderRequirements, ContractError> {
    let value = bounded(raw)?;
    validate(&value)?;
    Ok(value)
}

pub fn negotiate(info: &ProviderInfo, required: &ProviderRequirements) -> Result<(), ContractError> {
    validate(&info.identity())?;
    validate(required)?;
    if info.contract_version != required.contract_version || info.provider_version != required.provider_version {
        return Err(ContractError::new(
            ErrorCode::UnsupportedVersion,
            format!(
                "expected contract {} / provider {}, got {} / {}",
                required.contract_version, required.provider_version, info.contract_version, info.provider_version
            ),
        ));
    }
    if info.source_dirty || info.source_commit != required.source_commit {
        return Err(ContractError::new(
            ErrorCode::SourceMismatch,
            format!("expected clean provider source {}", required.source_commit),
        ));
    }
    if info.provider_id != required.provider_id
        || info.target != required.target
        || info.service_name != required.service_name
    {
        return Err(ContractError::new(
            ErrorCode::CapabilityMissing,
            "provider, target or service differs from composition lock",
        ));
    }
    for (command, major) in &required.commands {
        if info.commands.get(command) != Some(major) {
            return Err(ContractError::new(
                ErrorCode::CapabilityMissing,
                format!("required CLI {command} v{major} is unavailable"),
            ));
        }
    }
    for (name, major) in &required.schemas {
        if info.schemas.get(name) != Some(major) {
            return Err(schema(format!(
                "required schema {name} v{major} is unavailable or incompatible"
            )));
        }
    }
    for (list, names) in [
        (&info.capabilities, &required.capabilities),
        (&info.operations, &required.operations),
    ] {
        for name in names {
            if !list.contains(name) {
                return Err(ContractError::new(
                    ErrorCode::CapabilityMissing,
                    format!("required capability/operation {name} is unavailable"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    #[test]
    fn raw_wire_vectors_have_identical_utf8_only_semantics() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../contracts/provider-raw-vectors-v1.json")).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let hex = case["rawHex"].as_str().unwrap().as_bytes();
            let raw: Vec<u8> = hex
                .chunks_exact(2)
                .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
                .collect();
            let result = decode_info(&raw);
            assert_eq!(result.is_ok(), case["accepted"].as_bool().unwrap(), "{}", case["name"]);
            if let Err(error) = result {
                assert_eq!(error.code, ErrorCode::SchemaMismatch);
            }
        }
    }
    #[test]
    fn public_adapter_preserves_independent_interop_v1_error_semantics() {
        for (domain, public) in [
            (ErrorCode::ProviderUnavailable, "CAPABILITY_UNAVAILABLE"),
            (ErrorCode::CapabilityMissing, "CAPABILITY_UNAVAILABLE"),
            (ErrorCode::SchemaMismatch, "SCHEMA_INVALID"),
            (ErrorCode::UnsupportedVersion, "UNSUPPORTED_VERSION"),
            (ErrorCode::SourceMismatch, "BINDING_MISMATCH"),
        ] {
            assert_eq!(domain.public_code(), public);
        }
    }
    #[test]
    fn shared_vectors_reject_incompatible_provider() {
        let vectors: Value = serde_json::from_str(include_str!("../../../contracts/provider-vectors-v1.json")).unwrap();
        let required = decode_requirements(&serde_json::to_vec(&vectors["requirements"]).unwrap()).unwrap();
        let report = decode_info(&serde_json::to_vec(&vectors["report"]).unwrap()).unwrap();
        negotiate(&report, &required).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let mut report = vectors["report"].clone();
            report[case["field"].as_str().unwrap()] = case["value"].clone();
            let result =
                decode_info(&serde_json::to_vec(&report).unwrap()).and_then(|info| negotiate(&info, &required));
            assert_eq!(
                result.unwrap_err().code.as_str(),
                case["code"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
    #[test]
    fn rejects_duplicate_nested_keys_and_oversized_reports() {
        let vectors: Value = serde_json::from_str(include_str!("../../../contracts/provider-vectors-v1.json")).unwrap();
        let raw = serde_json::to_string(&vectors["report"]).unwrap().replace(
            "\"service-call\":\"2\"",
            "\"service-call\":\"2\",\"service-call\":\"2\"",
        );
        assert!(decode_info(raw.as_bytes()).is_err());
        assert!(decode_info(&vec![b' '; MAX_CONTRACT_BYTES + 1]).is_err());
        let mut bad = vectors["requirements"].clone();
        bad["sourceDirty"] = json!(false);
        assert!(decode_requirements(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
