//! Protocol v2 binds admission and replies to the daemon on one connection.
//! Identity is package/source provenance, not an authorization credential.
use crate::{negotiate, ContractError, ErrorCode, ProviderInfo, ProviderRequirements};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const WIRE_VERSION: &str = "2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonIdentity {
    pub schema_version: String,
    pub instance_id: String,
    pub provider: ProviderInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientHello {
    pub schema_version: String,
    pub request_id: String,
    pub required_provider: ProviderRequirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerHello {
    pub schema_version: String,
    pub request_id: String,
    pub daemon: DaemonIdentity,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundDaemonRequest<T> {
    pub schema_version: String,
    pub daemon_instance_id: String,
    pub request: T,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundInvocation<T> {
    pub schema_version: String,
    pub required_provider: ProviderRequirements,
    pub request: T,
}

impl<T> BoundInvocation<T> {
    /// Must run in the actual CLI execution before runtime/daemon initialization.
    pub fn validate_executor(&self, executor: &ProviderInfo) -> Result<(), ContractError> {
        if self.schema_version != WIRE_VERSION {
            return Err(schema("service-call requires a bound invocation v2"));
        }
        negotiate_v2(executor, &self.required_provider)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReply<T> {
    pub schema_version: String,
    pub request_id: String,
    pub operation: String,
    pub executor: ProviderInfo,
    pub daemon: DaemonIdentity,
    pub result: T,
}

fn schema(message: &str) -> ContractError {
    ContractError::new(ErrorCode::SchemaMismatch, message)
}

fn negotiate_v2(info: &ProviderInfo, required: &ProviderRequirements) -> Result<(), ContractError> {
    crate::validate(&info.identity())?;
    crate::validate(required)?;
    if info.contract_version != crate::CONTRACT_VERSION || required.contract_version != crate::CONTRACT_VERSION {
        return Err(ContractError::new(
            ErrorCode::UnsupportedVersion,
            "bound execution requires provider contract 2.0.0",
        ));
    }
    negotiate(info, required)
}

pub fn correlation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'))
}

pub fn validate_identity(value: &DaemonIdentity, required: &ProviderRequirements) -> Result<(), ContractError> {
    if value.schema_version != WIRE_VERSION || !correlation(&value.instance_id) {
        return Err(schema("daemon identity requires wire v2 and a bounded instance ID"));
    }
    negotiate_v2(&value.provider, required)
}

impl ClientHello {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != WIRE_VERSION || !correlation(&self.request_id) {
            return Err(schema("daemon admission requires a v2 hello and bounded request ID"));
        }
        // Validate the caller's lock shape without treating it as daemon identity.
        crate::decode_requirements(&serde_json::to_vec(&self.required_provider).map_err(|_| schema("invalid lock"))?)?;
        Ok(())
    }
}

impl ServerHello {
    pub fn validate(&self, hello: &ClientHello) -> Result<(), ContractError> {
        hello.validate()?;
        if self.schema_version != WIRE_VERSION || self.request_id != hello.request_id {
            return Err(schema("daemon hello version or request identity differs"));
        }
        validate_identity(&self.daemon, &hello.required_provider)
    }
}

/// Called before dispatch, against the process's immutable identity and same hello.
pub fn admit(
    schema_version: &str,
    instance_id: &str,
    request_id: &str,
    hello: &ClientHello,
    daemon: &DaemonIdentity,
) -> Result<(), ContractError> {
    hello.validate()?;
    validate_identity(daemon, &hello.required_provider)?;
    if schema_version != WIRE_VERSION || instance_id != daemon.instance_id || request_id != hello.request_id {
        return Err(ContractError::new(
            ErrorCode::SourceMismatch,
            "request is not bound to this daemon connection/instance",
        ));
    }
    Ok(())
}

pub fn validate_response_identity(
    actual: &DaemonIdentity,
    admitted: &DaemonIdentity,
    required: &ProviderRequirements,
) -> Result<(), ContractError> {
    validate_identity(actual, required)?;
    if actual != admitted {
        return Err(ContractError::new(
            ErrorCode::SourceMismatch,
            "daemon reply identity changed after admission",
        ));
    }
    Ok(())
}

pub fn decode_execution(
    raw: &[u8],
    maximum: usize,
    required: &ProviderRequirements,
    request_id: &str,
    operation: &str,
) -> Result<Value, ContractError> {
    if raw.len() > maximum {
        return Err(schema("bound execution reply exceeds byte limit"));
    }
    let value: ExecutionReply<Value> = serde_json::from_slice(raw)
        .map_err(|_| schema("missing, malformed or legacy unbound execution reply; expected wire v2"))?;
    if value.schema_version != WIRE_VERSION
        || value.request_id != request_id
        || value.operation != operation
        || !correlation(request_id)
    {
        return Err(schema("bound execution reply version/request/operation differs"));
    }
    negotiate_v2(&value.executor, required)?;
    validate_identity(&value.daemon, required)?;
    Ok(value.result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (ProviderInfo, ClientHello, DaemonIdentity) {
        let vectors: Value = serde_json::from_str(include_str!("../../../contracts/provider-vectors-v1.json")).unwrap();
        let provider = crate::decode_info(&serde_json::to_vec(&vectors["report"]).unwrap()).unwrap();
        let hello = ClientHello {
            schema_version: WIRE_VERSION.into(),
            request_id: "request-1".into(),
            required_provider: provider.identity(),
        };
        let daemon = DaemonIdentity {
            schema_version: WIRE_VERSION.into(),
            instance_id: "instance-1".into(),
            provider: provider.clone(),
        };
        (provider, hello, daemon)
    }
    #[test]
    fn wrong_daemon_and_restart_are_rejected_before_admission() {
        let (_, hello, daemon) = fixture();
        admit("2", "instance-1", "request-1", &hello, &daemon).unwrap();
        for field in ["source", "version", "capability"] {
            let mut wrong = daemon.clone();
            match field {
                "source" => wrong.provider.source_commit = "f".repeat(40),
                "version" => wrong.provider.contract_version = "0.0.0".into(),
                _ => wrong.provider.capabilities.clear(),
            }
            assert!(admit("2", "instance-1", "request-1", &hello, &wrong).is_err());
        }
        assert!(admit("2", "instance-before-restart", "request-1", &hello, &daemon).is_err());
        let mut restarted = daemon.clone();
        restarted.instance_id = "instance-2".into();
        assert!(validate_response_identity(&restarted, &daemon, &hello.required_provider).is_err());
    }
    #[test]
    fn legacy_response_replacement_executor_and_foreign_daemon_cannot_supply_results() {
        let (provider, hello, daemon) = fixture();
        let mut value = json!({"schemaVersion":"2","requestId":"request-1","operation":"applications.list",
            "executor":provider,"daemon":daemon,"result":[]});
        let decode = |value: &Value| {
            decode_execution(
                &serde_json::to_vec(value).unwrap(),
                1024 * 1024,
                &hello.required_provider,
                "request-1",
                "applications.list",
            )
        };
        assert_eq!(decode(&value).unwrap(), json!([]));
        let valid = value.clone();
        value["executor"]["sourceCommit"] = json!("f".repeat(40));
        assert_eq!(decode(&value).unwrap_err().code, ErrorCode::SourceMismatch);
        value = valid;
        value["daemon"]["provider"]["sourceCommit"] = json!("f".repeat(40));
        assert_eq!(decode(&value).unwrap_err().code, ErrorCode::SourceMismatch);
        assert!(decode(
            &json!({"schemaVersion":"1","requestId":"request-1","operation":"applications.list","result":[]})
        )
        .is_err());
    }
    #[test]
    fn replacement_executor_cannot_admit_the_bound_invocation() {
        let (provider, hello, _) = fixture();
        let invocation = BoundInvocation {
            schema_version: WIRE_VERSION.into(),
            required_provider: hello.required_provider,
            request: json!({"operation":"jobs.submit"}),
        };
        invocation.validate_executor(&provider).unwrap();
        let mut replaced = provider.clone();
        replaced.source_commit = "f".repeat(40);
        assert_eq!(
            invocation.validate_executor(&replaced).unwrap_err().code,
            ErrorCode::SourceMismatch
        );
    }
}
