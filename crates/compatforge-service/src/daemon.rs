//! Per-user service transport, distinct from the EOF-owned api-session v1.

use crate::ServiceResponse;
#[cfg(any(target_os = "linux", test))]
use crate::{AutomationService, ServiceRequest};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
#[cfg(any(target_os = "linux", test))]
use std::sync::atomic::{AtomicBool, Ordering};

pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CONNECTIONS: usize = 8;
pub const SOCKET_NAME: &str = "service.sock";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonReply {
    pub schema_version: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ServiceResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DaemonError>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonError {
    pub code: String,
    pub message: String,
}

pub fn write_frame(writer: &mut impl Write, bytes: &[u8], maximum: usize) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() > u32::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame length"));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

pub fn read_frame(reader: &mut impl Read, maximum: usize) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame length"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(any(target_os = "linux", test))]
fn dispatch(service: &AutomationService, request: ServiceRequest, stop: &AtomicBool) -> DaemonReply {
    let id = request.request_id.clone();
    let result = if stop.load(Ordering::Acquire) {
        Err(("closing", "service is closing".into()))
    } else if let Err(error) = request.validate() {
        Err(("invalid-request", error.to_string()))
    } else if request.operation == "daemon.stop" {
        if request.payload != serde_json::json!({}) {
            Err(("invalid-request", "daemon.stop requires an empty object".into()))
        } else {
            stop.store(true, Ordering::Release);
            Ok(ServiceResponse {
                schema_version: "1".into(),
                request_id: id.clone(),
                operation: request.operation,
                result: serde_json::json!({"stopping":true}),
            })
        }
    } else {
        service.call(request).map_err(|error| (error.code(), error.to_string()))
    };
    match result {
        Ok(response) => DaemonReply {
            schema_version: "1".into(),
            request_id: id,
            response: Some(response),
            error: None,
        },
        Err((code, message)) => DaemonReply {
            schema_version: "1".into(),
            request_id: id,
            response: None,
            error: Some(DaemonError {
                code: code.into(),
                message: message.chars().take(1000).collect(),
            }),
        },
    }
}

#[cfg(any(target_os = "linux", test))]
fn shutdown_reply(mut reply: DaemonReply, failure: Option<&str>) -> DaemonReply {
    match failure {
        Some(message) => {
            reply.response = None;
            reply.error = Some(DaemonError {
                code: "cleanup-failed".into(),
                message: message.chars().take(1000).collect(),
            });
        }
        None => {
            if let Some(response) = &mut reply.response {
                response.result = serde_json::json!({"stopped": true});
            }
        }
    }
    reply
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{request, run, runtime_directory};

#[cfg(not(target_os = "linux"))]
pub fn runtime_directory() -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "shared service requires Linux peer credentials",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn length_prefix_rejects_large_frames_before_reading_payload() {
        let mut reader = Cursor::new([0, 0, 0, 5, 1, 2, 3, 4, 5]);
        assert_eq!(
            read_frame(&mut reader, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(reader.position(), 4);
        let mut bytes = Vec::new();
        assert!(write_frame(&mut bytes, b"large", 4).is_err());
        assert!(bytes.is_empty());
    }

    #[test]
    fn frames_preserve_unicode_and_reject_truncation() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, "中文".as_bytes(), 100).unwrap();
        let mut input = Cursor::new(bytes.clone());
        assert_eq!(read_frame(&mut input, 100).unwrap(), "中文".as_bytes());
        bytes.pop();
        assert_eq!(
            read_frame(&mut Cursor::new(bytes), 100).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn stop_acknowledgement_reports_cleanup_failure_and_only_then_success() {
        let reply = || DaemonReply {
            schema_version: "1".into(),
            request_id: "stop".into(),
            response: Some(ServiceResponse {
                schema_version: "1".into(),
                request_id: "stop".into(),
                operation: "daemon.stop".into(),
                result: serde_json::json!({"stopping":true}),
            }),
            error: None,
        };
        let failed = shutdown_reply(reply(), Some("process still owned"));
        assert!(failed.response.is_none());
        assert_eq!(failed.error.unwrap().code, "cleanup-failed");
        assert_eq!(
            shutdown_reply(reply(), None).response.unwrap().result,
            serde_json::json!({"stopped":true})
        );
    }

    #[test]
    fn request_error_is_recoverable_and_only_valid_stop_closes_admission() {
        let root = std::env::temp_dir().join(format!(
            "cf-daemon-dispatch-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut config: compatforge_domain::CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        config.storage_root = root.join("storage").to_string_lossy().into_owned();
        let service = AutomationService::new(
            config,
            crate::ServiceConfig {
                schema_version: "1".into(),
                service_root: root.join("service").to_string_lossy().into_owned(),
            },
        )
        .unwrap();
        let stop = AtomicBool::new(false);
        let call = |operation: &str, payload: serde_json::Value| ServiceRequest {
            schema_version: "1".into(),
            request_id: "desktop-1".into(),
            operation: operation.into(),
            payload,
        };
        assert_eq!(
            dispatch(&service, call("missing.operation", serde_json::json!({})), &stop)
                .error
                .unwrap()
                .code,
            "not-found"
        );
        assert!(
            dispatch(&service, call("applications.list", serde_json::json!({})), &stop)
                .response
                .is_some()
        );
        assert!(
            dispatch(&service, call("daemon.stop", serde_json::json!({"extra":true})), &stop)
                .error
                .is_some()
        );
        assert!(!stop.load(Ordering::Acquire));
        assert!(dispatch(&service, call("daemon.stop", serde_json::json!({})), &stop)
            .response
            .is_some());
        assert!(stop.load(Ordering::Acquire));
        assert_eq!(
            dispatch(&service, call("applications.list", serde_json::json!({})), &stop)
                .error
                .unwrap()
                .code,
            "closing"
        );
        service.shutdown_and_wait().unwrap();
    }
}
