//! Bounded debug-session contract. Runtime provider implementation follows in Task 6.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub const MAX_DEBUG_REQUEST_BYTES: usize = 64 * 1024;
const MAX_SESSIONS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebugError {
    InvalidRequest,
    InvalidTarget,
    DigestMismatch,
    Unauthorized,
    InvalidTransition,
    Unavailable,
    Capacity,
    BackendFailed,
}

impl fmt::Display for DebugError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InvalidRequest => "invalid debug request",
                Self::InvalidTarget => "invalid managed debug target",
                Self::DigestMismatch => "debugger digest mismatch",
                Self::Unauthorized => "debug session handle is not authorized",
                Self::InvalidTransition => "invalid debug session state transition",
                Self::Unavailable => "debugger provider is not installed or verified",
                Self::Capacity => "maximum debug sessions reached",
                Self::BackendFailed => "debugger backend failed",
            }
        )
    }
}

impl std::error::Error for DebugError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugTarget {
    pub application_id: String,
    pub generation_id: String,
    pub launcher_id: String,
}

impl DebugTarget {
    pub fn validate(&self) -> Result<(), DebugError> {
        fn id(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= 96
                && value
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        }
        if id(&self.application_id)
            && self.generation_id.starts_with("gen-")
            && id(&self.generation_id)
            && id(&self.launcher_id)
        {
            Ok(())
        } else {
            Err(DebugError::InvalidTarget)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugSessionHandle {
    pub session_id: String,
    pub capability: String,
}

/// No PID attachment, debugger path, shell, expression or generic GDB command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DebugRequest {
    Launch { target: DebugTarget },
    Status { handle: DebugSessionHandle },
    Terminate { handle: DebugSessionHandle },
    Disconnect { handle: DebugSessionHandle },
}

pub fn decode_request(bytes: &[u8]) -> Result<DebugRequest, DebugError> {
    if bytes.is_empty() || bytes.len() > MAX_DEBUG_REQUEST_BYTES {
        return Err(DebugError::InvalidRequest);
    }
    let mut wire: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| DebugError::InvalidRequest)?;
    let object = wire.as_object_mut().ok_or(DebugError::InvalidRequest)?;
    if object
        .remove("schemaVersion")
        .as_ref()
        .and_then(serde_json::Value::as_str)
        != Some("1")
    {
        return Err(DebugError::InvalidRequest);
    }
    let request: DebugRequest = serde_json::from_value(wire).map_err(|_| DebugError::InvalidRequest)?;
    if let DebugRequest::Launch { target } = &request {
        target.validate()?;
    }
    Ok(request)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedDebugger {
    pub provider_id: String,
    pub runtime_pack_digest: String,
    pub winedbg_sha256: String,
    pub gdb_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebuggerBinary {
    WineDbg,
    Gdb,
}

impl PinnedDebugger {
    pub fn verify_executable(&self, binary: DebuggerBinary, bytes: &[u8]) -> Result<(), DebugError> {
        if self.provider_id != "winedbg-gdb"
            || !valid_digest(&self.runtime_pack_digest)
            || !valid_digest(&self.winedbg_sha256)
            || !valid_digest(&self.gdb_sha256)
        {
            return Err(DebugError::InvalidRequest);
        }
        let actual = format!("sha256:{:x}", Sha256::digest(bytes));
        let expected = match binary {
            DebuggerBinary::WineDbg => &self.winedbg_sha256,
            DebuggerBinary::Gdb => &self.gdb_sha256,
        };
        if *expected == actual {
            Ok(())
        } else {
            Err(DebugError::DigestMismatch)
        }
    }
}

/// Package metadata can describe an unavailable provider; it cannot enable a
/// provider without both binary digests and the selected Runtime Pack identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebuggerPackageBinding {
    pub schema_version: u8,
    pub provider_id: String,
    pub runtime_pack_digest: String,
    pub available: bool,
    pub winedbg_sha256: Option<String>,
    pub gdb_sha256: Option<String>,
}

impl DebuggerPackageBinding {
    pub fn trusted(&self, selected_runtime_digest: &str) -> Result<PinnedDebugger, DebugError> {
        if self.schema_version != 1 || self.provider_id != "winedbg-gdb" || !valid_digest(&self.runtime_pack_digest) {
            return Err(DebugError::InvalidRequest);
        }
        if self.runtime_pack_digest != selected_runtime_digest {
            return Err(DebugError::DigestMismatch);
        }
        let (Some(winedbg_sha256), Some(gdb_sha256)) = (&self.winedbg_sha256, &self.gdb_sha256) else {
            return Err(DebugError::Unavailable);
        };
        if !self.available || !valid_digest(winedbg_sha256) || !valid_digest(gdb_sha256) {
            return Err(DebugError::Unavailable);
        }
        Ok(PinnedDebugger {
            provider_id: self.provider_id.clone(),
            runtime_pack_digest: self.runtime_pack_digest.clone(),
            winedbg_sha256: winedbg_sha256.clone(),
            gdb_sha256: gdb_sha256.clone(),
        })
    }
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    Active,
    Stopped,
    Terminated,
    Disconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugEvent {
    Stopped,
    Continued,
}

/// A provider owns and cleans up every process it starts. A failed cleanup is not reported as success.
pub trait Backend {
    type Owned;
    fn launch(&self, target: &DebugTarget) -> Result<Self::Owned, DebugError>;
    fn terminate(&self, owned: &mut Self::Owned) -> Result<(), DebugError>;
    fn disconnect(&self, owned: &mut Self::Owned) -> Result<(), DebugError>;
}

pub struct UnavailableBackend;
impl Backend for UnavailableBackend {
    type Owned = ();
    fn launch(&self, _: &DebugTarget) -> Result<Self::Owned, DebugError> {
        Err(DebugError::Unavailable)
    }
    fn terminate(&self, _: &mut Self::Owned) -> Result<(), DebugError> {
        Ok(())
    }
    fn disconnect(&self, _: &mut Self::Owned) -> Result<(), DebugError> {
        Ok(())
    }
}

struct Session<O> {
    owner_uid: u32,
    target: DebugTarget,
    capability: String,
    state: SessionState,
    owned: Option<O>,
}

pub struct DebugSupervisor<B: Backend> {
    backend: B,
    sessions: BTreeMap<String, Session<B::Owned>>,
}

impl<B: Backend> DebugSupervisor<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            sessions: BTreeMap::new(),
        }
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    pub fn launch(&mut self, target: DebugTarget, owner_uid: u32) -> Result<DebugSessionHandle, DebugError> {
        target.validate()?;
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(DebugError::Capacity);
        }
        let mut random = [0_u8; 48];
        getrandom::getrandom(&mut random).map_err(|_| DebugError::Unavailable)?;
        let session_id = format!("debug-{}", hex(&random[..16]));
        let capability = hex(&random[16..]);
        let owned = self.backend.launch(&target)?;
        self.sessions.insert(
            session_id.clone(),
            Session {
                owner_uid,
                target,
                capability: capability.clone(),
                state: SessionState::Active,
                owned: Some(owned),
            },
        );
        Ok(DebugSessionHandle { session_id, capability })
    }

    fn authorized(&self, handle: &DebugSessionHandle, owner_uid: u32) -> Result<&Session<B::Owned>, DebugError> {
        let session = self.sessions.get(&handle.session_id).ok_or(DebugError::Unauthorized)?;
        if session.owner_uid != owner_uid
            || !constant_time_equal(session.capability.as_bytes(), handle.capability.as_bytes())
        {
            return Err(DebugError::Unauthorized);
        }
        Ok(session)
    }

    pub fn state(&self, handle: &DebugSessionHandle, owner_uid: u32) -> Result<SessionState, DebugError> {
        Ok(self.authorized(handle, owner_uid)?.state)
    }

    pub fn target(&self, handle: &DebugSessionHandle, owner_uid: u32) -> Result<DebugTarget, DebugError> {
        Ok(self.authorized(handle, owner_uid)?.target.clone())
    }

    pub fn record(&mut self, handle: &DebugSessionHandle, owner_uid: u32, event: DebugEvent) -> Result<(), DebugError> {
        let state = self.authorized(handle, owner_uid)?.state;
        let next = match (state, event) {
            (SessionState::Active, DebugEvent::Stopped) => SessionState::Stopped,
            (SessionState::Stopped, DebugEvent::Continued) => SessionState::Active,
            _ => return Err(DebugError::InvalidTransition),
        };
        self.sessions
            .get_mut(&handle.session_id)
            .ok_or(DebugError::Unauthorized)?
            .state = next;
        Ok(())
    }

    pub fn terminate(&mut self, handle: &DebugSessionHandle, owner_uid: u32) -> Result<(), DebugError> {
        let state = self.authorized(handle, owner_uid)?.state;
        if state == SessionState::Terminated {
            return Ok(());
        }
        if state == SessionState::Disconnected {
            return Err(DebugError::InvalidTransition);
        }
        let session = self
            .sessions
            .get_mut(&handle.session_id)
            .ok_or(DebugError::Unauthorized)?;
        if let Some(owned) = session.owned.as_mut() {
            self.backend.terminate(owned)?;
        }
        session.owned = None;
        session.state = SessionState::Terminated;
        Ok(())
    }

    pub fn disconnect(&mut self, handle: &DebugSessionHandle, owner_uid: u32) -> Result<(), DebugError> {
        let state = self.authorized(handle, owner_uid)?.state;
        if state == SessionState::Disconnected {
            return Ok(());
        }
        if state == SessionState::Terminated {
            return Err(DebugError::InvalidTransition);
        }
        let session = self
            .sessions
            .get_mut(&handle.session_id)
            .ok_or(DebugError::Unauthorized)?;
        if let Some(owned) = session.owned.as_mut() {
            self.backend.disconnect(owned)?;
        }
        session.owned = None;
        session.state = SessionState::Disconnected;
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), DebugError> {
        let mut first_error = None;
        for session in self.sessions.values_mut() {
            if let Some(owned) = session.owned.as_mut() {
                match self.backend.terminate(owned) {
                    Ok(()) => {
                        session.owned = None;
                        session.state = SessionState::Terminated;
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl<B: Backend> Drop for DebugSupervisor<B> {
    fn drop(&mut self) {
        for session in self.sessions.values_mut() {
            if let Some(owned) = session.owned.as_mut() {
                let _ = self.backend.terminate(owned);
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(ALPHABET[(byte >> 4) as usize] as char);
        result.push(ALPHABET[(byte & 0xF) as usize] as char);
    }
    result
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
