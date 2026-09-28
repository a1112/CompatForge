//! Bounded DAP framing and the public request allowlist. GDB's own DAP
//! interpreter accepts debugger commands; callers only reach this subset.

use crate::{DebugError, DebugTarget, MAX_DEBUG_REQUEST_BYTES};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const MAX_HEADER_BYTES: usize = 128;
const MAX_ITEMS: usize = 64;

#[derive(Default)]
pub struct DapFrameDecoder {
    header: Vec<u8>,
    body: Vec<u8>,
    expected: Option<usize>,
}

impl DapFrameDecoder {
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<Value>, DebugError> {
        let mut messages = Vec::new();
        while !bytes.is_empty() {
            if let Some(expected) = self.expected {
                let take = (expected - self.body.len()).min(bytes.len());
                self.body.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.body.len() == expected {
                    let message = serde_json::from_slice(&self.body).map_err(|_| DebugError::InvalidRequest)?;
                    messages.push(message);
                    self.body.clear();
                    self.expected = None;
                }
            } else {
                let byte = bytes[0];
                bytes = &bytes[1..];
                if byte == b'\n' && self.header.last() != Some(&b'\r')
                    || self.header.last() == Some(&b'\r') && byte != b'\n'
                    || !(byte.is_ascii_graphic() || byte == b' ' || byte == b'\r' || byte == b'\n')
                {
                    return Err(DebugError::InvalidRequest);
                }
                self.header.push(byte);
                if self.header.len() > MAX_HEADER_BYTES {
                    return Err(DebugError::InvalidRequest);
                }
                if self.header.ends_with(b"\r\n\r\n") {
                    let length = parse_header(&self.header)?;
                    self.header.clear();
                    self.expected = Some(length);
                }
            }
        }
        Ok(messages)
    }
}

fn parse_header(header: &[u8]) -> Result<usize, DebugError> {
    let text = std::str::from_utf8(header).map_err(|_| DebugError::InvalidRequest)?;
    let line = text.strip_suffix("\r\n\r\n").ok_or(DebugError::InvalidRequest)?;
    let number = line
        .strip_prefix("Content-Length: ")
        .ok_or(DebugError::InvalidRequest)?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DebugError::InvalidRequest);
    }
    let length = number.parse::<usize>().map_err(|_| DebugError::InvalidRequest)?;
    if !(1..=MAX_DEBUG_REQUEST_BYTES).contains(&length) {
        return Err(DebugError::InvalidRequest);
    }
    Ok(length)
}

pub fn encode_message(message: &Value) -> Result<Vec<u8>, DebugError> {
    let body = serde_json::to_vec(message).map_err(|_| DebugError::InvalidRequest)?;
    if body.len() > MAX_DEBUG_REQUEST_BYTES {
        return Err(DebugError::InvalidRequest);
    }
    let mut framed = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    framed.extend_from_slice(&body);
    Ok(framed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeDapRequest {
    Initialize {
        seq: u64,
    },
    Launch {
        seq: u64,
        target: DebugTarget,
    },
    SetBreakpoints {
        seq: u64,
        source: String,
        lines: Vec<u32>,
    },
    ConfigurationDone {
        seq: u64,
    },
    Threads {
        seq: u64,
    },
    Continue {
        seq: u64,
        thread_id: u64,
    },
    Pause {
        seq: u64,
        thread_id: u64,
    },
    Next {
        seq: u64,
        thread_id: u64,
    },
    StepIn {
        seq: u64,
        thread_id: u64,
    },
    StepOut {
        seq: u64,
        thread_id: u64,
    },
    StackTrace {
        seq: u64,
        thread_id: u64,
        start_frame: u32,
        levels: u32,
    },
    Scopes {
        seq: u64,
        frame_id: u64,
    },
    Variables {
        seq: u64,
        reference: u64,
        start: u32,
        count: u32,
    },
    Terminate {
        seq: u64,
    },
    Disconnect {
        seq: u64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    seq: u64,
    #[serde(rename = "type")]
    kind: String,
    command: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DisconnectArguments {
    #[serde(default)]
    terminate_debuggee: bool,
    #[serde(default)]
    restart: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BreakpointArguments {
    source: Source,
    breakpoints: Vec<Breakpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    path: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Breakpoint {
    line: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ThreadArguments {
    thread_id: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FrameArguments {
    frame_id: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StackArguments {
    thread_id: u64,
    #[serde(default)]
    start_frame: u32,
    #[serde(default = "default_count")]
    levels: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VariableArguments {
    variables_reference: u64,
    #[serde(default)]
    start: u32,
    #[serde(default = "default_count")]
    count: u32,
}

fn default_count() -> u32 {
    MAX_ITEMS as u32
}

fn parse_arguments<T: for<'a> Deserialize<'a>>(arguments: Value) -> Result<T, DebugError> {
    serde_json::from_value(if arguments.is_null() { json!({}) } else { arguments })
        .map_err(|_| DebugError::InvalidRequest)
}

fn checked_thread(id: u64) -> Result<u64, DebugError> {
    if id == 0 {
        Err(DebugError::InvalidRequest)
    } else {
        Ok(id)
    }
}

impl SafeDapRequest {
    pub fn parse(value: &Value) -> Result<Self, DebugError> {
        let envelope: Envelope = serde_json::from_value(value.clone()).map_err(|_| DebugError::InvalidRequest)?;
        if envelope.kind != "request" || envelope.seq == 0 {
            return Err(DebugError::InvalidRequest);
        }
        let seq = envelope.seq;
        let args = envelope.arguments;
        match envelope.command.as_str() {
            "initialize" => {
                if !args.is_null() && !args.is_object() {
                    return Err(DebugError::InvalidRequest);
                }
                Ok(Self::Initialize { seq })
            }
            "launch" => {
                let target: DebugTarget = parse_arguments(args)?;
                target.validate()?;
                Ok(Self::Launch { seq, target })
            }
            "setBreakpoints" => {
                let args: BreakpointArguments = parse_arguments(args)?;
                if args.source.path.len() > 4096
                    || !args.source.path.starts_with('/')
                    || args.source.path.chars().any(char::is_control)
                    || args.source.path.split('/').any(|part| part == "..")
                    || args
                        .source
                        .name
                        .as_ref()
                        .is_some_and(|name| name.len() > 255 || name.chars().any(char::is_control))
                    || args.breakpoints.len() > 128
                    || args.breakpoints.iter().any(|point| point.line == 0)
                {
                    return Err(DebugError::InvalidRequest);
                }
                Ok(Self::SetBreakpoints {
                    seq,
                    source: args.source.path,
                    lines: args.breakpoints.into_iter().map(|point| point.line).collect(),
                })
            }
            "configurationDone" => {
                let _: Empty = parse_arguments(args)?;
                Ok(Self::ConfigurationDone { seq })
            }
            "threads" => {
                let _: Empty = parse_arguments(args)?;
                Ok(Self::Threads { seq })
            }
            "continue" | "pause" | "next" | "stepIn" | "stepOut" => {
                let args: ThreadArguments = parse_arguments(args)?;
                let thread_id = checked_thread(args.thread_id)?;
                Ok(match envelope.command.as_str() {
                    "continue" => Self::Continue { seq, thread_id },
                    "pause" => Self::Pause { seq, thread_id },
                    "next" => Self::Next { seq, thread_id },
                    "stepIn" => Self::StepIn { seq, thread_id },
                    _ => Self::StepOut { seq, thread_id },
                })
            }
            "stackTrace" => {
                let args: StackArguments = parse_arguments(args)?;
                if args.levels == 0 || args.levels as usize > MAX_ITEMS || args.start_frame > 10_000 {
                    return Err(DebugError::InvalidRequest);
                }
                Ok(Self::StackTrace {
                    seq,
                    thread_id: checked_thread(args.thread_id)?,
                    start_frame: args.start_frame,
                    levels: args.levels,
                })
            }
            "scopes" => {
                let args: FrameArguments = parse_arguments(args)?;
                Ok(Self::Scopes {
                    seq,
                    frame_id: args.frame_id,
                })
            }
            "variables" => {
                let args: VariableArguments = parse_arguments(args)?;
                if args.variables_reference == 0
                    || args.count == 0
                    || args.count as usize > MAX_ITEMS
                    || args.start > 10_000
                {
                    return Err(DebugError::InvalidRequest);
                }
                Ok(Self::Variables {
                    seq,
                    reference: args.variables_reference,
                    start: args.start,
                    count: args.count,
                })
            }
            "terminate" => {
                let _: Empty = parse_arguments(args)?;
                Ok(Self::Terminate { seq })
            }
            "disconnect" => {
                let args: DisconnectArguments = parse_arguments(args)?;
                if args.terminate_debuggee || args.restart {
                    return Err(DebugError::InvalidRequest);
                }
                Ok(Self::Disconnect { seq })
            }
            _ => Err(DebugError::InvalidRequest),
        }
    }
}

/// Service-selected target, symbol file and source map. None of these paths or
/// the private network-namespace port come from a DAP client request.
pub struct DapBinding {
    target: DebugTarget,
    program: String,
    port: u16,
    sources: BTreeMap<String, String>,
}

impl DapBinding {
    pub fn new<K, V, I>(target: DebugTarget, program: &str, port: u16, sources: I) -> Result<Self, DebugError>
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        target.validate()?;
        if !safe_absolute_path(program) || port < 1024 {
            return Err(DebugError::InvalidRequest);
        }
        let mut mapped = BTreeMap::new();
        for (public, backend) in sources {
            let public = public.into();
            let backend = backend.into();
            if !safe_absolute_path(&public) || !safe_absolute_path(&backend) || mapped.insert(public, backend).is_some()
            {
                return Err(DebugError::InvalidRequest);
            }
        }
        if mapped.len() > 128 {
            return Err(DebugError::InvalidRequest);
        }
        Ok(Self {
            target,
            program: program.into(),
            port,
            sources: mapped,
        })
    }

    pub fn forward(&self, request: &SafeDapRequest) -> Result<Value, DebugError> {
        let (seq, command, arguments) = match request {
            SafeDapRequest::Initialize { seq } => (
                *seq,
                "initialize",
                json!({"adapterID":"gdb","clientID":"compatforge","linesStartAt1":true,"columnsStartAt1":true}),
            ),
            SafeDapRequest::Launch { seq, target } => {
                if target != &self.target {
                    return Err(DebugError::Unauthorized);
                }
                (
                    *seq,
                    "attach",
                    json!({"program":self.program,"target":format!("127.0.0.1:{}", self.port)}),
                )
            }
            SafeDapRequest::SetBreakpoints { seq, source, lines } => {
                let mapped = self.sources.get(source).ok_or(DebugError::Unauthorized)?;
                (
                    *seq,
                    "setBreakpoints",
                    json!({"source":{"path":mapped},"breakpoints":lines.iter().map(|line| json!({"line":line})).collect::<Vec<_>>()}),
                )
            }
            SafeDapRequest::ConfigurationDone { seq } => (*seq, "configurationDone", json!({})),
            SafeDapRequest::Threads { seq } => (*seq, "threads", json!({})),
            SafeDapRequest::Continue { seq, thread_id } => (*seq, "continue", json!({"threadId":thread_id})),
            SafeDapRequest::Pause { seq, thread_id } => (*seq, "pause", json!({"threadId":thread_id})),
            SafeDapRequest::Next { seq, thread_id } => (*seq, "next", json!({"threadId":thread_id})),
            SafeDapRequest::StepIn { seq, thread_id } => (*seq, "stepIn", json!({"threadId":thread_id})),
            SafeDapRequest::StepOut { seq, thread_id } => (*seq, "stepOut", json!({"threadId":thread_id})),
            SafeDapRequest::StackTrace {
                seq,
                thread_id,
                start_frame,
                levels,
            } => (
                *seq,
                "stackTrace",
                json!({"threadId":thread_id,"startFrame":start_frame,"levels":levels}),
            ),
            SafeDapRequest::Scopes { seq, frame_id } => (*seq, "scopes", json!({"frameId":frame_id})),
            SafeDapRequest::Variables {
                seq,
                reference,
                start,
                count,
            } => (
                *seq,
                "variables",
                json!({"variablesReference":reference,"start":start,"count":count}),
            ),
            SafeDapRequest::Terminate { seq } => (*seq, "terminate", json!({})),
            SafeDapRequest::Disconnect { seq } => (*seq, "disconnect", json!({"terminateDebuggee":false})),
        };
        Ok(json!({"seq":seq,"type":"request","command":command,"arguments":arguments}))
    }
}

fn safe_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|part| part == "..")
}

pub fn sanitize_initialize_response(mut response: Value) -> Result<Value, DebugError> {
    if response.get("type") != Some(&json!("response"))
        || response.get("command") != Some(&json!("initialize"))
        || response.get("success") != Some(&json!(true))
    {
        return Err(DebugError::InvalidRequest);
    }
    let object = response.as_object_mut().ok_or(DebugError::InvalidRequest)?;
    object.insert(
        "body".into(),
        json!({
            "supportsConfigurationDoneRequest": true,
            "supportsTerminateRequest": true,
            "supportsDelayedStackTraceLoading": true
        }),
    );
    Ok(response)
}
