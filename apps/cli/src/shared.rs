//! Fixed desktop client commands; never load runtime context from desktop metadata.
use std::error::Error;
use std::io;
#[cfg(target_os = "linux")]
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Daemon(&'a str, &'a str),
    Call(&'a str),
    Debug(&'a str),
    DebugAdapter(&'a str),
    Stop,
    Export,
    BoundExport(&'a str, &'a str),
    Launch(&'a str, &'a str, &'a [String]),
}

fn parse(arguments: &[String]) -> io::Result<Option<Command<'_>>> {
    Ok(Some(match arguments {
        [command, config, service] if command == "service-daemon" => Command::Daemon(config, service),
        [command, file] if command == "service-call" => Command::Call(file),
        [command, file] if command == "debug-session" => Command::Debug(file),
        [command, file] if command == "debug-adapter" => Command::DebugAdapter(file),
        [command] if command == "service-stop" => Command::Stop,
        [command] if command == "desktop-export" => Command::Export,
        [command, lock_flag, lock, id_flag, id]
            if command == "desktop-export" && lock_flag == "--provider-contract" && id_flag == "--request-id" =>
        {
            Command::BoundExport(lock, id)
        }
        [command, app, launcher, separator, files @ ..] if command == "desktop-launch" && separator == "--" => {
            compatforge_service::desktop::launch_request(app, launcher, files).map_err(io::Error::other)?;
            Command::Launch(app, launcher, files)
        }
        [command, ..]
            if [
                "service-daemon",
                "service-call",
                "debug-session",
                "debug-adapter",
                "service-stop",
                "desktop-export",
                "desktop-launch",
            ]
            .contains(&command.as_str()) =>
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid shared service command arguments",
            ))
        }
        _ => return Ok(None),
    }))
}

pub fn run(arguments: &[String]) -> Option<Result<(), Box<dyn Error>>> {
    match parse(arguments) {
        Ok(Some(command)) => Some(execute(command)),
        Ok(None) => None,
        Err(error) => Some(Err(error.into())),
    }
}

#[cfg(not(target_os = "linux"))]
fn execute(command: Command<'_>) -> Result<(), Box<dyn Error>> {
    let _ = command;
    Err(io::Error::new(io::ErrorKind::Unsupported, "shared service requires Linux").into())
}

#[cfg(target_os = "linux")]
fn execute(command: Command<'_>) -> Result<(), Box<dyn Error>> {
    use compatforge_service::{daemon, ServiceRequest};
    use forge_provider_contract::binding::{correlation, BoundInvocation};
    use forge_provider_contract::{decode_requirements, negotiate, ContractError, ErrorCode};
    use serde_json::json;
    use std::path::Path;
    let executor = crate::provider::info();
    let mut required = executor.identity();
    let mut call = None;
    let mut export_id = None;
    // Recheck the actual executing binary, not the binary used by an earlier probe.
    match command {
        Command::Call(path) => {
            let invocation: BoundInvocation<ServiceRequest> = read_shared_json(
                Path::new(path),
                compatforge_service::transport::MAX_REQUEST_BYTES + forge_provider_contract::MAX_CONTRACT_BYTES,
            )?;
            invocation.validate_executor(&executor)?;
            required = invocation.required_provider;
            call = Some(invocation.request);
        }
        Command::BoundExport(lock, id) => {
            required = decode_requirements(lock.as_bytes())?;
            if !correlation(id) {
                return Err(ContractError::new(ErrorCode::SchemaMismatch, "invalid bound desktop request ID").into());
            }
            export_id = Some(id);
        }
        _ => {}
    }
    negotiate(&executor, &required)?;
    let directory = daemon::runtime_directory()?;
    if let Command::Daemon(config, service) = command {
        return daemon::run(
            &directory,
            read_shared_json(Path::new(config), 4 * 1024 * 1024).map_err(|error| io::Error::other(format!("shared context configuration {config} is unavailable or invalid: {error}; provision it using CompatForge local context bootstrap")))?,
            read_shared_json(Path::new(service), 4 * 1024 * 1024).map_err(|error| io::Error::other(format!("shared service configuration {service} is unavailable or invalid: {error}")))?,
            executor,
        )
        .map_err(Into::into);
    }
    if let Command::DebugAdapter(path) = command {
        return run_debug_adapter(&directory, Path::new(path));
    }
    let (operation, payload) = match command {
        Command::Stop => ("daemon.stop", json!({})),
        Command::Export | Command::BoundExport(_, _) => ("desktop.launchers", json!({})),
        Command::Launch(app, launcher, files) => {
            let mut request = compatforge_service::desktop::launch_request(app, launcher, files)?;
            request.argument_overrides = windows_files(files);
            for key in ["DISPLAY", "XAUTHORITY"] {
                if let Ok(value) = std::env::var(key) {
                    request.environment_overrides.insert(key.into(), value);
                }
            }
            // Reuse the install session allowlist: only local DISPLAY and an
            // absolute XAUTHORITY are accepted from the launching desktop.
            let mut checked = request.clone();
            checked.kind = compatforge_service::JobKind::Install;
            checked.launcher_id = None;
            checked.argument_overrides.clear();
            checked.executable_path = Some("/session-validation-only".into());
            checked.validate()?;
            ("jobs.submit", serde_json::to_value(request)?)
        }
        Command::Call(_) => {
            let request = call.expect("decoded bound request");
            return print_reply(daemon::request(&directory, &request, &required)?, false, executor);
        }
        Command::Debug(path) => {
            let payload: serde_json::Value =
                read_shared_json(Path::new(path), compatforge_debug::MAX_DEBUG_REQUEST_BYTES)?;
            compatforge_debug::decode_request(&serde_json::to_vec(&payload)?)?;
            ("debug.session", payload)
        }
        Command::DebugAdapter(_) => unreachable!(),
        Command::Daemon(_, _) => unreachable!(),
    };
    let request = ServiceRequest {
        schema_version: "1".into(),
        request_id: export_id
            .map(str::to_owned)
            .unwrap_or_else(|| format!("desktop-{}", std::process::id())),
        operation: operation.into(),
        payload,
    };
    print_reply(
        daemon::request(&directory, &request, &required)?,
        matches!(command, Command::Export | Command::BoundExport(_, _)),
        executor,
    )
}

#[cfg(any(target_os = "linux", test))]
fn is_benign_ide_launch(arguments: &serde_json::Value) -> bool {
    let Some(fields) = arguments.as_object() else {
        return false;
    };
    if fields.is_empty() {
        return true;
    }
    fields.len() == 3
        && fields.get("type").and_then(serde_json::Value::as_str) == Some("compatforge")
        && fields.get("request").and_then(serde_json::Value::as_str) == Some("launch")
        && fields
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control))
}

#[cfg(any(target_os = "linux", test))]
fn encode_numbered_dap(mut message: serde_json::Value, next: &mut u64) -> io::Result<Vec<u8>> {
    if *next == 0
        || *next == u64::MAX
        || !matches!(
            message.get("type").and_then(serde_json::Value::as_str),
            Some("response" | "event")
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid outgoing DAP message",
        ));
    }
    message
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DAP object required"))?
        .insert("seq".into(), serde_json::Value::from(*next));
    let framed = compatforge_debug::dap::encode_message(&message).map_err(io::Error::other)?;
    *next += 1;
    Ok(framed)
}

#[cfg(target_os = "linux")]
fn run_debug_adapter(directory: &Path, launch_path: &Path) -> Result<(), Box<dyn Error>> {
    use compatforge_debug::dap::{DapFrameDecoder, SafeDapRequest};
    use compatforge_debug::{DebugRequest, DebugSessionHandle};
    use compatforge_service::{daemon, ServiceRequest};
    use serde_json::{json, Value};
    use std::io::{Read, Write};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    let payload: Value = read_shared_json(launch_path, compatforge_debug::MAX_DEBUG_REQUEST_BYTES)?;
    let command = compatforge_debug::decode_request(&serde_json::to_vec(&payload)?)?;
    let DebugRequest::Launch { target } = command else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "adapter requires a managed debug launch request",
        )
        .into());
    };
    let launched = daemon::request(
        directory,
        &ServiceRequest {
            schema_version: "1".into(),
            request_id: format!("dap-launch-{}", std::process::id()),
            operation: "debug.session".into(),
            payload,
        },
        &crate::provider::info().identity(),
    )?;
    let handle: DebugSessionHandle = serde_json::from_value(debug_reply_result(launched)?)?;
    let (sender, receiver) = mpsc::sync_channel::<Result<Option<Value>, String>>(8);
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut decoder = DapFrameDecoder::default();
        let mut bytes = [0_u8; 8192];
        loop {
            match input.read(&mut bytes) {
                Ok(0) => {
                    let _ = sender.send(Ok(None));
                    break;
                }
                Ok(count) => match decoder.push(&bytes[..count]) {
                    Ok(messages) => {
                        for message in messages {
                            if sender.send(Ok(Some(message))).is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                },
                Err(error) => {
                    let _ = sender.send(Err(error.to_string()));
                    break;
                }
            }
        }
    });
    let mut terminal = false;
    let mut next_outgoing_seq = 1_u64;
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut output = std::io::stdout().lock();
        loop {
            let message = match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(Some(mut message))) => {
                    if message.get("command") == Some(&json!("launch"))
                        && message.get("arguments").is_some_and(is_benign_ide_launch)
                    {
                        message["arguments"] = serde_json::to_value(&target)?;
                    }
                    match SafeDapRequest::parse(&message) {
                        Ok(_) => Some(message),
                        Err(_) => {
                            let reject = json!({"seq":0,"request_seq":message.get("seq"),"type":"response",
                                "command":message.get("command"),"success":false,"message":"unsupported DAP request"});
                            output.write_all(&encode_numbered_dap(reject, &mut next_outgoing_seq)?)?;
                            output.flush()?;
                            continue;
                        }
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(error)) => return Err(io::Error::new(io::ErrorKind::InvalidData, error).into()),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => break,
            };
            let terminal_request = message.as_ref().is_some_and(|value| {
                matches!(
                    SafeDapRequest::parse(value),
                    Ok(SafeDapRequest::Terminate { .. } | SafeDapRequest::Disconnect { .. })
                )
            });
            let reply = daemon::request(
                directory,
                &ServiceRequest {
                    schema_version: "1".into(),
                    request_id: format!("dap-{}", std::process::id()),
                    operation: "debug.dap".into(),
                    payload: json!({"schemaVersion":"1","handle":handle,"message":message}),
                },
                &crate::provider::info().identity(),
            )?;
            let result = debug_reply_result(reply)?;
            let messages = result
                .get("messages")
                .and_then(Value::as_array)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid DAP service reply"))?;
            for item in messages {
                output.write_all(&encode_numbered_dap(item.clone(), &mut next_outgoing_seq)?)?;
            }
            output.flush()?;
            if terminal_request {
                terminal = true;
                break;
            }
        }
        Ok(())
    })();
    if !terminal {
        let _ = daemon::request(
            directory,
            &ServiceRequest {
                schema_version: "1".into(),
                request_id: format!("dap-close-{}", std::process::id()),
                operation: "debug.session".into(),
                payload: json!({"schemaVersion":"1","command":"disconnect","handle":handle}),
            },
            &crate::provider::info().identity(),
        );
    }
    result
}

#[cfg(target_os = "linux")]
fn debug_reply_result(reply: compatforge_service::daemon::DaemonReply) -> Result<serde_json::Value, Box<dyn Error>> {
    if let Some(error) = reply.error {
        return Err(io::Error::other(format!("{}: {}", error.code, error.message)).into());
    }
    Ok(reply
        .response
        .ok_or_else(|| io::Error::other("service returned no response"))?
        .result)
}

#[cfg(any(target_os = "linux", test))]
fn windows_files(files: &[String]) -> Vec<String> {
    files
        .iter()
        .map(|file| format!("Z:{}", file.replace('/', "\\")))
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn read_shared_json<T: serde::de::DeserializeOwned>(path: &std::path::Path, maximum: usize) -> io::Result<T> {
    use std::io::Read;
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shared configuration must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shared configuration or request exceeds byte limit",
        ));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(target_os = "linux")]
fn print_reply(
    reply: compatforge_service::daemon::DaemonReply,
    export: bool,
    executor: forge_provider_contract::ProviderInfo,
) -> Result<(), Box<dyn Error>> {
    if let Some(error) = reply.error {
        return Err(io::Error::other(format!("{}: {}", error.code, error.message)).into());
    }
    let response = reply
        .response
        .ok_or_else(|| io::Error::other("service returned no response"))?;
    let result = if export {
        let launchers: Vec<compatforge_service::desktop::DesktopLauncher> = serde_json::from_value(response.result)?;
        let entries = launchers.into_iter().map(|metadata| {
            let content = metadata.desktop_entry()?;
            Ok(serde_json::json!({"entryId":metadata.entry_id, "applicationId":metadata.application_id, "generationId":metadata.generation_id, "desktopEntry":content}))
        }).collect::<Result<Vec<_>, compatforge_service::ServiceError>>()?;
        serde_json::json!({"schemaVersion":"1", "entries":entries})
    } else {
        response.result
    };
    let bound = forge_provider_contract::binding::ExecutionReply {
        schema_version: forge_provider_contract::binding::WIRE_VERSION.into(),
        request_id: response.request_id,
        operation: response.operation,
        executor,
        daemon: reply.daemon,
        result,
    };
    println!("{}", serde_json::to_string(&bound)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).into()).collect()
    }
    #[test]
    fn desktop_client_preserves_each_file_after_required_separator() {
        let arguments = args(&[
            "desktop-launch",
            "7zip",
            "main",
            "--",
            "/home/a b.txt",
            "/home/中文%F\".txt",
        ]);
        assert_eq!(
            parse(&arguments).unwrap(),
            Some(Command::Launch("7zip", "main", &arguments[4..]))
        );
        assert!(parse(&args(&["desktop-launch", "7zip", "main", "/home/a"])).is_err());
        assert!(parse(&args(&["desktop-launch", "7zip", "main", "--socket", "other"])).is_err());
        assert_eq!(
            windows_files(&arguments[4..]),
            args(&["Z:\\home\\a b.txt", "Z:\\home\\中文%F\".txt"])
        );
    }
    #[test]
    fn known_shared_commands_fail_closed_without_affecting_legacy_commands() {
        assert_eq!(parse(&args(&["service-stop"])).unwrap(), Some(Command::Stop));
        assert_eq!(parse(&args(&["desktop-export"])).unwrap(), Some(Command::Export));
        assert!(parse(&args(&["service-daemon", "config"])).is_err());
        assert_eq!(parse(&args(&["api-session", "config", "service"])).unwrap(), None);
        assert!(parse(&args(&["debug-session"])).is_err());
        assert!(parse(&args(&["debug-session", "request.json", "--attach", "123"])).is_err());
        assert_eq!(
            parse(&args(&["debug-session", "request.json"])).unwrap(),
            Some(Command::Debug("request.json"))
        );
        assert!(parse(&args(&["debug-adapter"])).is_err());
        assert!(parse(&args(&["debug-adapter", "request.json", "--eval", "id"])).is_err());
        assert_eq!(
            parse(&args(&["debug-adapter", "request.json"])).unwrap(),
            Some(Command::DebugAdapter("request.json"))
        );
    }

    #[test]
    fn shared_configuration_and_request_files_are_bounded_before_json_decode() {
        let path = std::env::temp_dir().join(format!("cf-shared-bounds-{}.json", std::process::id()));
        std::fs::write(&path, b"[0,0,0,0,0,0,0,0]").unwrap();
        assert_eq!(
            read_shared_json::<serde_json::Value>(&path, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(read_shared_json::<serde_json::Value>(&path, 32).unwrap().is_array());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn public_dap_sequences_are_positive_and_monotonic_across_replies_and_rejections() {
        let mut next = 1;
        let mut decoder = compatforge_debug::dap::DapFrameDecoder::default();
        for (index, message) in [
            serde_json::json!({"seq":90,"type":"event","event":"initialized"}),
            serde_json::json!({"seq":0,"request_seq":2,"type":"response","command":"evaluate","success":false}),
            serde_json::json!({"seq":3,"request_seq":1,"type":"response","command":"initialize","success":true}),
        ]
        .into_iter()
        .enumerate()
        {
            let encoded = encode_numbered_dap(message, &mut next).unwrap();
            let parsed = decoder.push(&encoded).unwrap();
            assert_eq!(parsed[0]["seq"], (index + 1) as u64);
        }
        assert_eq!(next, 4);
    }

    #[test]
    fn common_ide_launch_metadata_is_discarded_only_for_exact_static_shape() {
        assert!(is_benign_ide_launch(&serde_json::json!({})));
        assert!(is_benign_ide_launch(&serde_json::json!({
            "type":"compatforge","request":"launch","name":"Managed Windows app"
        })));
        for forged in [
            serde_json::json!({"type":"compatforge","request":"attach","name":"x"}),
            serde_json::json!({"type":"compatforge","request":"launch","name":"x","program":"/tmp/other.exe"}),
            serde_json::json!({"type":"compatforge","request":"launch","name":"\n"}),
        ] {
            assert!(!is_benign_ide_launch(&forged));
        }
    }
}
