//! Fixed desktop client commands; never load runtime context from desktop metadata.
use std::error::Error;
use std::io;

#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Daemon(&'a str, &'a str),
    Call(&'a str),
    Stop,
    Export,
    Launch(&'a str, &'a str, &'a [String]),
}

fn parse(arguments: &[String]) -> io::Result<Option<Command<'_>>> {
    Ok(Some(match arguments {
        [command, config, service] if command == "service-daemon" => Command::Daemon(config, service),
        [command, file] if command == "service-call" => Command::Call(file),
        [command] if command == "service-stop" => Command::Stop,
        [command] if command == "desktop-export" => Command::Export,
        [command, app, launcher, separator, files @ ..] if command == "desktop-launch" && separator == "--" => {
            compatforge_service::desktop::launch_request(app, launcher, files).map_err(io::Error::other)?;
            Command::Launch(app, launcher, files)
        }
        [command, ..]
            if [
                "service-daemon",
                "service-call",
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
    use serde_json::json;
    use std::path::Path;
    let directory = daemon::runtime_directory()?;
    if let Command::Daemon(config, service) = command {
        return daemon::run(
            &directory,
            read_shared_json(Path::new(config), 4 * 1024 * 1024).map_err(|error| io::Error::other(format!("shared context configuration {config} is unavailable or invalid: {error}; provision it using CompatForge local context bootstrap")))?,
            read_shared_json(Path::new(service), 4 * 1024 * 1024).map_err(|error| io::Error::other(format!("shared service configuration {service} is unavailable or invalid: {error}")))?,
        )
        .map_err(Into::into);
    }
    let (operation, payload) = match command {
        Command::Stop => ("daemon.stop", json!({})),
        Command::Export => ("desktop.launchers", json!({})),
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
        Command::Call(path) => {
            let request: ServiceRequest =
                read_shared_json(Path::new(path), compatforge_service::transport::MAX_REQUEST_BYTES)?;
            return print_reply(daemon::request(&directory, &request)?, false);
        }
        Command::Daemon(_, _) => unreachable!(),
    };
    let request = ServiceRequest {
        schema_version: "1".into(),
        request_id: format!("desktop-{}", std::process::id()),
        operation: operation.into(),
        payload,
    };
    print_reply(
        daemon::request(&directory, &request)?,
        matches!(command, Command::Export),
    )
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
fn print_reply(reply: compatforge_service::daemon::DaemonReply, export: bool) -> Result<(), Box<dyn Error>> {
    if let Some(error) = reply.error {
        return Err(io::Error::other(format!("{}: {}", error.code, error.message)).into());
    }
    let response = reply
        .response
        .ok_or_else(|| io::Error::other("service returned no response"))?;
    if export {
        let launchers: Vec<compatforge_service::desktop::DesktopLauncher> = serde_json::from_value(response.result)?;
        let entries = launchers.into_iter().map(|metadata| {
            let content = metadata.desktop_entry()?;
            Ok(serde_json::json!({"entryId":metadata.entry_id, "applicationId":metadata.application_id, "generationId":metadata.generation_id, "desktopEntry":content}))
        }).collect::<Result<Vec<_>, compatforge_service::ServiceError>>()?;
        println!("{}", serde_json::json!({"schemaVersion":"1", "entries":entries}));
    } else {
        println!("{}", serde_json::to_string(&response)?);
    }
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
}
