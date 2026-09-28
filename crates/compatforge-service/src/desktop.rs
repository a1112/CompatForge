//! Reviewed Linux desktop metadata. Never serializes a runtime or shell command.

use crate::{JobKind, JobRequest, ServiceError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CLIENT: &str = "/usr/bin/compatforge-cli";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopLauncher {
    pub entry_id: String,
    pub application_id: String,
    pub launcher_id: String,
    pub generation_id: String,
    pub name: String,
    pub icon: String,
    pub startup_wm_class: String,
    pub mime_types: Vec<String>,
}

impl DesktopLauncher {
    pub fn desktop_entry(&self) -> Result<String, ServiceError> {
        checked_id(&self.application_id)?;
        checked_id(&self.launcher_id)?;
        if self.entry_id.len() > 255 || self.entry_id != entry_id(&self.application_id, &self.launcher_id) {
            return Err(invalid("invalid desktop entry identity"));
        }
        checked_text(&self.name)?;
        let declaration = reviewed(&self.application_id, &self.launcher_id);
        if self.icon != declaration.0
            || self.startup_wm_class != declaration.1
            || self.mime_types.iter().map(String::as_str).collect::<Vec<_>>() != declaration.2
        {
            return Err(invalid("desktop metadata differs from reviewed declaration"));
        }
        // IDs are restricted ASCII tokens. Names never enter Exec, so literal
        // percent signs there are not field codes; only the standalone %F is.
        let name = self.name.replace('\\', "\\\\");
        let mut text = format!("[Desktop Entry]\nType=Application\nVersion=1.0\nName={name}\nExec={CLIENT} desktop-launch {} {} -- %F\nTryExec={CLIENT}\nIcon={}\nTerminal=false\nCategories=Utility;\nX-Forge-Managed=true\n",
            self.application_id, self.launcher_id, self.icon);
        if !self.startup_wm_class.is_empty() {
            text.push_str(&format!("StartupWMClass={}\n", self.startup_wm_class));
        }
        if !self.mime_types.is_empty() {
            text.push_str(&format!("MimeType={};\n", self.mime_types.join(";")));
        }
        Ok(text)
    }
}

pub fn launch_request(application: &str, launcher: &str, files: &[String]) -> Result<JobRequest, ServiceError> {
    checked_id(application)?;
    checked_id(launcher)?;
    for file in files {
        checked_text(file)?;
        if !file.starts_with('/') {
            return Err(invalid("desktop files must be absolute local paths"));
        }
    }
    let request = JobRequest {
        schema_version: "1".into(),
        application_id: application.into(),
        kind: JobKind::Launch,
        launcher_id: Some(launcher.into()),
        executable_path: None,
        argument_overrides: files.to_vec(),
        environment_overrides: BTreeMap::new(),
    };
    request.validate().map_err(ServiceError::Model)?;
    Ok(request)
}

pub(crate) fn checked_id(id: &str) -> Result<(), ServiceError> {
    if id.is_empty()
        || id.len() > 128
        || !id.as_bytes()[0].is_ascii_lowercase() && !id.as_bytes()[0].is_ascii_digit()
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || id.starts_with("gen-")
        || matches!(id, "con" | "prn" | "aux" | "nul")
        || id.starts_with("com") && id[3..].parse::<u8>().is_ok_and(|n| (1..=9).contains(&n))
        || id.starts_with("lpt") && id[3..].parse::<u8>().is_ok_and(|n| (1..=9).contains(&n))
    {
        return Err(invalid("invalid or reserved desktop identifier"));
    }
    Ok(())
}

fn checked_text(text: &str) -> Result<(), ServiceError> {
    if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(invalid("desktop text is empty, oversized or contains controls"));
    }
    Ok(())
}

fn invalid(message: &str) -> ServiceError {
    ServiceError::Invalid(message.into())
}

fn entry_id(app: &str, launcher: &str) -> String {
    format!("org.forgeos.CompatForge.{app}.{launcher}.desktop")
}

fn reviewed(app: &str, launcher: &str) -> (&'static str, &'static str, &'static [&'static str]) {
    match (app, launcher) {
        ("7zip", "main") => (
            "package-x-generic",
            "7zfm.exe",
            &["application/zip", "application/x-7z-compressed"],
        ),
        ("notepad-plus-plus", "main") => ("text-editor", "notepad++.exe", &["text/plain"]),
        ("sumatrapdf", "main") => ("application-pdf", "sumatrapdf.exe", &["application/pdf"]),
        _ => ("application-x-executable", "", &[]),
    }
}

pub(crate) fn from_generation(generation: &crate::ApplicationGeneration) -> Result<Vec<DesktopLauncher>, ServiceError> {
    generation
        .definition
        .launchers
        .iter()
        .map(|launcher| {
            let (icon, class, mime) = reviewed(&generation.definition.id, &launcher.id);
            let metadata = DesktopLauncher {
                entry_id: entry_id(&generation.definition.id, &launcher.id),
                application_id: generation.definition.id.clone(),
                launcher_id: launcher.id.clone(),
                generation_id: generation.id.clone(),
                name: if generation.definition.launchers.len() == 1 {
                    generation.definition.name.clone()
                } else {
                    format!("{} — {}", generation.definition.name, launcher.name)
                },
                icon: icon.into(),
                startup_wm_class: class.into(),
                mime_types: mime.iter().map(|s| (*s).into()).collect(),
            };
            metadata.desktop_entry()?;
            Ok(metadata)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> DesktopLauncher {
        DesktopLauncher {
            entry_id: "org.forgeos.CompatForge.7zip.main.desktop".into(),
            application_id: "7zip".into(),
            launcher_id: "main".into(),
            generation_id: "gen-job-123-1".into(),
            name: "压缩 \"文件\" 100% \\".into(),
            icon: "package-x-generic".into(),
            startup_wm_class: "7zfm.exe".into(),
            mime_types: vec!["application/zip".into(), "application/x-7z-compressed".into()],
        }
    }

    #[test]
    fn entry_keeps_names_out_of_exec_and_has_one_standalone_file_field() {
        let entry = metadata().desktop_entry().unwrap();
        assert!(entry.contains("Name=压缩 \"文件\" 100% \\\\\n"));
        assert!(entry.contains("Exec=/usr/bin/compatforge-cli desktop-launch 7zip main -- %F\n"));
        assert!(entry.contains("MimeType=application/zip;application/x-7z-compressed;\n"));
        assert!(!entry.contains("wine"));
    }

    #[test]
    fn files_remain_individual_arguments_even_with_unicode_quotes_and_percent() {
        let files = vec!["/tmp/中文 文件.txt".into(), "/tmp/a\"b%F.txt".into()];
        let request = launch_request("7zip", "main", &files).unwrap();
        assert_eq!(request.argument_overrides, files);
        assert_eq!(request.launcher_id.as_deref(), Some("main"));
        assert!(request.environment_overrides.is_empty());
    }

    #[test]
    fn refuses_injection_reserved_ids_and_invalid_files() {
        for id in ["../evil", "main\nExec=x", "main%F", "CON", "gen-job-1", "-flag", "a.b"] {
            assert!(launch_request(id, "main", &[]).is_err(), "{id}");
        }
        for file in ["relative.txt", "/tmp/new\nline", "/tmp/zero\0file"] {
            assert!(launch_request("7zip", "main", &[file.into()]).is_err());
        }
        let mut entry = metadata();
        entry.name = "bad\nExec=bad".into();
        assert!(entry.desktop_entry().is_err());
    }

    #[test]
    fn full_entry_identity_must_fit_linux_filename_limit() {
        let mut entry = metadata();
        entry.application_id = "a".repeat(128);
        entry.launcher_id = "b".repeat(128);
        entry.entry_id = entry_id(&entry.application_id, &entry.launcher_id);
        entry.icon = "application-x-executable".into();
        entry.startup_wm_class.clear();
        entry.mime_types.clear();
        assert!(entry.desktop_entry().is_err());
    }
}
