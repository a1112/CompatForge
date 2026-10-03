use super::{validate_id, validate_schema_version, validate_sha256, ContractError, CpuArchitecture};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path};

pub const MAX_MSI_BYTES: u64 = 2_147_483_648;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallPackage {
    pub path: String,
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
}

impl InstallPackage {
    pub fn validate(&self) -> Result<(), ContractError> {
        let path = Path::new(&self.path);
        if !path.is_absolute()
            || self.path.len() > 4096
            || self.path.chars().any(char::is_control)
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || path.file_name().and_then(|p| p.to_str()) != Some(self.file_name.as_str())
            || self.file_name.len() > 255
            || self.file_name.len() < 5
            || !self
                .file_name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b" ._()+-".contains(&c))
            || !self
                .file_name
                .as_bytes()
                .first()
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            || !self.file_name.to_ascii_lowercase().ends_with(".msi")
        {
            return Err(ContractError::UnsupportedValue("package path/name"));
        }
        validate_sha256("package.sha256", &self.sha256)?;
        if !(1..=MAX_MSI_BYTES).contains(&self.size_bytes) || self.media_type != "application/x-msi" {
            return Err(ContractError::UnsupportedValue("package size/mediaType"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InstallUi {
    None,
    Basic,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallHandler {
    pub kind: String,
    pub action: String,
    pub ui: InstallUi,
    pub reboot: String,
    pub properties: BTreeMap<String, String>,
}
impl InstallHandler {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_properties(false)
    }
    /// Validate retained failed/cancelled metadata, never an execution request.
    /// Older managed-MSI builds admitted spaces that Wine could not execute.
    pub fn validate_retained_failure_metadata(&self) -> Result<(), ContractError> {
        self.validate_properties(true)
    }
    fn validate_properties(&self, allow_legacy_spaces: bool) -> Result<(), ContractError> {
        if self.kind != "msiexec" || self.action != "install" || self.reboot != "suppress" || self.properties.len() > 5
        {
            return Err(ContractError::UnsupportedValue("closed msiexec handler"));
        }
        for (key, value) in &self.properties {
            let valid = match key.as_str() {
                "ALLUSERS" => matches!(value.as_str(), "1" | "2"),
                "MSIINSTALLPERUSER" => value == "1",
                "INSTALLDIR" | "INSTALLFOLDER" | "TARGETDIR" => valid_install_directory(value, allow_legacy_spaces),
                _ => false,
            };
            if !valid {
                return Err(ContractError::UnsupportedValue("unauthorized msiexec property"));
            }
        }
        Ok(())
    }
    pub fn arguments(&self, package: &str) -> Result<Vec<String>, ContractError> {
        self.validate()?;
        let mut args = vec![
            "/i".into(),
            package.into(),
            match self.ui {
                InstallUi::None => "/qn",
                InstallUi::Basic => "/qb",
            }
            .into(),
            "/norestart".into(),
            "REBOOT=ReallySuppress".into(),
        ];
        // Property values are validated without spaces or literal quotes.
        // Wine's msiexec keeps outer argv quotes in property names, so space-
        // containing overrides are rejected before execution. MSI defaults
        // may still install into directories such as Program Files.
        args.extend(self.properties.iter().map(|(k, v)| format!("{k}={v}")));
        Ok(args)
    }
}
fn valid_install_directory(value: &str, allow_legacy_spaces: bool) -> bool {
    value.starts_with("C:\\")
        && value.len() > 3
        && value.len() <= 4096
        && value
            .bytes()
            .all(|c| (0x21..=0x7e).contains(&c) || (allow_legacy_spaces && c == b' '))
        && !value.chars().any(|c| "\"<>|?*/=".contains(c))
        && !value[3..].contains(':')
        && !value[3..]
            .split('\\')
            .any(|c| matches!(c, "" | "." | "..") || c.ends_with(['.', ' ']))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallConstraints {
    pub allow_virtual_machine: bool,
    pub allow_remote: bool,
    pub network_policy: String,
    pub maximum_runtime_milliseconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallRequest {
    pub schema_version: String,
    pub request_id: String,
    pub bottle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipe_id: Option<String>,
    pub package: InstallPackage,
    pub handler: InstallHandler,
    pub constraints: InstallConstraints,
}
impl InstallRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_schema_version(&self.schema_version)?;
        validate_id("bottleId", &self.bottle_id)?;
        if let Some(id) = &self.recipe_id {
            validate_id("recipeId", id)?;
        }
        if self.request_id.len() != 36
            || !self.request_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
        {
            return Err(ContractError::UnsupportedValue("canonical request UUID"));
        }
        self.package.validate()?;
        self.handler.validate()?;
        let c = &self.constraints;
        if c.allow_virtual_machine
            || c.allow_remote
            || !matches!(c.network_policy.as_str(), "deny" | "installer-only")
            || !(1000..=3_600_000).contains(&c.maximum_runtime_milliseconds)
        {
            return Err(ContractError::UnsupportedValue("install constraints"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsiPackageBinding {
    pub package: InstallPackage,
    pub stored_path: String,
    pub architecture: CpuArchitecture,
}

/// Trusted installer policy, deliberately outside historical runtime snapshots.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeInstallerTool {
    pub pack_id: String,
    pub pack_digest: String,
    pub path: String,
    pub digest: String,
    pub architecture: CpuArchitecture,
}

impl RuntimeInstallerTool {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("wineInstallerTools.packId", &self.pack_id)?;
        super::validate_digest("wineInstallerTools.packDigest", &self.pack_digest)?;
        super::validate_digest("wineInstallerTools.digest", &self.digest)?;
        if !Path::new(&self.path).is_absolute()
            || self.path.chars().any(char::is_control)
            || Path::new(&self.path)
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || !matches!(self.architecture, CpuArchitecture::I386 | CpuArchitecture::X86_64)
        {
            return Err(ContractError::UnsupportedValue("wineInstallerTools path/architecture"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsiInstallBinding {
    pub package: MsiPackageBinding,
    pub handler: InstallHandler,
    pub tool: RuntimeInstallerTool,
    pub maximum_runtime_milliseconds: u64,
}

impl MsiInstallBinding {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.package.package.validate()?;
        self.handler.validate()?;
        self.tool.validate()?;
        if self.package.architecture != self.tool.architecture
            || !(1000..=3_600_000).contains(&self.maximum_runtime_milliseconds)
            || !Path::new(&self.package.stored_path).is_absolute()
            || self.package.stored_path.chars().any(char::is_control)
            || Path::new(&self.package.stored_path)
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(ContractError::UnsupportedValue("msiInstall binding"));
        }
        Ok(())
    }

    pub fn arguments(&self) -> Result<Vec<String>, ContractError> {
        self.validate()?;
        let mut arguments = vec![self.tool.path.clone()];
        arguments.extend(self.handler.arguments(&self.package.stored_path)?);
        Ok(arguments)
    }
}
