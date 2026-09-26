//! Exact x64 DXVK DLL evidence for the Linux development Provider.

use crate::{
    sha256_file, valid_version, validate_linux_digest, validate_linux_relative_path, verify_entrypoint,
    EvidenceFailure, ProbeCommand, ProbeCommandSpec, ProbeCommandStatus, VerifiedEntrypoint,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_DXVK_DLL_BYTES: u64 = 64 * 1024 * 1024;
const PE_HEADER_BYTES: usize = 512;
const MAX_VULKAN_OUTPUT_BYTES: usize = 128 * 1024;
const VULKAN_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DxvkSource {
    pub version: String,
    pub d3d11: VerifiedEntrypoint,
    pub dxgi: VerifiedEntrypoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDxvkPair {
    pub d3d11: PathBuf,
    pub dxgi: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VulkanSource {
    pub probe: VerifiedEntrypoint,
    pub icd_manifest: VerifiedEntrypoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedVulkanDevice {
    pub api_version: String,
    pub device_name: String,
    pub probe: PathBuf,
    pub icd_manifest: PathBuf,
}

impl DxvkSource {
    pub fn validate(&self) -> Result<(), EvidenceFailure> {
        if !valid_version(&self.version) {
            return Err(EvidenceFailure::Version);
        }
        for (name, entrypoint) in [("d3d11.dll", &self.d3d11), ("dxgi.dll", &self.dxgi)] {
            validate_linux_relative_path("dxvk.path", &entrypoint.path).map_err(|_| EvidenceFailure::Entrypoint)?;
            validate_linux_digest("dxvk.digest", &entrypoint.digest).map_err(|_| EvidenceFailure::Digest)?;
            if Path::new(&entrypoint.path).file_name().and_then(|name| name.to_str()) != Some(name) {
                return Err(EvidenceFailure::Entrypoint);
            }
        }
        if Path::new(&self.d3d11.path).parent() != Path::new(&self.dxgi.path).parent() {
            return Err(EvidenceFailure::Entrypoint);
        }
        Ok(())
    }
}

pub fn verify_dxvk_pair(root: &Path, source: &DxvkSource) -> Result<VerifiedDxvkPair, EvidenceFailure> {
    source.validate()?;
    let root = fs::canonicalize(root).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    if !root.is_dir() {
        return Err(EvidenceFailure::MaterializedRoot);
    }
    let d3d11 = verify_dll(&root, &source.d3d11)?;
    let dxgi = verify_dll(&root, &source.dxgi)?;
    Ok(VerifiedDxvkPair { d3d11, dxgi })
}

pub fn verify_vulkan_device(
    root: &Path,
    source: &VulkanSource,
    command: &dyn ProbeCommand,
) -> Result<VerifiedVulkanDevice, EvidenceFailure> {
    for entrypoint in [&source.probe, &source.icd_manifest] {
        validate_linux_relative_path("vulkan.path", &entrypoint.path).map_err(|_| EvidenceFailure::Entrypoint)?;
        validate_linux_digest("vulkan.digest", &entrypoint.digest).map_err(|_| EvidenceFailure::Digest)?;
    }
    if Path::new(&source.probe.path).file_name().and_then(|name| name.to_str()) != Some("vulkaninfo")
        || Path::new(&source.icd_manifest.path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some("lvp_icd.json")
    {
        return Err(EvidenceFailure::Entrypoint);
    }
    let root = fs::canonicalize(root).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    let probe = verify_entrypoint(&root, &source.probe)?;
    let icd_manifest = verify_regular_file(&root, &source.icd_manifest)?;
    let specification = ProbeCommandSpec {
        executable: probe.clone(),
        arguments: vec![OsString::from("--text")],
        working_directory: root.clone(),
        environment: BTreeMap::from([
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (
                OsString::from("VK_ICD_FILENAMES"),
                icd_manifest.clone().into_os_string(),
            ),
        ]),
        deadline: Instant::now() + VULKAN_PROBE_TIMEOUT,
        combined_output_limit: MAX_VULKAN_OUTPUT_BYTES,
    };
    let output = command.run(&specification).map_err(|_| EvidenceFailure::Command)?;
    if Instant::now() >= specification.deadline
        || output.status != ProbeCommandStatus::Success
        || output.stdout.len().saturating_add(output.stderr.len()) > MAX_VULKAN_OUTPUT_BYTES
    {
        return Err(EvidenceFailure::Command);
    }
    let (api_version, device_name) = parse_vulkan_device(&output.stdout)?;
    if verify_entrypoint(&root, &source.probe)? != probe
        || verify_regular_file(&root, &source.icd_manifest)? != icd_manifest
    {
        return Err(EvidenceFailure::Digest);
    }
    Ok(VerifiedVulkanDevice {
        api_version,
        device_name,
        probe,
        icd_manifest,
    })
}

fn verify_regular_file(root: &Path, file: &VerifiedEntrypoint) -> Result<PathBuf, EvidenceFailure> {
    let candidate = root.join(&file.path);
    let metadata = fs::symlink_metadata(&candidate).map_err(|_| EvidenceFailure::Entrypoint)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 4096 {
        return Err(EvidenceFailure::Entrypoint);
    }
    let canonical = fs::canonicalize(&candidate).map_err(|_| EvidenceFailure::Entrypoint)?;
    if canonical != candidate || !canonical.starts_with(root) {
        return Err(EvidenceFailure::Entrypoint);
    }
    if sha256_file(&canonical)? != file.digest {
        return Err(EvidenceFailure::Digest);
    }
    Ok(canonical)
}

fn parse_vulkan_device(bytes: &[u8]) -> Result<(String, String), EvidenceFailure> {
    let text = std::str::from_utf8(bytes).map_err(|_| EvidenceFailure::Command)?;
    let lines = text.lines().map(str::trim).collect::<Vec<_>>();
    let value = |name: &str| -> Option<&str> {
        lines.iter().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.trim_start().strip_prefix('='))
                .map(str::trim)
        })
    };
    let api_version = value("apiVersion")
        .and_then(|value| value.split_whitespace().next())
        .ok_or(EvidenceFailure::Command)?;
    let mut numbers = api_version.split('.').filter_map(|part| part.parse::<u32>().ok());
    let major = numbers.next().ok_or(EvidenceFailure::Command)?;
    let minor = numbers.next().ok_or(EvidenceFailure::Command)?;
    if major < 1
        || (major == 1 && minor < 3)
        || value("deviceType") != Some("PHYSICAL_DEVICE_TYPE_CPU")
        || value("maxPushConstantsSize")
            .and_then(|value| value.parse::<u32>().ok())
            .map_or(true, |size| size < 256)
    {
        return Err(EvidenceFailure::Command);
    }
    let device_name = value("deviceName")
        .and_then(|value| value.split_whitespace().next())
        .filter(|name| *name == "llvmpipe")
        .ok_or(EvidenceFailure::Command)?;
    for extension in [
        "VK_EXT_depth_clip_enable",
        "VK_EXT_robustness2",
        "VK_EXT_transform_feedback",
        "VK_KHR_load_store_op_none",
        "VK_KHR_maintenance5",
    ] {
        if !lines
            .iter()
            .any(|line| line.starts_with(extension) && line.contains(": extension revision "))
        {
            return Err(EvidenceFailure::Command);
        }
    }
    for feature in ["shaderInt64", "shaderInt16", "shaderInt8", "scalarBlockLayout"] {
        if value(feature) != Some("true") {
            return Err(EvidenceFailure::Command);
        }
    }
    Ok((api_version.to_owned(), device_name.to_owned()))
}

fn verify_dll(root: &Path, entrypoint: &VerifiedEntrypoint) -> Result<PathBuf, EvidenceFailure> {
    let candidate = root.join(&entrypoint.path);
    let metadata = fs::symlink_metadata(&candidate).map_err(|_| EvidenceFailure::Entrypoint)?;
    if !metadata.file_type().is_file() || metadata.len() < 512 || metadata.len() > MAX_DXVK_DLL_BYTES {
        return Err(EvidenceFailure::Entrypoint);
    }
    let canonical = fs::canonicalize(&candidate).map_err(|_| EvidenceFailure::Entrypoint)?;
    if canonical != candidate || !canonical.starts_with(root) {
        return Err(EvidenceFailure::Entrypoint);
    }
    if sha256_file(&canonical)? != entrypoint.digest {
        return Err(EvidenceFailure::Digest);
    }
    let mut header = [0_u8; PE_HEADER_BYTES];
    fs::File::open(&canonical)
        .map_err(|_| EvidenceFailure::Elf)?
        .read_exact(&mut header)
        .map_err(|_| EvidenceFailure::Elf)?;
    if &header[0..2] != b"MZ" {
        return Err(EvidenceFailure::Elf);
    }
    let offset = u32::from_le_bytes(header[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = header
        .get(offset..offset.saturating_add(24))
        .ok_or(EvidenceFailure::Elf)?;
    if &coff[0..4] != b"PE\0\0" {
        return Err(EvidenceFailure::Elf);
    }
    if u16::from_le_bytes(coff[4..6].try_into().unwrap()) != 0x8664 {
        return Err(EvidenceFailure::Architecture);
    }
    let optional_magic = header.get(offset + 24..offset + 26).ok_or(EvidenceFailure::Elf)?;
    if u16::from_le_bytes(coff[22..24].try_into().unwrap()) & 0x2000 == 0
        || u16::from_le_bytes(optional_magic.try_into().unwrap()) != 0x20b
    {
        return Err(EvidenceFailure::Elf);
    }
    Ok(canonical)
}
