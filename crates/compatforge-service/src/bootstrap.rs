//! Host-specific desktop bootstrap. Linux consumes an explicit verified provider
//! configuration; it never falls back to macOS discovery or PATH lookup.

use compatforge_domain::{CapabilityReport, CoreConfig, HostOs};
use compatforge_provider_linux::{LinuxProviderConfig, LinuxProviderSet};
use compatforge_provider_macos::MacOsLocalContextRequest;
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;

pub const MAX_PROVIDER_CONFIG_BYTES: u64 = 64 * 1024;

pub fn read_linux_provider_config(path: &Path) -> Result<LinuxProviderConfig, String> {
    if !path.is_absolute() {
        return Err("Linux Provider 配置必须使用绝对路径".into());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| format!("无法读取 Linux Provider 配置：{error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Linux Provider 配置必须是普通文件，不能使用符号链接".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not follow a raced symlink or block on a raced FIFO/device.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the entry, never its link target.
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("无法读取 Linux Provider 配置：{error}"))?;
    if !file.metadata().map_err(|error| error.to_string())?.is_file() {
        return Err("Linux Provider 配置必须是普通文件".into());
    }
    decode_linux_provider_config(file)
}

fn decode_linux_provider_config(reader: impl Read) -> Result<LinuxProviderConfig, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_PROVIDER_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_PROVIDER_CONFIG_BYTES {
        return Err("Linux Provider 配置超过 64 KiB".into());
    }
    let config: LinuxProviderConfig =
        serde_json::from_slice(&bytes).map_err(|error| format!("Linux Provider 配置无效：{error}"))?;
    config.validate().map_err(|error| error.to_string())?;
    Ok(config)
}

#[derive(Debug)]
pub enum DesktopContextRequest {
    MacOs(MacOsLocalContextRequest),
    Linux {
        provider: Box<LinuxProviderConfig>,
        storage_root: String,
    },
}

pub fn select_desktop_context(
    os: HostOs,
    macos: MacOsLocalContextRequest,
    linux: Option<LinuxProviderConfig>,
) -> Result<DesktopContextRequest, String> {
    match os {
        HostOs::Linux => {
            let provider = linux.ok_or("Linux 需要显式运行时配置：--linux-provider-config /absolute/provider.json")?;
            if macos.materialized_root.is_some()
                || macos.wine.is_some()
                || macos.wineserver.is_some()
                || macos.version.is_some()
            {
                return Err("Linux 运行时只接受 --linux-provider-config，不接受 macOS Wine 覆盖参数".into());
            }
            provider
                .validate()
                .map_err(|error| format!("Linux 运行时配置无效：{error}"))?;
            Ok(DesktopContextRequest::Linux {
                provider: Box::new(provider),
                storage_root: macos.storage_root,
            })
        }
        HostOs::MacOs if linux.is_none() => Ok(DesktopContextRequest::MacOs(macos)),
        HostOs::MacOs => Err("macOS 不接受 Linux 运行时配置".into()),
        _ => Err("桌面运行时当前仅支持 Linux 和 macOS".into()),
    }
}

pub struct DesktopContext {
    pub config: CoreConfig,
    pub receipt: Value,
    pub version: String,
    pub pack_id: String,
}

/// Blocking provider work: invoke on a worker thread, never on a UI event loop.
pub fn create_desktop_context(
    host: &CapabilityReport,
    request: DesktopContextRequest,
) -> Result<DesktopContext, String> {
    match request {
        DesktopContextRequest::Linux { provider, storage_root } => {
            if host.host.os != HostOs::Linux {
                return Err("Linux 运行时与当前主机不匹配".into());
            }
            let snapshot = LinuxProviderSet::probe(host, &provider).map_err(|error| error.to_string())?;
            let config = snapshot.core_config(storage_root).map_err(|error| error.to_string())?;
            let runtime = provider.wine_runtime;
            Ok(DesktopContext {
                config,
                receipt: json!({ "schemaVersion": "1", "source": "explicit-linux-provider", "version": runtime.version,
                    "packId": runtime.pack_id, "packDigest": runtime.pack_digest, "architecture": runtime.architecture,
                    "capabilities": runtime.capabilities }),
                version: runtime.version,
                pack_id: runtime.pack_id,
            })
        }
        DesktopContextRequest::MacOs(request) => {
            if host.host.os != HostOs::MacOs {
                return Err("macOS 运行时与当前主机不匹配".into());
            }
            let local =
                compatforge_provider_macos::create_local_context(host, &request).map_err(|error| error.to_string())?;
            Ok(DesktopContext {
                config: local.config,
                receipt: serde_json::to_value(&local.receipt).map_err(|error| error.to_string())?,
                version: local.receipt.version,
                pack_id: local.receipt.pack_id,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::{CpuArchitecture, SCHEMA_VERSION_V1};
    use compatforge_provider_linux::{VerifiedEntrypoint, WineRuntimeConfig};

    fn macos_request() -> MacOsLocalContextRequest {
        MacOsLocalContextRequest {
            schema_version: SCHEMA_VERSION_V1.into(),
            runtime_store_root: "/private/runtime".into(),
            storage_root: "/private/storage".into(),
            materialized_root: None,
            wine: None,
            wineserver: None,
            version: None,
        }
    }

    fn linux_config() -> LinuxProviderConfig {
        LinuxProviderConfig {
            schema_version: SCHEMA_VERSION_V1.into(),
            runtime_store_root: "/explicit/runtime".into(),
            wine_runtime: WineRuntimeConfig {
                provider_id: "linux-wine".into(),
                pack_id: "wine-test".into(),
                pack_digest: format!("sha256:{}", "1".repeat(64)),
                version: "11.0".into(),
                architecture: CpuArchitecture::X86_64,
                materialized_root: "/explicit/wine".into(),
                wine: VerifiedEntrypoint {
                    path: "bin/wine".into(),
                    digest: format!("sha256:{}", "2".repeat(64)),
                },
                wineserver: VerifiedEntrypoint {
                    path: "bin/wineserver".into(),
                    digest: format!("sha256:{}", "3".repeat(64)),
                },
                capabilities: vec!["guest-x86_64".into()],
                wined3d_capabilities: vec!["opengl".into()],
            },
            dxvk_graphics: None,
            bottle_font: None,
        }
    }

    #[test]
    fn linux_missing_configuration_never_selects_macos_discovery() {
        let error = select_desktop_context(HostOs::Linux, macos_request(), None).unwrap_err();
        assert!(error.contains("--linux-provider-config"));
    }

    #[test]
    fn linux_host_cannot_execute_a_macos_request_even_if_selection_is_bypassed() {
        let mut report: CapabilityReport =
            serde_json::from_str(include_str!("../../../examples/capability-report.linux-arm64.json")).unwrap();
        report.host.os = HostOs::Linux;
        let result = create_desktop_context(&report, DesktopContextRequest::MacOs(macos_request()));
        assert!(matches!(result, Err(error) if error == "macOS 运行时与当前主机不匹配"));
    }

    #[test]
    fn linux_selects_only_exact_pinned_provider_configuration() {
        let expected = linux_config();
        let selected = select_desktop_context(HostOs::Linux, macos_request(), Some(expected.clone())).unwrap();
        let DesktopContextRequest::Linux { provider, storage_root } = selected else {
            panic!("selected macOS on Linux")
        };
        assert_eq!(*provider, expected);
        assert_eq!(storage_root, "/private/storage");
    }

    #[test]
    fn macos_default_discovery_is_retained() {
        let selected = select_desktop_context(HostOs::MacOs, macos_request(), None).unwrap();
        let DesktopContextRequest::MacOs(request) = selected else {
            panic!("wrong provider")
        };
        assert!(request.materialized_root.is_none());
    }

    #[test]
    fn unsupported_hosts_and_cross_host_configuration_fail_closed() {
        assert!(select_desktop_context(HostOs::Windows, macos_request(), None).is_err());
        assert!(select_desktop_context(HostOs::MacOs, macos_request(), Some(linux_config())).is_err());
        let mut overridden = macos_request();
        overridden.materialized_root = Some("/mac/wine".into());
        assert!(select_desktop_context(HostOs::Linux, overridden, Some(linux_config())).is_err());
    }

    #[test]
    fn provider_file_is_bounded_and_rejects_unknown_fields() {
        let bytes = serde_json::to_vec(&linux_config()).unwrap();
        assert_eq!(decode_linux_provider_config(bytes.as_slice()).unwrap(), linux_config());
        let mut oversized = bytes;
        oversized.resize(MAX_PROVIDER_CONFIG_BYTES as usize + 1, b' ');
        assert!(decode_linux_provider_config(oversized.as_slice())
            .unwrap_err()
            .contains("64 KiB"));
        let mut value = serde_json::to_value(linux_config()).unwrap();
        value["discoverFromPath"] = true.into();
        assert!(decode_linux_provider_config(serde_json::to_vec(&value).unwrap().as_slice()).is_err());
        assert!(read_linux_provider_config(Path::new("relative-provider.json")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn provider_file_rejects_symlinks_directories_and_fifos_without_opening_them() {
        let root = std::env::temp_dir().join(format!(
            "compatforge-bootstrap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let config = root.join("provider.json");
        std::fs::write(&config, serde_json::to_vec(&linux_config()).unwrap()).unwrap();
        assert_eq!(read_linux_provider_config(&config).unwrap(), linux_config());
        let symlink = root.join("provider-link.json");
        std::os::unix::fs::symlink(&config, &symlink).unwrap();
        assert!(read_linux_provider_config(&symlink).is_err());
        assert!(read_linux_provider_config(&root).is_err());
        let fifo = root.join("provider.fifo");
        assert!(std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(read_linux_provider_config(&fifo).is_err());
        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_file(symlink).unwrap();
        std::fs::remove_file(config).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
