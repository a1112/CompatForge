#![cfg(target_os = "linux")]

use compatforge_provider_linux::{
    verify_dxvk_pair, verify_vulkan_device, DxvkSource, EvidenceFailure, ProbeCommand, ProbeCommandFailure,
    ProbeCommandOutput, ProbeCommandSpec, ProbeCommandStatus, VerifiedEntrypoint, VulkanSource,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{
    ffi::{OsStr, OsString},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    source: DxvkSource,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "compatforge-dxvk-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("x64")).unwrap();
        let d3d11 = pe64_dll();
        let dxgi = pe64_dll();
        fs::write(root.join("x64/d3d11.dll"), &d3d11).unwrap();
        fs::write(root.join("x64/dxgi.dll"), &dxgi).unwrap();
        let source = DxvkSource {
            version: "2.7.1".into(),
            d3d11: VerifiedEntrypoint {
                path: "x64/d3d11.dll".into(),
                digest: sha256(&d3d11),
            },
            dxgi: VerifiedEntrypoint {
                path: "x64/dxgi.dll".into(),
                digest: sha256(&dxgi),
            },
        };
        Self { root, source }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn sha256(data: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(data))
}

fn pe64_dll() -> Vec<u8> {
    let mut bytes = vec![0_u8; 512];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[0x96..0x98].copy_from_slice(&0x2000_u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes
}

#[test]
fn verified_pair_requires_exact_x64_pe_dlls() {
    let fixture = Fixture::new();
    let pair = verify_dxvk_pair(&fixture.root, &fixture.source).unwrap();
    assert_eq!(pair.d3d11, fixture.root.join("x64/d3d11.dll"));
    assert_eq!(pair.dxgi, fixture.root.join("x64/dxgi.dll"));
}

#[test]
fn changed_or_wrong_architecture_dll_is_rejected() {
    let fixture = Fixture::new();
    let path = fixture.root.join("x64/d3d11.dll");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0x84] = 0x4c;
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        verify_dxvk_pair(&fixture.root, &fixture.source),
        Err(EvidenceFailure::Digest)
    );
    let mut source = fixture.source.clone();
    source.d3d11.digest = sha256(&bytes);
    assert_eq!(
        verify_dxvk_pair(&fixture.root, &source),
        Err(EvidenceFailure::Architecture)
    );
}

#[test]
fn split_directories_are_rejected() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("other")).unwrap();
    fs::copy(fixture.root.join("x64/dxgi.dll"), fixture.root.join("other/dxgi.dll")).unwrap();
    let mut source = fixture.source.clone();
    source.dxgi.path = "other/dxgi.dll".into();
    assert_eq!(
        verify_dxvk_pair(&fixture.root, &source),
        Err(EvidenceFailure::Entrypoint)
    );
}

#[test]
fn truncated_optional_header_is_rejected_without_panicking() {
    let fixture = Fixture::new();
    let path = fixture.root.join("x64/d3d11.dll");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0x3c..0x40].copy_from_slice(&488_u32.to_le_bytes());
    bytes[488..492].copy_from_slice(b"PE\0\0");
    bytes[492..494].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[510..512].copy_from_slice(&0x2000_u16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    let mut source = fixture.source.clone();
    source.d3d11.digest = sha256(&bytes);
    assert_eq!(verify_dxvk_pair(&fixture.root, &source), Err(EvidenceFailure::Elf));
}

struct VulkanCommand {
    output: Vec<u8>,
}

impl ProbeCommand for VulkanCommand {
    fn run(&self, spec: &ProbeCommandSpec) -> Result<ProbeCommandOutput, ProbeCommandFailure> {
        assert_eq!(spec.arguments, [OsString::from("--text")]);
        assert_eq!(
            spec.environment.get(OsStr::new("VK_ICD_FILENAMES")),
            Some(
                &spec
                    .working_directory
                    .join("share/vulkan/icd.d/lvp_icd.json")
                    .into_os_string()
            ),
        );
        Ok(ProbeCommandOutput {
            status: ProbeCommandStatus::Success,
            stdout: self.output.clone(),
            stderr: Vec::new(),
        })
    }
}

fn vulkan_fixture() -> (Fixture, VulkanSource) {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("bin")).unwrap();
    fs::create_dir_all(fixture.root.join("share/vulkan/icd.d")).unwrap();
    let probe = fs::read(std::env::current_exe().unwrap()).unwrap();
    let icd = b"{\"ICD\":{\"library_path\":\"libvulkan_lvp.so\"}}";
    fs::write(fixture.root.join("bin/vulkaninfo"), &probe).unwrap();
    fs::set_permissions(fixture.root.join("bin/vulkaninfo"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(fixture.root.join("share/vulkan/icd.d/lvp_icd.json"), icd).unwrap();
    let source = VulkanSource {
        probe: VerifiedEntrypoint {
            path: "bin/vulkaninfo".into(),
            digest: sha256(&probe),
        },
        icd_manifest: VerifiedEntrypoint {
            path: "share/vulkan/icd.d/lvp_icd.json".into(),
            digest: sha256(icd),
        },
    };
    (fixture, source)
}

const VULKAN_INFO: &str = "apiVersion = 1.4.354\n\
deviceType = PHYSICAL_DEVICE_TYPE_CPU\n\
deviceName = llvmpipe\n\
maxPushConstantsSize = 256\n\
VK_EXT_depth_clip_enable : extension revision 1\n\
VK_EXT_robustness2 : extension revision 1\n\
VK_EXT_transform_feedback : extension revision 1\n\
VK_KHR_load_store_op_none : extension revision 1\n\
VK_KHR_maintenance5 : extension revision 1\n\
shaderInt64 = true\nshaderInt16 = true\nshaderInt8 = true\nscalarBlockLayout = true\n";

#[test]
fn vulkan_probe_requires_usable_software_device() {
    let (fixture, source) = vulkan_fixture();
    let observed = verify_vulkan_device(
        &fixture.root,
        &source,
        &VulkanCommand {
            output: VULKAN_INFO.as_bytes().to_vec(),
        },
    )
    .unwrap();
    assert_eq!(observed.api_version, "1.4.354");
    assert_eq!(observed.device_name, "llvmpipe");
}

#[test]
fn vulkan_probe_rejects_missing_required_feature_and_changed_icd() {
    let (fixture, source) = vulkan_fixture();
    let unavailable = VULKAN_INFO.replace("shaderInt8 = true", "shaderInt8 = false");
    assert_eq!(
        verify_vulkan_device(
            &fixture.root,
            &source,
            &VulkanCommand {
                output: unavailable.into_bytes()
            }
        ),
        Err(EvidenceFailure::Command),
    );
    fs::write(fixture.root.join("share/vulkan/icd.d/lvp_icd.json"), b"changed").unwrap();
    assert_eq!(
        verify_vulkan_device(
            &fixture.root,
            &source,
            &VulkanCommand {
                output: VULKAN_INFO.as_bytes().to_vec()
            }
        ),
        Err(EvidenceFailure::Digest),
    );
}
