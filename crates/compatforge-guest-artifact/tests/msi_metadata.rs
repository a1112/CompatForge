use compatforge_domain::{CpuArchitecture, InstallPackage};
use compatforge_guest_artifact::inspect_msi_package;
use sha2::{Digest, Sha256};
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn fixture(
    kind: msi::PackageType,
    arch: &str,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> (std::path::PathBuf, InstallPackage) {
    let root = std::env::temp_dir().join(format!(
        "cf-msi-meta-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("canary.msi");
    let mut pkg = msi::Package::create(kind, fs::File::create(&path).unwrap()).unwrap();
    pkg.summary_info_mut().set_arch(arch);
    pkg.flush().unwrap();
    drop(pkg);
    let mut bytes = fs::read(&path).unwrap();
    mutate(&mut bytes);
    fs::write(&path, &bytes).unwrap();
    let p = InstallPackage {
        path: path.to_string_lossy().into(),
        file_name: "canary.msi".into(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        size_bytes: bytes.len() as u64,
        media_type: "application/x-msi".into(),
    };
    (root, p)
}
#[test]
fn bounds_declared_minifat_before_dependency_allocation() {
    let (root, p) = fixture(msi::PackageType::Installer, "x64", |b| {
        b[64..68].copy_from_slice(&u32::MAX.to_le_bytes())
    });
    let error = inspect_msi_package(&p, CpuArchitecture::X86_64).unwrap_err();
    assert!(error.to_string().contains("MiniFAT allocation"));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn inspects_installer_type_and_template_architecture_without_staging() {
    for (kind, arch, expected) in [
        (msi::PackageType::Installer, "x64", true),
        (msi::PackageType::Installer, "Intel", false),
        (msi::PackageType::Installer, "Arm64", false),
        (msi::PackageType::Patch, "x64", false),
        (msi::PackageType::Transform, "x64", false),
    ] {
        let (root, p) = fixture(kind, arch, |_| {});
        assert_eq!(inspect_msi_package(&p, CpuArchitecture::X86_64).is_ok(), expected);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
