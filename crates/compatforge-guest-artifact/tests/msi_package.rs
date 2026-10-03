#![cfg(target_os = "linux")]
use compatforge_domain::{CpuArchitecture, InstallPackage};
use compatforge_guest_artifact::MsiPackageStore;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);

fn fixture(kind: msi::PackageType, arch: &str) -> (PathBuf, InstallPackage) {
    let root = std::env::temp_dir().join(format!(
        "cf-msi-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("canary.msi");
    let mut pkg = msi::Package::create(kind, fs::File::create(&path).unwrap()).unwrap();
    pkg.summary_info_mut().set_arch(arch);
    pkg.flush().unwrap();
    drop(pkg);
    let bytes = fs::read(&path).unwrap();
    let request = InstallPackage {
        path: path.to_string_lossy().into(),
        file_name: "canary.msi".into(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        size_bytes: bytes.len() as u64,
        media_type: "application/x-msi".into(),
    };
    (root, request)
}

#[test]
fn stages_actual_compound_installer_and_rechecks_source_and_object() {
    let (root, request) = fixture(msi::PackageType::Installer, "x64");
    let store = MsiPackageStore::new(root.join("store"));
    let binding = store.prepare(&request, CpuArchitecture::X86_64).unwrap();
    store.verify(&binding).unwrap();
    assert_eq!(
        fs::read(&binding.stored_path).unwrap(),
        fs::read(&request.path).unwrap()
    );
    fs::write(&request.path, b"source substitution").unwrap();
    assert!(store.verify(&binding).is_err());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn rejects_wrong_identity_architecture_and_non_installer_compound_file() {
    let (root, mut request) = fixture(msi::PackageType::Installer, "x64");
    let store = MsiPackageStore::new(root.join("store"));
    assert!(store.prepare(&request, CpuArchitecture::I386).is_err());
    request.size_bytes += 1;
    assert!(store.prepare(&request, CpuArchitecture::X86_64).is_err());
    request.size_bytes -= 1;
    request.sha256 = "0".repeat(64);
    assert!(store.prepare(&request, CpuArchitecture::X86_64).is_err());
    fs::remove_dir_all(&root).unwrap();
    for kind in [msi::PackageType::Patch, msi::PackageType::Transform] {
        let (root, request) = fixture(kind, "x64");
        assert!(MsiPackageStore::new(root.join("store"))
            .prepare(&request, CpuArchitecture::X86_64)
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn rejects_replaced_stored_object_and_paths_outside_store() {
    let (root, request) = fixture(msi::PackageType::Installer, "x64");
    let store = MsiPackageStore::new(root.join("store"));
    let mut binding = store.prepare(&request, CpuArchitecture::X86_64).unwrap();
    let original = binding.stored_path.clone();
    binding.stored_path = request.path.clone();
    assert!(store.verify(&binding).is_err());
    binding.stored_path = original;
    fs::set_permissions(&binding.stored_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&binding.stored_path, b"object substitution").unwrap();
    assert!(store.verify(&binding).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_symlink_source_and_storage_ancestor() {
    use std::os::unix::fs::symlink;
    let (root, mut request) = fixture(msi::PackageType::Installer, "x64");
    let alias = root.join("alias.msi");
    symlink(&request.path, &alias).unwrap();
    request.path = alias.to_string_lossy().into();
    request.file_name = "alias.msi".into();
    assert!(MsiPackageStore::new(root.join("store"))
        .prepare(&request, CpuArchitecture::X86_64)
        .is_err());
    request.path = root.join("canary.msi").to_string_lossy().into();
    request.file_name = "canary.msi".into();
    symlink(&root, root.join("linked")).unwrap();
    assert!(MsiPackageStore::new(root.join("linked/store"))
        .prepare(&request, CpuArchitecture::X86_64)
        .is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fifo_child() {
    let Some(root) = std::env::var_os("COMPATFORGE_MSI_FIFO_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let request: InstallPackage = read_fifo_identity(&root);
    assert!(MsiPackageStore::new(root.join("store"))
        .prepare(&request, CpuArchitecture::X86_64)
        .is_err());
}

fn read_fifo_identity(root: &std::path::Path) -> InstallPackage {
    let bytes = fs::read(root.join("identity")).unwrap();
    let fields = String::from_utf8(bytes).unwrap();
    let (size, hash) = fields.split_once('\n').unwrap();
    InstallPackage {
        path: root.join("canary.msi").to_string_lossy().into(),
        file_name: "canary.msi".into(),
        sha256: hash.into(),
        size_bytes: size.parse().unwrap(),
        media_type: "application/x-msi".into(),
    }
}

#[test]
fn rejects_fifo_source_and_existing_object_without_waiting_for_writer() {
    use rustix::fs::{mknodat, FileType, Mode, CWD};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for source_fifo in [true, false] {
        let (root, request) = fixture(msi::PackageType::Installer, "x64");
        fs::write(
            root.join("identity"),
            format!("{}\n{}", request.size_bytes, request.sha256),
        )
        .unwrap();
        let path = if source_fifo {
            fs::remove_file(&request.path).unwrap();
            PathBuf::from(&request.path)
        } else {
            let parent = root
                .join("store/installer-packages/objects/sha256")
                .join(&request.sha256);
            fs::create_dir_all(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
            parent.join("package.msi")
        };
        mknodat(CWD, &path, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fifo_child"])
            .env("COMPATFORGE_MSI_FIFO_TEST_ROOT", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        fs::remove_dir_all(root).unwrap();
        assert!(
            status.is_some_and(|s| s.success()),
            "FIFO should fail without waiting for a writer: source={source_fifo}"
        );
    }
}

#[test]
fn cancelled_preparation_does_not_read_source_or_create_objects() {
    use std::sync::atomic::AtomicBool;
    let (root, request) = fixture(msi::PackageType::Installer, "x64");
    let flag = AtomicBool::new(true);
    fs::remove_file(&request.path).unwrap();
    let error = MsiPackageStore::new(root.join("store"))
        .prepare_cancellable(&request, CpuArchitecture::X86_64, Some(&flag))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    assert!(!root.join("store").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pins_package_and_tool_handles_across_path_substitution_and_detects_held_byte_drift() {
    use compatforge_domain::{InstallHandler, InstallUi, MsiInstallBinding, RuntimeInstallerTool};
    use compatforge_guest_artifact::PinnedMsiInputs;
    let (root, request) = fixture(msi::PackageType::Installer, "x64");
    let package = MsiPackageStore::new(root.join("store"))
        .prepare(&request, CpuArchitecture::X86_64)
        .unwrap();
    let path = root.join("msiexec.exe");
    let bytes = include_bytes!("../../../tests/fixtures/hello-x86_64.exe");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let binding = MsiInstallBinding {
        package,
        handler: InstallHandler {
            kind: "msiexec".into(),
            action: "install".into(),
            ui: InstallUi::None,
            reboot: "suppress".into(),
            properties: Default::default(),
        },
        tool: RuntimeInstallerTool {
            pack_id: "wine-test".into(),
            pack_digest: format!("sha256:{}", "a".repeat(64)),
            path: path.to_string_lossy().into(),
            digest: format!("sha256:{:x}", Sha256::digest(bytes)),
            architecture: CpuArchitecture::X86_64,
        },
        maximum_runtime_milliseconds: 120000,
    };
    let pinned = PinnedMsiInputs::pin(&binding, None).unwrap();
    let original_package = PathBuf::from(&binding.package.stored_path).with_file_name("retained.msi");
    fs::rename(&binding.package.stored_path, &original_package).unwrap();
    fs::write(&binding.package.stored_path, b"replacement").unwrap();
    let original_tool = root.join("retained-msiexec.exe");
    fs::rename(&path, &original_tool).unwrap();
    fs::write(&path, b"replacement").unwrap();
    pinned.revalidate(None).unwrap();
    assert!(PinnedMsiInputs::pin(&binding, None).is_err());
    let arguments = pinned.execution_arguments().unwrap();
    assert!(arguments[0].starts_with(&format!(r"\\?\unix\proc\{}\fd\", std::process::id())));
    assert!(arguments[2].starts_with(&format!(r"\\?\unix\proc\{}\fd\", std::process::id())));
    assert_eq!(&arguments[3..], &["/qn", "/norestart", "REBOOT=ReallySuppress"]);
    fs::set_permissions(&original_tool, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&original_tool, b"held inode modified").unwrap();
    assert!(pinned.revalidate(None).is_err());
    drop(pinned);
    fs::remove_dir_all(root).unwrap();
}
