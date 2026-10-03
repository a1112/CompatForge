use compatforge_domain::{CoreConfig, CpuArchitecture, InstallRequest};
use compatforge_orchestrator::{InstallIntent, InstallLaunchOptions, PolicyEngine};
use serde_json::json;

fn input() -> (CoreConfig, InstallRequest) {
    let mut config: CoreConfig =
        serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
    config.capabilities.host.architecture = CpuArchitecture::X86_64;
    config.storage_root = std::env::temp_dir().join("cf-msi-plan-tests").to_string_lossy().into();
    config.supervisor.maximum_runtime_milliseconds = Some(60000);
    let binding = &config.runtime_bindings[0];
    config.wine_installer_tools = vec![serde_json::from_value(json!({"packId":binding.pack_id, "packDigest":binding.pack_digest,
        "path":std::env::temp_dir().join("msiexec.exe"), "digest":format!("sha256:{}", "a".repeat(64)), "architecture":"x86_64"})).unwrap()];
    let request = serde_json::from_value(json!({"schemaVersion":"1", "requestId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "bottleId":"msi-canary",
        "package":{"path":std::env::temp_dir().join("canary.msi"),"fileName":"canary.msi","sha256":"b".repeat(64),"sizeBytes":1299197952_u64,"mediaType":"application/x-msi"},
        "handler":{"kind":"msiexec","action":"install","ui":"none","reboot":"suppress","properties":{}},
        "constraints":{"allowVirtualMachine":false,"allowRemote":false,"networkPolicy":"deny","maximumRuntimeMilliseconds":120000}})).unwrap();
    (config, request)
}

#[test]
fn compiles_a_closed_intent_without_claiming_package_inspection() {
    let (config, request) = input();
    let intent = InstallIntent::compile(
        &config,
        &request,
        CpuArchitecture::X86_64,
        InstallLaunchOptions::default(),
    )
    .unwrap();
    let plan = intent.plan();
    assert!(plan.guest_artifact.is_none() && plan.bottle_executable.is_none());
    assert_eq!(plan.lifecycle.maximum_runtime_milliseconds, Some(60000));
    assert_eq!(plan.process.arguments[1], "/i");
    assert_eq!(plan.process.arguments[4], "/norestart");
    PolicyEngine::authorize(&config, plan).unwrap();
}

#[test]
fn rejects_missing_tools_cross_runtime_architecture_and_policy_revocation() {
    let (mut config, request) = input();
    assert!(InstallIntent::compile(
        &config,
        &request,
        CpuArchitecture::I386,
        InstallLaunchOptions::default()
    )
    .is_err());
    let intent = InstallIntent::compile(
        &config,
        &request,
        CpuArchitecture::X86_64,
        InstallLaunchOptions::default(),
    )
    .unwrap();
    config.wine_installer_tools.clear();
    assert!(PolicyEngine::authorize(&config, intent.plan()).is_err());
    assert!(InstallIntent::compile(
        &config,
        &request,
        CpuArchitecture::X86_64,
        InstallLaunchOptions::default()
    )
    .is_err());
}

#[test]
fn rejects_plan_package_escape_command_injection_and_lifecycle_drift() {
    let (config, request) = input();
    let intent = InstallIntent::compile(
        &config,
        &request,
        CpuArchitecture::X86_64,
        InstallLaunchOptions::default(),
    )
    .unwrap();
    let mut plan = intent.plan().clone();
    plan.msi_install.as_mut().unwrap().package.stored_path =
        std::env::temp_dir().join("outside.msi").to_string_lossy().into();
    plan.process.arguments = plan.msi_install.as_ref().unwrap().arguments().unwrap();
    assert!(PolicyEngine::authorize(&config, &plan).is_err());
    let mut plan = intent.plan().clone();
    plan.process.arguments.push("TRANSFORMS=evil.mst".into());
    assert!(PolicyEngine::authorize(&config, &plan).is_err());
    let mut plan = intent.plan().clone();
    plan.msi_install.as_mut().unwrap().maximum_runtime_milliseconds = 120000;
    plan.lifecycle.maximum_runtime_milliseconds = Some(120000);
    assert!(PolicyEngine::authorize(&config, &plan).is_err());
    let mut plan = intent.plan().clone();
    plan.lifecycle.wineserver = None;
    assert!(PolicyEngine::authorize(&config, &plan).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn prepares_real_compound_bytes_and_rejects_source_tool_context_drift() {
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    let (mut config, mut request) = input();
    let root = std::env::temp_dir().join(format!("cf-prepared-msi-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    config.storage_root = root.join("store").to_string_lossy().into();
    let source = root.join("canary.msi");
    let mut package = msi::Package::create(msi::PackageType::Installer, fs::File::create(&source).unwrap()).unwrap();
    package.summary_info_mut().set_arch("x64");
    package.flush().unwrap();
    drop(package);
    let bytes = fs::read(&source).unwrap();
    request.package.path = source.to_string_lossy().into();
    request.package.sha256 = format!("{:x}", Sha256::digest(&bytes));
    request.package.size_bytes = bytes.len() as u64;
    let tool = root.join("msiexec.exe");
    let pe = include_bytes!("../../../tests/fixtures/hello-x86_64.exe");
    fs::write(&tool, pe).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o400)).unwrap();
    config.wine_installer_tools[0].path = tool.to_string_lossy().into();
    config.wine_installer_tools[0].digest = format!("sha256:{:x}", Sha256::digest(pe));
    let intent = InstallIntent::compile(
        &config,
        &request,
        CpuArchitecture::X86_64,
        InstallLaunchOptions::default(),
    )
    .unwrap();
    let prepared = intent.prepare(&config, None).unwrap();
    prepared.authorize(&config).unwrap();
    let mut changed = config.clone();
    changed.supervisor.maximum_runtime_milliseconds = Some(120000);
    assert!(prepared.authorize(&changed).is_err());
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&tool, b"tool replaced").unwrap();
    assert!(prepared.authorize(&config).is_err());
    fs::write(&tool, pe).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o400)).unwrap();
    fs::write(&source, b"package replaced").unwrap();
    assert!(prepared.authorize(&config).is_err());
    fs::remove_dir_all(root).unwrap();
}
