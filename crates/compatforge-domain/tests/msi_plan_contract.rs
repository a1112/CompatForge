use compatforge_domain::{CoreConfig, LaunchPlan};
use serde_json::{json, Value};

fn tool() -> Value {
    json!({"packId":"wine-pack", "packDigest":format!("sha256:{}", "a".repeat(64)),
        "path":std::env::temp_dir().join("msiexec.exe"), "digest":format!("sha256:{}", "b".repeat(64)), "architecture":"x86_64"})
}

#[test]
fn accepts_separate_installer_policy_and_rejects_identity_drift() {
    let mut value: Value =
        serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
    let mut t = tool();
    t["packId"] = value["runtimeBindings"][0]["packId"].clone();
    t["packDigest"] = value["runtimeBindings"][0]["packDigest"].clone();
    value["wineInstallerTools"] = json!([t.clone()]);
    serde_json::from_value::<CoreConfig>(value.clone())
        .unwrap()
        .validate()
        .unwrap();
    for field in ["packId", "packDigest", "digest", "architecture", "path"] {
        let mut changed = value.clone();
        changed["wineInstallerTools"][0][field] = json!("invalid");
        assert!(
            serde_json::from_value::<CoreConfig>(changed)
                .map(|c| c.validate().is_err())
                .unwrap_or(true),
            "{field}"
        );
    }
    value["wineInstallerTools"] = json!([t.clone(), t]);
    assert!(serde_json::from_value::<CoreConfig>(value).unwrap().validate().is_err());
}

#[test]
fn msi_plan_binds_closed_arguments_package_runtime_and_deadline() {
    let mut value: Value = serde_json::from_str(include_str!("../../../examples/launch-plan.json")).unwrap();
    let mut t = tool();
    t["packId"] = value["runtime"]["packId"].clone();
    t["packDigest"] = value["runtime"]["packDigest"].clone();
    let package = std::env::temp_dir().join("canary.msi");
    let stored = std::env::temp_dir().join("objects/package.msi");
    value["msiInstall"] = json!({"package":{"package":{"path":package,"fileName":"canary.msi","sha256":"c".repeat(64),"sizeBytes":16384,"mediaType":"application/x-msi"},"storedPath":stored,"architecture":"x86_64"},
        "handler":{"kind":"msiexec","action":"install","ui":"none","reboot":"suppress","properties":{}},"tool":t,"maximumRuntimeMilliseconds":120000});
    value["process"]["arguments"] = json!([t["path"], "/i", stored, "/qn", "/norestart", "REBOOT=ReallySuppress"]);
    value["lifecycle"]["maximumRuntimeMilliseconds"] = json!(120000);
    serde_json::from_value::<LaunchPlan>(value.clone())
        .unwrap()
        .validate()
        .unwrap();
    for (field, changed_value) in [
        ("arguments", json!([t["path"], "/i", stored, "/forcerestart"])),
        ("arguments", json!(["msiexec", "/i", stored])),
    ] {
        let mut changed = value.clone();
        changed["process"][field] = changed_value;
        assert!(serde_json::from_value::<LaunchPlan>(changed)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut changed = value.clone();
    changed["msiInstall"]["tool"]["packId"] = json!("other-pack");
    assert!(serde_json::from_value::<LaunchPlan>(changed)
        .unwrap()
        .validate()
        .is_err());
    let mut changed = value;
    changed["lifecycle"]["maximumRuntimeMilliseconds"] = json!(3600000);
    assert!(serde_json::from_value::<LaunchPlan>(changed)
        .unwrap()
        .validate()
        .is_err());
}
