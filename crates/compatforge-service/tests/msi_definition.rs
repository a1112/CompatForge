use compatforge_service::{ApplicationDefinition, InstallerDefinition};
use serde_json::{json, Value};
fn app() -> Value {
    json!({"schemaVersion":"1", "id":"msi-canary", "name":"MSI Canary", "version":"1.0", "publisher":"test", "category":"utilities", "bottleId":"msi-canary",
        "installer":{"fileName":"canary.msi", "sha256":"a".repeat(64), "msi":{"sizeBytes":1299197952_u64,"architecture":"x86_64", "handler":{"kind":"msiexec","action":"install","ui":"none","reboot":"suppress","properties":{}},"maximumRuntimeMilliseconds":120000}},
        "launchers":[{"id":"main", "name":"Canary", "executable":"Program Files/Canary/canary.exe"}]})
}
#[test]
fn legacy_installer_serialization_has_no_new_field() {
    let legacy = json!({"fileName":"old.exe", "sha256":"a".repeat(64), "arguments":["/S"]});
    let definition: InstallerDefinition = serde_json::from_value(legacy.clone()).unwrap();
    assert!(definition.msi.is_none());
    assert_eq!(serde_json::to_value(definition).unwrap(), legacy);
}
#[test]
fn validates_closed_msi_definition_and_rejects_raw_arguments_size_and_identity() {
    serde_json::from_value::<ApplicationDefinition>(app())
        .unwrap()
        .validate()
        .unwrap();
    for (field, value) in [
        ("sizeBytes", json!(2147483649_u64)),
        ("sizeBytes", json!(true)),
        ("architecture", json!("arm64")),
        ("maximumRuntimeMilliseconds", json!(0)),
        ("arguments", json!(["/forcerestart"])),
    ] {
        let mut changed = app();
        changed["installer"]["msi"][field] = value;
        assert!(
            serde_json::from_value::<ApplicationDefinition>(changed)
                .map(|d| d.validate().is_err())
                .unwrap_or(true),
            "{field}"
        );
    }
    let mut changed = app();
    changed["installer"]["arguments"] = json!(["TRANSFORMS=evil.mst"]);
    assert!(serde_json::from_value::<ApplicationDefinition>(changed)
        .unwrap()
        .validate()
        .is_err());
    let mut changed = app();
    changed["installer"].as_object_mut().unwrap().remove("sha256");
    assert!(serde_json::from_value::<ApplicationDefinition>(changed)
        .unwrap()
        .validate()
        .is_err());
    let mut changed = app();
    changed["installer"]["fileName"] = json!("canary.exe");
    assert!(serde_json::from_value::<ApplicationDefinition>(changed)
        .unwrap()
        .validate()
        .is_err());
}
