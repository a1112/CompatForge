use compatforge_domain::InstallRequest;
use serde_json::{json, Value};

fn request() -> Value {
    let path = std::env::temp_dir().join("canary.msi");
    json!({
        "schemaVersion":"1", "requestId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "bottleId":"msi-canary",
        "package":{"path":path,"fileName":"canary.msi","sha256":"a".repeat(64),"sizeBytes":1299197952_u64,"mediaType":"application/x-msi"},
        "handler":{"kind":"msiexec","action":"install","ui":"none","reboot":"suppress","properties":{}},
        "constraints":{"allowVirtualMachine":false,"allowRemote":false,"networkPolicy":"deny","maximumRuntimeMilliseconds":120000}
    })
}

#[test]
fn accepts_real_jasp_size_and_bounded_installer_settings() {
    let mut value = request();
    for size in [1299197952_u64, 2147483648] {
        value["package"]["sizeBytes"] = json!(size);
        serde_json::from_value::<InstallRequest>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
    }
    value["package"]["sizeBytes"] = json!(2147483649_u64);
    assert!(serde_json::from_value::<InstallRequest>(value)
        .unwrap()
        .validate()
        .is_err());
}

#[test]
fn rejects_unsafe_installer_properties_and_raw_arguments() {
    serde_json::from_value::<InstallRequest>(request())
        .unwrap()
        .validate()
        .unwrap();
    for (key, value) in [
        ("TRANSFORMS", "evil.mst"),
        ("REBOOT", "Force"),
        ("INSTALLDIR", "https://example.com/install"),
        ("INSTALLFOLDER", "C:\\good\" /forcerestart"),
        ("INSTALLFOLDER", "C:\\good\nBAD=1"),
        ("INSTALLDIR", "C:\\good\\..\\outside"),
    ] {
        let mut r = request();
        r["handler"]["properties"] = json!({key:value});
        assert!(
            serde_json::from_value::<InstallRequest>(r).unwrap().validate().is_err(),
            "{key}={value}"
        );
    }
    let mut r = request();
    r["handler"]["arguments"] = json!(["/forcerestart"]);
    assert!(serde_json::from_value::<InstallRequest>(r).is_err());
}

#[test]
fn rejects_path_name_drift_and_unknown_nested_fields() {
    for (key, value) in [
        ("path", json!("https://example.com/canary.msi")),
        ("path", json!("/fixtures/../canary.msi")),
        ("fileName", json!("other.msi")),
        ("sizeBytes", json!(true)),
        ("mediaType", json!("application/x-msix")),
        ("extra", json!(true)),
    ] {
        let mut r = request();
        r["package"][key] = value;
        assert!(
            serde_json::from_value::<InstallRequest>(r)
                .map(|r| r.validate().is_err())
                .unwrap_or(true),
            "{key}"
        );
    }
}

#[test]
fn shares_filename_and_directory_boundaries_with_python_and_schema() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/msi-validation-vectors.json")).unwrap();
    for case in vectors["fileNames"].as_array().unwrap() {
        let mut r = request();
        let name = case["value"].as_str().unwrap();
        r["package"]["fileName"] = json!(name);
        r["package"]["path"] = json!(std::env::temp_dir().join(name));
        assert_eq!(
            serde_json::from_value::<InstallRequest>(r).unwrap().validate().is_ok(),
            case["valid"].as_bool().unwrap(),
            "{name:?}"
        );
    }
    for case in vectors["installDirectories"].as_array().unwrap() {
        let mut r = request();
        r["handler"]["properties"] = json!({"INSTALLDIR":case["value"]});
        assert_eq!(
            serde_json::from_value::<InstallRequest>(r).unwrap().validate().is_ok(),
            case["valid"].as_bool().unwrap(),
            "{:?}",
            case["value"]
        );
    }
    for case in vectors["pathAncestors"].as_array().unwrap() {
        let mut r = request();
        r["package"]["path"] = json!(std::env::temp_dir()
            .join(case["value"].as_str().unwrap())
            .join("canary.msi"));
        assert_eq!(
            serde_json::from_value::<InstallRequest>(r).unwrap().validate().is_ok(),
            case["valid"].as_bool().unwrap()
        );
    }
}
