use super::*;
use compatforge_domain::CoreConfig;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn close_to_background_follows_persisted_setting() {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("compatforge-close-setting-{}-{id}", std::process::id()));
    let mut config: CoreConfig =
        serde_json::from_str(include_str!("../../../../examples/context-config.linux-arm64.json")).unwrap();
    config.storage_root = root.join("storage").to_string_lossy().into_owned();
    let service = Arc::new(
        AutomationService::new(
            config,
            ServiceConfig {
                schema_version: SCHEMA_VERSION_V1.into(),
                service_root: root.join("service").to_string_lossy().into_owned(),
            },
        )
        .unwrap(),
    );
    let mut runtime = DesktopRuntime::new(root.clone(), false, DesktopLaunchOptions::default());
    runtime.service = Some(service.clone());
    let state = AppState::new(runtime);

    assert!(!close_to_background_enabled(&state));
    let mut settings = service.get_settings().unwrap();
    settings.close_to_background = true;
    service.update_settings(&settings).unwrap();
    assert!(close_to_background_enabled(&state));
    state.shutdown();
    assert!(!close_to_background_enabled(&state));

    drop(service);
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}
