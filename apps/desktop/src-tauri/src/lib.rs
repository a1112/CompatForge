#![forbid(unsafe_code)]

use compatforge_capability::{ContextCapabilityQuery, HostProbe};
use compatforge_domain::{validate_portable_relative_path, CapabilityReport, ProviderDescriptor, SCHEMA_VERSION_V1};
use compatforge_provider_macos::{create_local_context, MacOsLocalContextReceipt, MacOsLocalContextRequest};
use compatforge_service::{AutomationService, ServiceConfig, ServiceRequest, ServiceResponse};
use serde::Serialize;
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(target_os = "macos")]
use tauri::TitleBarStyle;
use tauri::{AppHandle, Manager, RunEvent, State, WebviewUrl, WebviewWindowBuilder, WindowEvent};

const INVALID_LAUNCH_ARGUMENTS: &str = "CompatForge 开发者验收启动参数无效";
const DESKTOP_LAUNCH_FAILED: &str = "CompatForge 桌面应用启动失败";
const MAX_RUNTIME_VERSION_BYTES: usize = 128;

#[derive(Debug, Clone, Default)]
struct DesktopLaunchOptions {
    acceptance_root: Option<PathBuf>,
    runtime_override: Option<RuntimeOverride>,
}

#[derive(Debug, Clone)]
struct RuntimeOverride {
    materialized_root: PathBuf,
    wine: String,
    wineserver: String,
    version: String,
}

impl DesktopLaunchOptions {
    fn parse<I, S>(arguments: I) -> Result<Self, &'static str>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut arguments = arguments.into_iter().map(Into::into);
        arguments.next().ok_or(INVALID_LAUNCH_ARGUMENTS)?;

        let mut acceptance_root = None;
        let mut wine_root = None;
        let mut wine = None;
        let mut wineserver = None;
        let mut version = None;
        while let Some(flag) = arguments.next() {
            let flag = flag.to_str().ok_or(INVALID_LAUNCH_ARGUMENTS)?;
            let value = arguments.next().ok_or(INVALID_LAUNCH_ARGUMENTS)?;
            let value = value.to_str().ok_or(INVALID_LAUNCH_ARGUMENTS)?;
            if value.starts_with("--") {
                return Err(INVALID_LAUNCH_ARGUMENTS);
            }
            match flag {
                "--acceptance-root" => set_once(&mut acceptance_root, value.to_owned())?,
                "--wine-root" => set_once(&mut wine_root, value.to_owned())?,
                "--wine" => set_once(&mut wine, value.to_owned())?,
                "--wineserver" => set_once(&mut wineserver, value.to_owned())?,
                "--version" => set_once(&mut version, value.to_owned())?,
                _ => return Err(INVALID_LAUNCH_ARGUMENTS),
            }
        }

        let supplied = [
            acceptance_root.is_some(),
            wine_root.is_some(),
            wine.is_some(),
            wineserver.is_some(),
            version.is_some(),
        ];
        if supplied.iter().all(|value| !value) {
            return Ok(Self::default());
        }
        if !supplied.iter().all(|value| *value) {
            return Err(INVALID_LAUNCH_ARGUMENTS);
        }

        let acceptance_root = acceptance_root.unwrap();
        let wine_root = wine_root.unwrap();
        let wine = wine.unwrap();
        let wineserver = wineserver.unwrap();
        let version = version.unwrap();
        if !serialized_path_is_absolute(&acceptance_root) || !serialized_path_is_absolute(&wine_root) {
            return Err(INVALID_LAUNCH_ARGUMENTS);
        }
        validate_portable_relative_path("wine", &wine).map_err(|_| INVALID_LAUNCH_ARGUMENTS)?;
        validate_portable_relative_path("wineserver", &wineserver).map_err(|_| INVALID_LAUNCH_ARGUMENTS)?;
        if !valid_runtime_version(&version) {
            return Err(INVALID_LAUNCH_ARGUMENTS);
        }

        Ok(Self {
            acceptance_root: Some(PathBuf::from(acceptance_root)),
            runtime_override: Some(RuntimeOverride {
                materialized_root: PathBuf::from(wine_root),
                wine,
                wineserver,
                version,
            }),
        })
    }
}

fn set_once(slot: &mut Option<String>, value: String) -> Result<(), &'static str> {
    if slot.replace(value).is_some() {
        Err(INVALID_LAUNCH_ARGUMENTS)
    } else {
        Ok(())
    }
}

fn serialized_path_is_absolute(value: &str) -> bool {
    Path::new(value).is_absolute()
        || value.starts_with('/')
        || value
            .as_bytes()
            .get(1..3)
            .is_some_and(|separator| separator == b":\\" || separator == b":/")
        || value.starts_with("\\\\")
}

fn valid_runtime_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUNTIME_VERSION_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b' ' | b'(' | b')'))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityView {
    id: String,
    label: String,
    status: String,
    available: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeSnapshot {
    runtime_ready: bool,
    runtime_status: String,
    smoke_mode: bool,
    capabilities: Vec<CapabilityView>,
    receipt: Option<Value>,
    error: Option<String>,
}

struct DesktopRuntime {
    acceptance_root: Option<PathBuf>,
    runtime_override: Option<RuntimeOverride>,
    runtime_store_root: PathBuf,
    storage_root: PathBuf,
    service_root: PathBuf,
    smoke_mode: bool,
    service: Option<Arc<AutomationService>>,
    receipt: Option<MacOsLocalContextReceipt>,
    capabilities: Option<CapabilityReport>,
    runtime_status: String,
    error: Option<String>,
}

impl DesktopRuntime {
    fn new(base: PathBuf, smoke_mode: bool, options: DesktopLaunchOptions) -> Self {
        let root = options.acceptance_root.as_deref().unwrap_or(&base);
        let runtime_store_root = root.join("runtime-store");
        let storage_root = root.join("storage");
        let service_root = root.join("service");
        Self {
            acceptance_root: options.acceptance_root,
            runtime_override: options.runtime_override,
            runtime_store_root,
            storage_root,
            service_root,
            smoke_mode,
            service: None,
            receipt: None,
            capabilities: None,
            runtime_status: if smoke_mode {
                "Smoke 模式：未执行 Runtime Bootstrap".into()
            } else {
                "正在准备运行环境…".into()
            },
            error: None,
        }
    }

    fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            runtime_ready: self.service.is_some(),
            runtime_status: self.runtime_status.clone(),
            smoke_mode: self.smoke_mode,
            capabilities: self
                .capabilities
                .as_ref()
                .map(capability_views)
                .unwrap_or_else(waiting_capabilities),
            receipt: self
                .receipt
                .as_ref()
                .and_then(|receipt| serde_json::to_value(receipt).ok()),
            error: self.error.clone(),
        }
    }
}

struct BootstrapResult {
    service: Arc<AutomationService>,
    receipt: MacOsLocalContextReceipt,
    capabilities: CapabilityReport,
}

struct AppState {
    runtime: Mutex<DesktopRuntime>,
    bootstrap: Mutex<()>,
}

impl AppState {
    fn new(runtime: DesktopRuntime) -> Self {
        Self {
            runtime: Mutex::new(runtime),
            bootstrap: Mutex::new(()),
        }
    }

    fn shutdown(&self) {
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.service = None;
        }
    }
}

fn lock_runtime<'a>(state: &'a State<'_, AppState>) -> Result<MutexGuard<'a, DesktopRuntime>, String> {
    state.runtime.lock().map_err(|_| "桌面运行状态锁已损坏".into())
}

fn service(state: &State<'_, AppState>) -> Result<Arc<AutomationService>, String> {
    lock_runtime(state)?
        .service
        .clone()
        .ok_or_else(|| "运行环境尚未完成 Bootstrap".into())
}

#[tauri::command]
fn state_snapshot(state: State<'_, AppState>) -> Result<RuntimeSnapshot, String> {
    Ok(lock_runtime(&state)?.snapshot())
}

#[tauri::command]
async fn bootstrap_runtime(state: State<'_, AppState>) -> Result<RuntimeSnapshot, String> {
    let _bootstrap = state.bootstrap.lock().map_err(|_| "Bootstrap 状态锁已损坏")?;
    let (runtime_store_root, storage_root, service_root, runtime_override) = {
        let runtime = lock_runtime(&state)?;
        (
            runtime.runtime_store_root.clone(),
            runtime.storage_root.clone(),
            runtime.service_root.clone(),
            runtime.runtime_override.clone(),
        )
    };
    let result = bootstrap_core(
        &runtime_store_root,
        &storage_root,
        &service_root,
        runtime_override.as_ref(),
    );
    let mut runtime = lock_runtime(&state)?;
    match result {
        Ok(result) => {
            runtime.runtime_status = format!("运行环境就绪 · {} · {}", result.receipt.version, result.receipt.pack_id);
            runtime.service = Some(result.service);
            runtime.receipt = Some(result.receipt);
            runtime.capabilities = Some(result.capabilities);
            runtime.error = None;
            Ok(runtime.snapshot())
        }
        Err(message) => {
            runtime.runtime_status = "Runtime Bootstrap 失败".into();
            runtime.error = Some(message.clone());
            Err(message)
        }
    }
}

#[tauri::command]
async fn service_call(request: ServiceRequest, state: State<'_, AppState>) -> Result<ServiceResponse, String> {
    service(&state)?.call(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn clear_error(state: State<'_, AppState>) -> Result<RuntimeSnapshot, String> {
    let mut runtime = lock_runtime(&state)?;
    runtime.error = None;
    Ok(runtime.snapshot())
}

#[tauri::command]
fn open_settings(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("settings") {
        window.show().map_err(|error| error.to_string())?;
        window.set_focus().map_err(|error| error.to_string())?;
        return Ok(());
    }
    let builder = WebviewWindowBuilder::new(&app, "settings", WebviewUrl::App("settings.html".into()))
        .title("CompatForge 设置")
        .inner_size(980.0, 680.0)
        .min_inner_size(760.0, 560.0)
        .resizable(true)
        .decorations(true);
    #[cfg(target_os = "macos")]
    let builder = builder.hidden_title(true).title_bar_style(TitleBarStyle::Overlay);
    builder.build().map_err(|error| error.to_string())?;
    Ok(())
}

fn bootstrap_core(
    runtime_store_root: &Path,
    storage_root: &Path,
    service_root: &Path,
    runtime_override: Option<&RuntimeOverride>,
) -> Result<BootstrapResult, String> {
    create_directory(runtime_store_root, "Runtime Store")?;
    create_directory(storage_root, "存储目录")?;
    create_directory(service_root, "服务目录")?;
    let host = HostProbe::probe().map_err(|error| format!("主机能力探测失败：{error}"))?;
    let request = local_context_request(runtime_store_root, storage_root, runtime_override)?;
    let local = create_local_context(&host, &request).map_err(|error| format!("Runtime Bootstrap 失败：{error}"))?;
    let capabilities =
        ContextCapabilityQuery::report(&local.config).map_err(|error| format!("能力报告生成失败：{error}"))?;
    let service = AutomationService::new(
        local.config,
        ServiceConfig {
            schema_version: SCHEMA_VERSION_V1.into(),
            service_root: path_text(service_root)?,
        },
    )
    .map_err(|error| format!("应用服务初始化失败：{error}"))?;
    service
        .seed_default_applications()
        .map_err(|error| format!("默认应用登记失败：{error}"))?;
    Ok(BootstrapResult {
        service: Arc::new(service),
        receipt: local.receipt,
        capabilities,
    })
}

fn local_context_request(
    runtime_store_root: &Path,
    storage_root: &Path,
    runtime_override: Option<&RuntimeOverride>,
) -> Result<MacOsLocalContextRequest, String> {
    let (materialized_root, wine, wineserver, version) = match runtime_override {
        Some(runtime) => (
            Some(path_text(&runtime.materialized_root)?),
            Some(runtime.wine.clone()),
            Some(runtime.wineserver.clone()),
            Some(runtime.version.clone()),
        ),
        None => (None, None, None, None),
    };
    Ok(MacOsLocalContextRequest {
        schema_version: SCHEMA_VERSION_V1.into(),
        runtime_store_root: path_text(runtime_store_root)?,
        storage_root: path_text(storage_root)?,
        materialized_root,
        wine,
        wineserver,
        version,
    })
}

fn create_directory(path: &Path, label: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|error| format!("无法创建{label}：{error}"))
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "路径不是有效 UTF-8".into())
}

fn capability_views(report: &CapabilityReport) -> Vec<CapabilityView> {
    vec![
        capability_view("runtime", "Wine Runtime", &report.runtime_providers, "wine"),
        capability_view("rosetta", "Rosetta 2", &report.translators, "rosetta"),
        capability_view("graphics", "图形兼容", &report.graphics_backends, "wined3d"),
    ]
}

fn waiting_capabilities() -> Vec<CapabilityView> {
    [
        ("runtime", "Wine Runtime"),
        ("rosetta", "Rosetta 2"),
        ("graphics", "图形兼容"),
    ]
    .into_iter()
    .map(|(id, label)| CapabilityView {
        id: id.into(),
        label: label.into(),
        status: "等待 Bootstrap".into(),
        available: false,
    })
    .collect()
}

fn capability_view(id: &str, label: &str, providers: &[ProviderDescriptor], kind: &str) -> CapabilityView {
    let provider = providers.iter().find(|provider| provider.kind == kind);
    let (status, available) = match provider {
        Some(provider) if provider.available => {
            let status = if provider.version.is_empty() {
                "可用".into()
            } else {
                format!("可用 · {}", provider.version)
            };
            (status, true)
        }
        Some(provider) => (provider.reason.clone().unwrap_or_else(|| "不可用".into()), false),
        None => ("未报告".into(), false),
    };
    CapabilityView {
        id: id.into(),
        label: label.into(),
        status,
        available,
    }
}

pub fn run<I, S>(arguments: I) -> Result<(), &'static str>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let options = DesktopLaunchOptions::parse(arguments)?;
    let application = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let base = app.path().app_local_data_dir()?;
            let default_root = base.clone();
            let smoke_mode = std::env::var_os("COMPATFORGE_DESKTOP_SMOKE").is_some();
            let runtime = DesktopRuntime::new(base, smoke_mode, options.clone());
            let root = runtime.acceptance_root.as_deref().unwrap_or(&default_root);
            std::fs::create_dir_all(root)?;
            app.manage(AppState::new(runtime));
            if smoke_mode {
                println!("COMPATFORGE_TAURI_SMOKE_READY");
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(2));
                    handle.exit(0);
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            state_snapshot,
            bootstrap_runtime,
            service_call,
            clear_error,
            open_settings
        ])
        .build(tauri::generate_context!())
        .map_err(|_| DESKTOP_LAUNCH_FAILED)?;

    application.run(|app_handle, event| {
        if matches!(event, RunEvent::Exit)
            || matches!(
                event,
                RunEvent::WindowEvent {
                    ref label,
                    event: WindowEvent::CloseRequested { .. },
                    ..
                } if label == "main"
            )
        {
            app_handle.state::<AppState>().shutdown();
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crossover_arguments() -> [&'static str; 11] {
        [
            "compatforge-desktop",
            "--acceptance-root",
            "/absolute/evidence/crossover",
            "--wine-root",
            "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver",
            "--wine",
            "bin/wine",
            "--wineserver",
            "bin/wineserver",
            "--version",
            "25.0",
        ]
    }

    #[test]
    fn acceptance_runtime_requires_an_exact_argument_quartet() {
        let options = DesktopLaunchOptions::parse(crossover_arguments()).unwrap();
        assert!(options.acceptance_root.is_some());
        assert!(options.runtime_override.is_some());
    }

    #[test]
    fn acceptance_runtime_is_forwarded_to_the_core_request() {
        let options = DesktopLaunchOptions::parse(crossover_arguments()).unwrap();
        let request = local_context_request(
            Path::new("/absolute/acceptance/runtime-store"),
            Path::new("/absolute/acceptance/storage"),
            options.runtime_override.as_ref(),
        )
        .unwrap();
        assert_eq!(
            request.materialized_root.as_deref(),
            Some("/Applications/CrossOver.app/Contents/SharedSupport/CrossOver")
        );
        assert_eq!(request.wine.as_deref(), Some("bin/wine"));
        assert_eq!(request.wineserver.as_deref(), Some("bin/wineserver"));
        assert_eq!(request.version.as_deref(), Some("25.0"));
    }

    #[test]
    fn normal_launch_has_no_acceptance_override() {
        let options = DesktopLaunchOptions::parse(["compatforge-desktop"]).unwrap();
        assert!(options.acceptance_root.is_none());
        assert!(options.runtime_override.is_none());
    }

    #[test]
    fn partial_or_relative_acceptance_arguments_are_rejected() {
        assert!(DesktopLaunchOptions::parse(["app", "--wine", "bin/wine"]).is_err());
        assert!(DesktopLaunchOptions::parse(["app", "--acceptance-root", "relative"]).is_err());

        let mut relative_entrypoint = crossover_arguments();
        relative_entrypoint[6] = "../bin/wine";
        assert!(DesktopLaunchOptions::parse(relative_entrypoint).is_err());

        let mut absolute_entrypoint = crossover_arguments();
        absolute_entrypoint[6] = "/bin/wine";
        assert!(DesktopLaunchOptions::parse(absolute_entrypoint).is_err());
    }

    #[test]
    fn duplicate_unknown_missing_and_positional_arguments_are_rejected() {
        let mut duplicate = crossover_arguments().to_vec();
        duplicate.extend(["--wine", "bin/wine"]);
        assert!(DesktopLaunchOptions::parse(duplicate).is_err());

        assert!(DesktopLaunchOptions::parse(["app", "--unknown", "value"]).is_err());
        assert!(DesktopLaunchOptions::parse(["app", "--acceptance-root"]).is_err());
        assert!(DesktopLaunchOptions::parse(["app", "positional"]).is_err());
    }

    #[test]
    fn runtime_version_is_closed_and_bounded() {
        let mut empty = crossover_arguments();
        empty[10] = "";
        assert!(DesktopLaunchOptions::parse(empty).is_err());

        let mut control_character = crossover_arguments();
        control_character[10] = "25.0\nforged";
        assert!(DesktopLaunchOptions::parse(control_character).is_err());

        let mut shell_punctuation = crossover_arguments();
        shell_punctuation[10] = "25.0;forged";
        assert!(DesktopLaunchOptions::parse(shell_punctuation).is_err());

        let long_version = "x".repeat(129);
        let mut too_long = crossover_arguments().map(str::to_owned);
        too_long[10] = long_version;
        assert!(DesktopLaunchOptions::parse(too_long).is_err());
    }

    #[test]
    fn initial_snapshot_is_not_service_ready() {
        let runtime = DesktopRuntime::new(
            PathBuf::from("/tmp/compatforge-tauri-test"),
            true,
            DesktopLaunchOptions::default(),
        );
        let snapshot = runtime.snapshot();
        assert!(snapshot.smoke_mode);
        assert!(!snapshot.runtime_ready);
        assert_eq!(snapshot.capabilities.len(), 3);
    }

    #[test]
    fn waiting_capability_cards_have_stable_ids() {
        let cards = waiting_capabilities();
        assert_eq!(
            cards.iter().map(|card| card.id.as_str()).collect::<Vec<_>>(),
            ["runtime", "rosetta", "graphics"]
        );
    }
}
