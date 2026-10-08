//! Common frameless behavior; native decorations and mobile windows keep their own chrome.
#[cfg(desktop)]
#[path = "project_window_corners.rs"]
mod project_window_corners;
pub fn init<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    let builder = tauri::plugin::Builder::new("project-window-chrome");
    #[cfg(desktop)]
    let builder = {
        use tauri::Manager;
        builder
            .on_window_ready(|window| project_window_corners::apply(&window))
            .js_init_script(include_str!("project-window-chrome.js").replace(
                "__PROJECT_CHROME_MACOS__",
                if cfg!(target_os = "macos") {
                    "true"
                } else {
                    "false"
                },
            ))
            .on_event(|app, event| {
                if let tauri::RunEvent::WindowEvent { label, event, .. } = event {
                    if matches!(
                        event,
                        tauri::WindowEvent::Resized(_)
                            | tauri::WindowEvent::Focused(_)
                            | tauri::WindowEvent::ScaleFactorChanged { .. }
                    ) {
                        if let Some(window) = app.get_webview_window(label) {
                            project_window_corners::apply(&window.as_ref().window());
                            let _ = window.eval(
                                "window.dispatchEvent(new Event('project-native-window-state'))",
                            );
                        }
                    }
                }
            })
    };
    builder.build()
}
