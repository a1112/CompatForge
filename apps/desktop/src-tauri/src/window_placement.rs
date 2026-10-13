//! Keep normal user geometry, correcting only windows outside the current work area.
use super::window_geometry::{self, Bounds, Geometry, Screen};
use std::{fs, path::Path};
use tauri::{Manager, WebviewWindow, WindowEvent};

fn snapshot(window: &WebviewWindow) -> Option<Geometry> {
    if window.is_minimized().ok()? || window.is_maximized().ok()? || window.is_fullscreen().ok()? {
        return None;
    }
    let scale = window.scale_factor().ok()?;
    let position = window.outer_position().ok()?;
    let size = window.inner_size().ok()?.to_logical::<f64>(scale);
    Some(Geometry {
        x: position.x as f64,
        y: position.y as f64,
        width: size.width,
        height: size.height,
    })
}
fn read(path: &Path) -> Option<Geometry> {
    let text = fs::read_to_string(path).ok()?;
    let values: Vec<f64> = text.split_whitespace().map(str::parse).collect::<Result<_, _>>().ok()?;
    if values.len() != 4 {
        return None;
    }
    let g = Geometry {
        x: values[0],
        y: values[1],
        width: values[2],
        height: values[3],
    };
    g.valid().then_some(g)
}
fn save(window: &WebviewWindow, path: &Path) {
    if let Some(g) = snapshot(window) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let pending = path.with_extension("tmp");
        if fs::write(&pending, format!("{} {} {} {}\n", g.x, g.y, g.width, g.height)).is_ok() {
            let _ = fs::rename(pending, path);
        }
    }
}
fn apply(window: &WebviewWindow, saved: Option<Geometry>, default: (f64, f64), minimum: (f64, f64)) {
    if window.is_maximized().unwrap_or(false) || window.is_fullscreen().unwrap_or(false) {
        return;
    }
    let Ok(monitors) = window.available_monitors() else {
        return;
    };
    // Primary first gives a deterministic fallback when a saved display is unplugged.
    let primary = window.primary_monitor().ok().flatten();
    let mut screens: Vec<Screen> = monitors
        .iter()
        .map(|m| {
            let area = m.work_area();
            Screen {
                area: Bounds {
                    x: area.position.x as f64,
                    y: area.position.y as f64,
                    width: area.size.width as f64,
                    height: area.size.height as f64,
                },
                scale: m.scale_factor(),
            }
        })
        .collect();
    if let Some(primary) = primary {
        if let Some(index) = monitors.iter().position(|m| m.position() == primary.position()) {
            screens.swap(0, index);
        }
    }
    if screens.is_empty() {
        return;
    }
    let screen = screens[window_geometry::select_screen(saved, &screens)];
    let frame = match (window.outer_size(), window.inner_size(), window.scale_factor()) {
        (Ok(outer), Ok(inner), Ok(scale)) => (
            (outer.width.saturating_sub(inner.width)) as f64 / scale,
            (outer.height.saturating_sub(inner.height)) as f64 / scale,
        ),
        _ => (0.0, 32.0),
    };
    let (geometry, min) = window_geometry::fit(saved, default, minimum, screen, frame);
    let _ = window.set_min_size(Some(tauri::LogicalSize::new(min.0, min.1)));
    let _ = window.set_size(tauri::LogicalSize::new(geometry.width, geometry.height));
    let _ = window.set_position(tauri::PhysicalPosition::new(
        geometry.x.round() as i32,
        geometry.y.round() as i32,
    ));
}

pub fn install(app: &tauri::App, label: &str, default: (f64, f64), minimum: (f64, f64), show: bool) {
    let Some(window) = app.get_webview_window(label) else {
        return;
    };
    let path = app
        .path()
        .app_config_dir()
        .ok()
        .map(|base| base.join(format!("window-geometry-{label}-v1.txt")));
    apply(&window, path.as_ref().and_then(|path| read(path)), default, minimum);
    if let Some(path) = &path {
        save(&window, path);
    }
    if show {
        let _ = window.show();
    }
    let tracked = window.clone();
    window.on_window_event(move |event| {
        if matches!(event, WindowEvent::ScaleFactorChanged { .. }) {
            apply(&tracked, snapshot(&tracked), default, minimum);
        }
        if matches!(
            event,
            WindowEvent::Moved(_)
                | WindowEvent::Resized(_)
                | WindowEvent::CloseRequested { .. }
                | WindowEvent::ScaleFactorChanged { .. }
        ) {
            if let Some(path) = &path {
                save(&tracked, path);
            }
        }
    });
}
