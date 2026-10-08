//! Native desktop corners. Windows owns the exact radius; macOS uses 10 points.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn square(maximized: bool, fullscreen: bool) -> bool {
    maximized || fullscreen
}

#[cfg(target_os = "windows")]
pub fn apply<R: tauri::Runtime>(window: &tauri::Window<R>) {
    use std::ffi::c_void;
    #[link(name = "dwmapi")]
    unsafe extern "system" {
        fn DwmSetWindowAttribute(
            hwnd: *mut c_void,
            attribute: u32,
            value: *const c_void,
            size: u32,
        ) -> i32;
    }
    let (Ok(hwnd), Ok(maximized), Ok(fullscreen)) =
        (window.hwnd(), window.is_maximized(), window.is_fullscreen())
    else {
        return;
    };
    // DWMWA_WINDOW_CORNER_PREFERENCE: let DWM preserve native shadows, DPI and
    // snapping policy. No SetWindowRgn: regions disable DWM's antialiased corners.
    let preference: u32 = if square(maximized, fullscreen) { 1 } else { 2 };
    // SAFETY: Tauri owns a live HWND; the DWORD pointer remains valid for this call.
    let result = unsafe {
        DwmSetWindowAttribute(
            hwnd.0 as *mut c_void,
            33,
            (&preference as *const u32).cast(),
            4,
        )
    };
    // Pre-Windows-11/compositor restrictions are a supported graceful fallback.
    // Never fail startup or replace the user's window with a region-shaped one.
    let _ = result;
}

#[cfg(target_os = "macos")]
pub fn apply<R: tauri::Runtime>(window: &tauri::Window<R>) {
    if window.is_decorated().unwrap_or(true) {
        return;
    }
    let (Ok(maximized), Ok(fullscreen)) = (window.is_maximized(), window.is_fullscreen()) else {
        return;
    };
    let radius = if square(maximized, fullscreen) {
        0.0
    } else {
        10.0
    };
    let owned = window.clone();
    let _ = window.run_on_main_thread(move || {
        use std::ffi::{c_char, c_void};
        #[link(name = "objc")]
        unsafe extern "C" {
            fn sel_registerName(name: *const c_char) -> *mut c_void;
            fn objc_getClass(name: *const c_char) -> *mut c_void;
            fn objc_msgSend();
        }
        let Ok(handle) = owned.ns_window() else {
            return;
        };
        // SAFETY: AppKit is accessed only on its main thread. Each selector uses
        // the exact Objective-C ABI: object getter, BOOL setter and CGFloat setter.
        // CGFloat is f64 on supported 64-bit Tauri macOS targets.
        unsafe {
            let get: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let set_bool: unsafe extern "C" fn(*mut c_void, *mut c_void, bool) =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let set_double: unsafe extern "C" fn(*mut c_void, *mut c_void, f64) =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let set_object: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let send_void: unsafe extern "C" fn(*mut c_void, *mut c_void) =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let view = get(handle, sel_registerName(c"contentView".as_ptr()));
            if view.is_null() {
                return;
            }
            set_bool(view, sel_registerName(c"setWantsLayer:".as_ptr()), true);
            let layer = get(view, sel_registerName(c"layer".as_ptr()));
            if layer.is_null() {
                return;
            }
            let color_class = objc_getClass(c"NSColor".as_ptr());
            if color_class.is_null() {
                return;
            }
            let clear = get(color_class, sel_registerName(c"clearColor".as_ptr()));
            if clear.is_null() {
                return;
            }
            set_bool(handle, sel_registerName(c"setOpaque:".as_ptr()), false);
            set_object(
                handle,
                sel_registerName(c"setBackgroundColor:".as_ptr()),
                clear,
            );
            set_double(
                layer,
                sel_registerName(c"setCornerRadius:".as_ptr()),
                radius,
            );
            set_bool(layer, sel_registerName(c"setMasksToBounds:".as_ptr()), true);
            send_void(handle, sel_registerName(c"invalidateShadow".as_ptr()));
        }
    });
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn apply<R: tauri::Runtime>(_window: &tauri::Window<R>) {
    // Linux/Wayland native window shape belongs to the compositor. Do not change
    // decorations or transparency behind its back; the frontend clips content.
}

#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
mod tests {
    use super::square;
    #[test]
    fn restored_windows_are_rounded() {
        assert!(!square(false, false));
    }
    #[test]
    fn maximized_and_fullscreen_windows_fill_the_screen() {
        assert!(square(true, false));
        assert!(square(false, true));
        assert!(square(true, true));
    }
}
