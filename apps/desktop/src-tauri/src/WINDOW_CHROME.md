# Desktop window behavior

`project_window_chrome::init()` installs the shared Tauri 2 desktop adapter.
Mobile builds contain an empty plugin. Native decorated windows retain their own
chrome; only frameless, resizable windows get the eight resize edges. Maximized
and fullscreen windows have no active resize edges.

## Title bars

- Use `data-tauri-drag-region="deep"` on passive titlebar content.
- Bare/`"true"` regions only accept direct hits, matching Tauri's current contract.
- Use `data-tauri-drag-region="false"` for an explicit opt-out.
- Buttons, links, form controls, editable content and interactive ARIA roles are
  excluded. Do not add a second pointer/mouse/double-click handler to these regions.
- macOS double-click maximization happens on mouseup and is cancelled by movement.
- Existing close/minimize/maximize buttons retain their application behavior,
  including close-to-tray and unsaved-document confirmation.

The adapter publishes `project-window-state` with native state in `event.detail`
and `data-window-{decorated,resizable,maximized,fullscreen,focused,maximizable}`
on the document element. Window controls can subscribe to update their icons.
`project-window-error` reports failed IPC operations. A permission/read failure
disables the adapter so existing native/app handlers remain usable.

The adapter updates on native window events, focus, resize and visibility changes;
it has no polling timer. Navigation disposes listeners and resize elements.
It only installs in the top-level local application document. Keep capabilities
local; loopback frontends must use their existing explicit origin capability.

## Verification

From this directory: `node --test project-window-chrome.test.cjs`.
From the Tauri crate: `cargo check --locked`.
Manually verify all eight resize directions, drag, double click, native snapping,
fullscreen, keyboard activation of window buttons, and close confirmation/tray
behavior on each supported desktop OS. Automated JavaScript tests mock native
IPC; they do not establish OS-level interaction correctness.

## Native rounded corners

Windows 11: DWM ROUND preference, native system radius and shadow. Maximized and
fullscreen use DONOTROUND. DWM may decline rounding on unsupported Windows,
per-pixel layered windows, remote/virtual sessions or snapped windows. No GDI
region fallback is installed because that disables DWM antialiasing/shadows.
macOS: decorated windows remain system-owned; frameless NSWindow content is
clipped by its native CALayer at 10 points (zero when maximized/fullscreen), on
the AppKit main thread. Linux outer geometry remains compositor-owned.
Frameless web content uses matching 8px (Windows/Linux) / 10px (macOS) clipping,
with --project-window-radius available to application styles. Mobile unchanged.
