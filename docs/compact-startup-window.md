# Compact startup window

The main window default changes from 1360 × 860 to 1080 × 720 logical pixels; nominal minimum 820 × 560. It starts hidden, fits to the monitor work area, then shows without forced maximization or fullscreen. 

Fresh geometry is capped at 80% of the available work area, with 16 logical pixels reserved at desktop edges and native frame space included. The effective minimum decreases on smaller screens. Valid saved geometry can remain larger than the default and can touch work-area edges; only out-of-bounds geometry is moved or reduced. Monitor selection uses overlap, including negative desktop coordinates, and falls back to the primary display when a saved monitor is disconnected. Scale changes reconcile the normal frame against the current work area.

Normal geometry is saved in app_config_dir/window-geometry-main-v1.txt, using physical desktop positions and logical content dimensions. Minimized, fullscreen and maximized frames never replace the saved normal geometry. A temporary file plus rename prevents a partial write from replacing the last valid state.

Source: `apps/desktop/src-tauri/src/window_geometry.rs` and `window_placement.rs`, installed from the desktop setup callback. No new framework or dependency is introduced.

Verification: the five geometry tests cover small/Retina screens, a valid larger saved window, negative monitor coordinates and display removal, edge/work-area-sized saved geometry, and invalid saved values. The helper is also compiled against Tauri's real API. Full application Cargo checks are recorded in the task report. Actual native window interaction and Windows/Linux appearance have not been visually verified in this task.
