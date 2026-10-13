//! Physical desktop coordinates, logical content sizes; monitor origins may be negative.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
#[derive(Clone, Copy, Debug)]
pub struct Screen {
    pub area: Bounds,
    pub scale: f64,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Geometry {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
impl Geometry {
    pub fn valid(self) -> bool {
        [self.x, self.y, self.width, self.height].iter().all(|v| v.is_finite()) && self.width > 0.0 && self.height > 0.0
    }
}

pub fn select_screen(saved: Option<Geometry>, screens: &[Screen]) -> usize {
    let Some(g) = saved else { return 0 };
    screens
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let width = (g.x + g.width * s.scale).min(s.area.x + s.area.width) - g.x.max(s.area.x);
            let height = (g.y + g.height * s.scale).min(s.area.y + s.area.height) - g.y.max(s.area.y);
            (i, width.max(0.0) * height.max(0.0))
        })
        .max_by(|a, b| a.1.total_cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .filter(|v| v.1 > 0.0)
        .map_or(0, |v| v.0)
}

/// Reserve desktop edges and frame space; only fresh defaults use the 80% cap.
pub fn fit(
    saved: Option<Geometry>,
    default: (f64, f64),
    minimum: (f64, f64),
    screen: Screen,
    frame: (f64, f64),
) -> (Geometry, (f64, f64)) {
    let scale = screen.scale;
    let valid = saved.filter(|g| g.valid());
    let margin = if valid.is_some() { 0.0 } else { 16.0 * scale };
    let area = screen.area;
    let available_w = ((area.width - margin * 2.0) / scale - frame.0).max(1.0);
    let available_h = ((area.height - margin * 2.0) / scale - frame.1).max(1.0);
    let compact_w = available_w.min(area.width / scale * 0.8 - frame.0).max(1.0);
    let compact_h = available_h.min(area.height / scale * 0.8 - frame.1).max(1.0);
    let min = (minimum.0.min(compact_w), minimum.1.min(compact_h));
    let (max_w, max_h) = if valid.is_some() {
        (available_w, available_h)
    } else {
        (compact_w, compact_h)
    };
    let width = valid.map_or(default.0, |g| g.width).clamp(min.0, max_w);
    let height = valid.map_or(default.1, |g| g.height).clamp(min.1, max_h);
    let outer_w = (width + frame.0) * scale;
    let outer_h = (height + frame.1) * scale;
    let x = valid.map_or(area.x + (area.width - outer_w) / 2.0, |g| g.x).clamp(
        area.x + margin.min((area.width - outer_w).max(0.0) / 2.0),
        area.x + (area.width - outer_w - margin).max(0.0),
    );
    let y = valid.map_or(area.y + (area.height - outer_h) / 2.0, |g| g.y).clamp(
        area.y + margin.min((area.height - outer_h).max(0.0) / 2.0),
        area.y + (area.height - outer_h - margin).max(0.0),
    );
    (Geometry { x, y, width, height }, min)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn screen(x: f64, scale: f64) -> Screen {
        Screen {
            area: Bounds {
                x,
                y: 50.0,
                width: 1440.0 * scale,
                height: 850.0 * scale,
            },
            scale,
        }
    }
    #[test]
    fn first_start_is_compact_on_retina_and_small_screens() {
        for scale in [1.0, 2.0] {
            let (g, _) = fit(None, (1440.0, 960.0), (960.0, 640.0), screen(0.0, scale), (0.0, 28.0));
            assert!(g.width <= 1152.0 && g.height <= 652.0);
            assert!(g.y + (g.height + 28.0) * scale <= 50.0 + 850.0 * scale - 16.0 * scale);
        }
        let s = Screen {
            area: Bounds {
                x: 0.0,
                y: 0.0,
                width: 800.0,
                height: 550.0,
            },
            scale: 1.0,
        };
        let (g, min) = fit(None, (1100.0, 760.0), (960.0, 640.0), s, (0.0, 28.0));
        assert!(g.width <= 640.0 && g.height <= 412.0 && min.0 <= g.width && min.1 <= g.height);
    }
    #[test]
    fn valid_large_saved_window_is_not_reset() {
        let saved = Geometry {
            x: 20.0,
            y: 70.0,
            width: 1320.0,
            height: 760.0,
        };
        assert_eq!(
            fit(
                Some(saved),
                (980.0, 660.0),
                (800.0, 540.0),
                screen(0.0, 1.0),
                (0.0, 0.0)
            )
            .0,
            saved
        );
    }
    #[test]
    fn negative_monitor_and_disconnected_monitor_are_supported() {
        let saved = Geometry {
            x: -1390.0,
            y: 90.0,
            width: 1000.0,
            height: 660.0,
        };
        let monitors = [screen(0.0, 1.0), screen(-1440.0, 1.0)];
        assert_eq!(select_screen(Some(saved), &monitors), 1);
        assert_eq!(
            fit(Some(saved), (980.0, 660.0), (800.0, 540.0), monitors[1], (0.0, 0.0)).0,
            saved
        );
        let g = fit(Some(saved), (980.0, 660.0), (800.0, 540.0), monitors[0], (0.0, 0.0)).0;
        assert!(g.x >= 0.0 && g.x + g.width <= 1440.0);
    }
    #[test]
    fn saved_edge_and_work_area_sized_windows_are_unchanged() {
        let s = screen(0.0, 1.0);
        for g in [
            Geometry {
                x: 0.0,
                y: 50.0,
                width: 1440.0,
                height: 822.0,
            },
            Geometry {
                x: 0.0,
                y: 50.0,
                width: 1000.0,
                height: 680.0,
            },
        ] {
            assert_eq!(fit(Some(g), (1000.0, 680.0), (800.0, 540.0), s, (0.0, 28.0)).0, g);
        }
    }
    #[test]
    fn invalid_saved_values_fall_back_to_default() {
        let invalid = Geometry {
            x: f64::NAN,
            y: 0.0,
            width: 1200.0,
            height: 800.0,
        };
        assert_eq!(
            fit(
                Some(invalid),
                (980.0, 660.0),
                (800.0, 540.0),
                screen(0.0, 1.0),
                (0.0, 0.0)
            ),
            fit(None, (980.0, 660.0), (800.0, 540.0), screen(0.0, 1.0), (0.0, 0.0))
        );
    }
}
