//! Siber-punk karanlık tema.

use egui::{Color32, Rounding, Stroke};

pub const BG: Color32 = Color32::from_rgb(8, 10, 14);
pub const PANEL: Color32 = Color32::from_rgb(13, 16, 22);
pub const PANEL_LT: Color32 = Color32::from_rgb(20, 25, 33);
pub const ACCENT: Color32 = Color32::from_rgb(0, 230, 200); // neon cyan
pub const ACCENT_DIM: Color32 = Color32::from_rgb(0, 150, 135);
pub const MAGENTA: Color32 = Color32::from_rgb(255, 60, 140);
pub const TEXT: Color32 = Color32::from_rgb(205, 222, 226);
pub const DIM: Color32 = Color32::from_rgb(120, 140, 146);
pub const WARN: Color32 = Color32::from_rgb(255, 180, 60);
pub const OK: Color32 = Color32::from_rgb(70, 230, 150);

/// Temayı egui bağlamına uygular.
pub fn apply(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::from_rgb(5, 6, 9);
    v.faint_bg_color = PANEL_LT;
    v.override_text_color = Some(TEXT);
    v.hyperlink_color = ACCENT;
    v.selection.bg_fill = ACCENT_DIM;
    v.selection.stroke = Stroke::new(1.0, ACCENT);

    let rounding = Rounding::same(4.0);
    v.widgets.noninteractive.bg_fill = PANEL;
    v.widgets.noninteractive.rounding = rounding;
    v.widgets.inactive.bg_fill = PANEL_LT;
    v.widgets.inactive.weak_bg_fill = PANEL_LT;
    v.widgets.inactive.rounding = rounding;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.hovered.bg_fill = Color32::from_rgb(28, 36, 46);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(28, 36, 46);
    v.widgets.hovered.rounding = rounding;
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.active.bg_fill = ACCENT_DIM;
    v.widgets.active.weak_bg_fill = ACCENT_DIM;
    v.widgets.active.rounding = rounding;

    ctx.set_visuals(v);

    // Biraz daha ferah aralık.
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    ctx.set_style(style);
}
