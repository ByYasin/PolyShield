//! PolyShield masaüstü arayüzü (Faz 3) — egui/eframe ile "Siber Kokpit".
//!
//! Tamamen Rust; çekirdek motorları (`poly-core`, `poly-vm`, `poly-rt`) doğrudan
//! bağlar — ayrı süreç/IPC gerekmez. Kullanıcı bir binary'i sürükler, fonksiyon
//! listesini görür, koruma modunu seçer ve tek tıkla zırhlar.

// Release'te konsol penceresini gizle (debug'da log için açık tut).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod theme;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1150.0, 740.0])
            .with_min_inner_size([820.0, 520.0])
            .with_title("PolyShield"),
        ..Default::default()
    };
    eframe::run_native(
        "PolyShield",
        native_options,
        Box::new(|cc| Ok(Box::new(app::PolyShieldApp::new(cc)))),
    )
}
