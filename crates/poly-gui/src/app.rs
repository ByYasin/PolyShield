//! PolyShield "Siber Kokpit" uygulama mantığı.

use egui::{Color32, RichText};

use poly_core::{BinaryInfo, SymbolVisibility};
use poly_rt::HwRng;
use poly_vm::VmProgram;

use crate::theme;

/// Bir fonksiyon zırhlandıktan sonraki istatistikler.
struct RowResult {
    vm_instrs: usize,
    native: usize,
    coverage: f64,
    bytecode_len: usize,
    armored_len: usize,
    junk: usize,
}

/// Listedeki tek bir fonksiyon satırı.
struct FuncRow {
    name: String,
    addr: u64,
    size: u64,
    file_offset: u64,
    visibility: SymbolVisibility,
    protectable: bool,
    virtualize: bool,
    obfuscate: bool,
    result: Option<RowResult>,
}

/// Yüklenmiş binary.
struct Loaded {
    path: String,
    bytes: Vec<u8>,
    format: String,
    arch: String,
    is64: bool,
    func_total: usize,
    rows: Vec<FuncRow>,
}

/// Grafik için tek fonksiyon verisi.
struct BarDatum {
    name: String,
    coverage: f64,
}

/// "GENERATE SECURE SHIELD" sonrası özet.
struct ShieldSummary {
    protected: usize,
    avg_coverage: f64,
    total_bytecode: usize,
    total_armored: usize,
    score: u32,
    elapsed_ms: f64,
    bars: Vec<BarDatum>,
}

pub struct PolyShieldApp {
    loaded: Option<Loaded>,
    status: String,
    filter: String,
    seed: u64,
    hw_entropy: bool,
    summary: Option<ShieldSummary>,
    hovering_file: bool,
}

impl PolyShieldApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        let mut rng = HwRng::auto();
        PolyShieldApp {
            loaded: None,
            status: "Bir .exe / .dll / ELF dosyasını buraya sürükleyin.".to_string(),
            filter: String::new(),
            seed: rng.next_u64(),
            hw_entropy: rng.is_hardware(),
            summary: None,
            hovering_file: false,
        }
    }

    // ---- yükleme ----------------------------------------------------------

    fn load_path(&mut self, path: &str) {
        match std::fs::read(path) {
            Ok(bytes) => self.load_bytes(bytes, path.to_string()),
            Err(e) => self.status = format!("✗ Dosya okunamadı: {e}"),
        }
    }

    fn load_bytes(&mut self, bytes: Vec<u8>, path: String) {
        match poly_core::parse_bytes(&bytes, Some(&path)) {
            Ok(info) => {
                let rows = build_rows(&info);
                let protectable = rows.iter().filter(|r| r.protectable).count();
                self.status = format!(
                    "✓ {} yüklendi — {} fonksiyon ({} zırhlanabilir)",
                    short_name(&path),
                    info.functions.len(),
                    protectable
                );
                self.loaded = Some(Loaded {
                    path,
                    bytes,
                    format: info.format.to_string(),
                    arch: format!("{}", info.arch),
                    is64: info.is_64bit,
                    func_total: info.functions.len(),
                    rows,
                });
                self.summary = None;
            }
            Err(e) => self.status = format!("✗ Ayrıştırma hatası: {e}"),
        }
    }

    // ---- zırhlama ---------------------------------------------------------

    fn generate_shield(&mut self) {
        let seed = self.seed;
        let Some(loaded) = self.loaded.as_mut() else {
            return;
        };

        let bytes = &loaded.bytes;
        let mut protected = 0usize;
        let mut cov_sum = 0.0f64;
        let mut total_bytecode = 0usize;
        let mut total_armored = 0usize;
        let mut bars = Vec::new();
        let start = std::time::Instant::now();

        for row in loaded.rows.iter_mut() {
            if !row.protectable || !(row.virtualize || row.obfuscate) {
                row.result = None;
                continue;
            }
            if let Some(res) = protect_row(bytes, row, seed) {
                cov_sum += res.coverage;
                total_bytecode += res.bytecode_len;
                total_armored += res.armored_len;
                protected += 1;
                bars.push(BarDatum {
                    name: row.name.clone(),
                    coverage: res.coverage,
                });
                row.result = Some(res);
            }
        }
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        if protected == 0 {
            self.status =
                "⚠ Hiç fonksiyon seçilmedi — en az birini Virtualize/Obfuscate işaretleyin.".into();
            self.summary = None;
            return;
        }

        let avg = cov_sum / protected as f64;
        // Güvenlik skoru: kapsam + korunan fonksiyon yoğunluğu.
        let score = (avg * 100.0).round() as u32;
        self.summary = Some(ShieldSummary {
            protected,
            avg_coverage: avg,
            total_bytecode,
            total_armored,
            score,
            elapsed_ms,
            bars,
        });
        self.status =
            format!("🛡 {protected} fonksiyon {elapsed_ms:.1} ms'de zırhlandı (skor %{score}).");
    }

    fn set_all(&mut self, virtualize: bool) {
        if let Some(loaded) = self.loaded.as_mut() {
            for row in loaded.rows.iter_mut() {
                if row.protectable {
                    row.virtualize = virtualize;
                    row.obfuscate = false;
                }
            }
        }
    }
}

impl eframe::App for PolyShieldApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_dropped_files(ctx);

        self.top_bar(ctx);
        self.side_panel(ctx);
        self.bottom_bar(ctx);
        self.central(ctx);

        if self.hovering_file {
            self.draw_drop_overlay(ctx);
        }
    }
}

impl PolyShieldApp {
    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        ctx.input(|i| {
            self.hovering_file = !i.raw.hovered_files.is_empty();
        });
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped.into_iter().next() {
            if let Some(path) = file.path {
                self.load_path(&path.to_string_lossy());
            } else if let Some(bytes) = file.bytes {
                let name = file.name.clone();
                self.load_bytes(bytes.to_vec(), name);
            }
        }
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("◢ POLYSHIELD ◣")
                        .color(theme::ACCENT)
                        .size(24.0)
                        .strong(),
                );
                ui.label(
                    RichText::new("CODE VIRTUALIZATION ENGINE")
                        .color(theme::MAGENTA)
                        .size(13.0),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (label, color) = if self.hw_entropy {
                        ("⚡ RDRAND", theme::OK)
                    } else {
                        ("⚙ SOFT-RNG", theme::WARN)
                    };
                    ui.label(RichText::new(label).color(color).size(12.0));
                    ui.label(RichText::new("ENTROPI:").color(theme::DIM).size(12.0));
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("📂 Dosya Aç").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter(
                            "Çalıştırılabilir",
                            &["exe", "dll", "sys", "so", "elf", "bin"],
                        )
                        .pick_file()
                    {
                        self.load_path(&path.to_string_lossy());
                    }
                }
                if ui.button("🎲 Yeni Tohum").clicked() {
                    let mut rng = HwRng::auto();
                    self.seed = rng.next_u64();
                    self.status = format!("Yeni polimorfik tohum: {:#018x}", self.seed);
                }
                ui.label(RichText::new(format!("seed {:#018x}", self.seed)).color(theme::DIM));
            });
            ui.add_space(4.0);
        });
    }

    fn side_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("side")
            .resizable(false)
            .exact_width(270.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("HEDEF BINARY").color(theme::ACCENT).strong());
                ui.separator();
                if let Some(l) = &self.loaded {
                    info_row(ui, "Dosya", &short_name(&l.path));
                    info_row(ui, "Format", &l.format);
                    info_row(
                        ui,
                        "Mimari",
                        &format!("{} ({})", l.arch, if l.is64 { "64-bit" } else { "32-bit" }),
                    );
                    info_row(ui, "Fonksiyon", &l.func_total.to_string());
                } else {
                    ui.label(RichText::new("(yüklü değil)").color(theme::DIM));
                }

                ui.add_space(16.0);
                ui.label(RichText::new("KORUMA").color(theme::ACCENT).strong());
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Tümü: Virtualize").clicked() {
                        self.set_all(true);
                    }
                    if ui.button("Temizle").clicked() {
                        self.set_all(false);
                    }
                });

                ui.add_space(12.0);
                let enabled = self.loaded.is_some();
                ui.add_enabled_ui(enabled, |ui| {
                    let btn = egui::Button::new(
                        RichText::new("⚡ GENERATE SECURE SHIELD ⚡")
                            .size(16.0)
                            .strong()
                            .color(Color32::BLACK),
                    )
                    .fill(theme::ACCENT)
                    .min_size(egui::vec2(250.0, 46.0));
                    if ui.add(btn).clicked() {
                        self.generate_shield();
                    }
                });

                if let Some(s) = &self.summary {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new("GÜVENLİK SKORU")
                            .color(theme::ACCENT)
                            .strong(),
                    );
                    ui.separator();
                    let frac = (s.score as f32 / 100.0).clamp(0.0, 1.0);
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .text(RichText::new(format!("%{}", s.score)).strong())
                            .fill(score_color(s.score)),
                    );
                    info_row(ui, "Korunan fn", &s.protected.to_string());
                    info_row(
                        ui,
                        "Ort. kapsam",
                        &format!("%{:.0}", s.avg_coverage * 100.0),
                    );
                    info_row(ui, "VM bytecode", &format!("{} B", s.total_bytecode));
                    info_row(ui, "Zırhlı boyut", &format!("{} B", s.total_armored));
                    info_row(ui, "Süre", &format!("{:.1} ms", s.elapsed_ms));

                    ui.add_space(12.0);
                    ui.label(
                        RichText::new("KAPSAM GRAFİĞİ")
                            .color(theme::ACCENT)
                            .strong(),
                    );
                    ui.separator();
                    draw_coverage_chart(ui, &s.bars);
                }
            });
    }

    fn central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔍").color(theme::DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("fonksiyon ara…")
                        .desired_width(260.0),
                );
                if self.loaded.is_none() {
                    ui.label(RichText::new("  ← dosya sürükleyip bırakın").color(theme::DIM));
                }
            });
            ui.separator();

            let Some(loaded) = self.loaded.as_mut() else {
                ui.vertical_centered(|ui| {
                    ui.add_space(120.0);
                    ui.label(
                        RichText::new("⬇ DOSYAYI BURAYA BIRAKIN ⬇")
                            .color(theme::ACCENT_DIM)
                            .size(22.0),
                    );
                });
                return;
            };

            let filter = self.filter.to_lowercase();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("funcs")
                        .striped(true)
                        .num_columns(7)
                        .spacing([14.0, 6.0])
                        .show(ui, |ui| {
                            header(ui);
                            for row in loaded.rows.iter_mut() {
                                if !filter.is_empty() && !row.name.to_lowercase().contains(&filter)
                                {
                                    continue;
                                }
                                draw_row(ui, row);
                            }
                        });
                });
        });
    }

    fn bottom_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("▌").color(theme::ACCENT));
                ui.label(RichText::new(&self.status).color(theme::TEXT));
            });
            ui.add_space(3.0);
        });
    }

    fn draw_drop_overlay(&self, ctx: &egui::Context) {
        egui::Area::new("drop_overlay".into())
            .fixed_pos(egui::pos2(0.0, 0.0))
            .show(ctx, |ui| {
                let screen = ctx.screen_rect();
                ui.painter().rect_filled(
                    screen,
                    0.0,
                    Color32::from_rgba_unmultiplied(0, 230, 200, 30),
                );
                ui.painter().text(
                    screen.center(),
                    egui::Align2::CENTER_CENTER,
                    "⬇ BIRAK",
                    egui::FontId::proportional(40.0),
                    theme::ACCENT,
                );
            });
    }
}

// ---- yardımcılar -----------------------------------------------------------

fn build_rows(info: &BinaryInfo) -> Vec<FuncRow> {
    info.functions
        .iter()
        .map(|f| {
            let protectable = f.file_offset.is_some() && f.size.map(|s| s > 0).unwrap_or(false);
            FuncRow {
                name: f.display_name().to_string(),
                addr: f.virtual_address,
                size: f.size.unwrap_or(0),
                file_offset: f.file_offset.unwrap_or(0),
                visibility: f.visibility,
                protectable,
                virtualize: false,
                obfuscate: false,
                result: None,
            }
        })
        .collect()
}

fn protect_row(bytes: &[u8], row: &FuncRow, seed: u64) -> Option<RowResult> {
    let off = row.file_offset as usize;
    let size = row.size as usize;
    let code = bytes.get(off..off.checked_add(size)?)?;
    let prog = VmProgram::from_x86(code, row.addr, Some(row.name.clone()));
    // Virtualize → VM'e güvenir, az junk. Obfuscate → yoğun junk ile karartma.
    let junk = if row.virtualize { 30 } else { 70 };
    let armored = prog.armor(seed ^ row.addr, junk);
    Some(RowResult {
        vm_instrs: prog.stats.vm_instrs,
        native: prog.stats.native,
        coverage: prog.stats.coverage,
        bytecode_len: prog.stats.bytecode_len,
        armored_len: armored.armored.len(),
        junk: armored.junk_added,
    })
}

fn header(ui: &mut egui::Ui) {
    let h = |ui: &mut egui::Ui, s: &str| ui.label(RichText::new(s).color(theme::MAGENTA).strong());
    h(ui, "ADRES");
    h(ui, "GÖR.");
    h(ui, "BOYUT");
    h(ui, "FONKSİYON");
    h(ui, "VIRT");
    h(ui, "OBF");
    h(ui, "SONUÇ");
    ui.end_row();
}

fn draw_row(ui: &mut egui::Ui, row: &mut FuncRow) {
    ui.label(
        RichText::new(format!("{:#012x}", row.addr))
            .color(theme::DIM)
            .monospace(),
    );
    ui.label(RichText::new(vis_short(row.visibility)).color(vis_color(row.visibility)));
    ui.label(
        RichText::new(row.size.to_string())
            .color(theme::TEXT)
            .monospace(),
    );
    ui.label(RichText::new(&row.name).color(theme::TEXT));

    ui.add_enabled_ui(row.protectable, |ui| {
        if ui.checkbox(&mut row.virtualize, "").changed() && row.virtualize {
            row.obfuscate = false;
        }
    });
    ui.add_enabled_ui(row.protectable, |ui| {
        if ui.checkbox(&mut row.obfuscate, "").changed() && row.obfuscate {
            row.virtualize = false;
        }
    });

    match &row.result {
        Some(r) => {
            let txt = format!(
                "%{:.0} • {} VM • +{} junk • {}B",
                r.coverage * 100.0,
                r.vm_instrs,
                r.junk,
                r.armored_len
            );
            let col = if r.native == 0 {
                theme::OK
            } else {
                theme::WARN
            };
            ui.label(RichText::new(txt).color(col).monospace());
        }
        None => {
            let s = if row.protectable {
                "—"
            } else {
                "(sembol/boyut yok)"
            };
            ui.label(RichText::new(s).color(theme::DIM));
        }
    }
    ui.end_row();
}

/// Korunan fonksiyonların kapsamını yatay bar grafiği olarak çizer (painter ile).
fn draw_coverage_chart(ui: &mut egui::Ui, bars: &[BarDatum]) {
    if bars.is_empty() {
        return;
    }
    let row_h = 18.0;
    let shown = bars.iter().take(12);
    let count = bars.len().min(12);
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), row_h * count as f32),
        egui::Sense::hover(),
    );
    let painter = ui.painter_at(rect);
    let label_w = 95.0_f32.min(rect.width() * 0.45);

    for (i, b) in shown.enumerate() {
        let y = rect.top() + i as f32 * row_h;
        let bar_area = egui::Rect::from_min_max(
            egui::pos2(rect.left() + label_w, y + 2.0),
            egui::pos2(rect.right(), y + row_h - 3.0),
        );
        // arka plan
        painter.rect_filled(bar_area, 2.0, theme::PANEL_LT);
        // dolu kısım
        let mut fill = bar_area;
        fill.set_right(bar_area.left() + bar_area.width() * b.coverage as f32);
        painter.rect_filled(fill, 2.0, score_color((b.coverage * 100.0) as u32));
        // isim
        painter.text(
            egui::pos2(rect.left(), y + row_h / 2.0),
            egui::Align2::LEFT_CENTER,
            short_sym(&b.name, 13),
            egui::FontId::monospace(11.0),
            theme::DIM,
        );
        // yüzde
        painter.text(
            egui::pos2(bar_area.right() - 4.0, y + row_h / 2.0),
            egui::Align2::RIGHT_CENTER,
            format!("%{:.0}", b.coverage * 100.0),
            egui::FontId::monospace(11.0),
            Color32::BLACK,
        );
    }
    if bars.len() > 12 {
        ui.label(
            RichText::new(format!("… +{}", bars.len() - 12))
                .color(theme::DIM)
                .size(11.0),
        );
    }
}

fn short_sym(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}

fn info_row(ui: &mut egui::Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{key}:"))
                .color(theme::DIM)
                .size(12.0),
        );
        ui.label(RichText::new(val).color(theme::TEXT).size(12.0));
    });
}

fn vis_short(v: SymbolVisibility) -> &'static str {
    match v {
        SymbolVisibility::Exported => "EXP",
        SymbolVisibility::Imported => "IMP",
        SymbolVisibility::Internal => "INT",
    }
}

fn vis_color(v: SymbolVisibility) -> Color32 {
    match v {
        SymbolVisibility::Exported => theme::OK,
        SymbolVisibility::Imported => theme::WARN,
        SymbolVisibility::Internal => theme::DIM,
    }
}

fn score_color(score: u32) -> Color32 {
    if score >= 80 {
        theme::OK
    } else if score >= 50 {
        theme::WARN
    } else {
        theme::MAGENTA
    }
}

fn short_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}
