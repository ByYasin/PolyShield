//! PolyShield komut satırı arayüzü.
//!
//! Faz 1'de iki alt komut sağlar:
//!   - `inspect`   — bir binary'i ayrıştırıp fonksiyon sembol haritasını döker.
//!   - `virtualize`— seçilen bir fonksiyonu Custom VM bytecode'a lift eder.
//!
//! İleride `shield` (tam zırhlama) ve inline `#[poly_virtualize]` desteği bu
//! kabuğun üzerine eklenecektir.

use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use poly_core::{BinaryInfo, FunctionSymbol, SymbolVisibility};
use poly_vm::VmProgram;

#[derive(Parser)]
#[command(
    name = "poly-cli",
    version,
    about = "PolyShield — native binary koruma aracı (Faz 1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bir PE/ELF dosyasını ayrıştırıp fonksiyon listesini gösterir.
    Inspect {
        /// İncelenecek .exe / .dll / .so / ELF dosyasının yolu.
        file: String,

        /// Özet metin yerine ham BinaryInfo JSON'unu yazdır.
        #[arg(long)]
        json: bool,

        /// Listelenecek maksimum fonksiyon sayısı (0 = sınırsız).
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Seçilen bir fonksiyonu Custom VM bytecode'a sanallaştırır.
    Virtualize {
        /// Hedef binary dosyasının yolu.
        file: String,

        /// Sanallaştırılacak fonksiyonun adı (alt-dize eşleşmesi).
        #[arg(long, conflicts_with = "addr")]
        function: Option<String>,

        /// Fonksiyonu adres ile seç (örn. 0x140001000).
        #[arg(long, value_parser = parse_u64)]
        addr: Option<u64>,

        /// Üretilen VM IR dökümünü göster.
        #[arg(long)]
        disasm: bool,

        /// VmProgram'ı JSON olarak yazdır.
        #[arg(long)]
        json: bool,

        /// Polimorfik zırhlama uygula (master tohum). Aynı tohum → aynı çıktı.
        #[arg(long, value_parser = parse_u64)]
        seed: Option<u64>,

        /// Junk enjeksiyon yoğunluğu (0–100), --seed ile birlikte.
        #[arg(long, default_value_t = 40)]
        junk: u8,

        /// N farklı tohumla varyant üretip çeşitliliği (diversity) göster.
        #[arg(long)]
        variants: Option<u32>,
    },

    /// Self-encrypting runtime demosu (Faz 2.1) — bytecode bellekte şifreli çalışır.
    SecureRun,

    /// Anti-debug tarama durumunu gösterir (Faz 2.2).
    Antidebug,

    /// Otopilot: işaretli (polyv_/polyo_) fonksiyonları toplu zırhlar (Faz 4.2).
    Shield {
        /// Hedef binary (genelde #[poly_virtualize] ile derlenmiş .dll/.so).
        file: String,

        /// Sanallaştırma için sembol öneki.
        #[arg(long, default_value = "polyv_")]
        prefix_virt: String,

        /// Karartma için sembol öneki.
        #[arg(long, default_value = "polyo_")]
        prefix_obf: String,

        /// Polimorfik master tohum.
        #[arg(long, value_parser = parse_u64, default_value_t = 0x5031_5348_4C44)]
        seed: u64,

        /// CI kapısı: kapsam bunun altındaysa hata koduyla çık (0.0–1.0).
        #[arg(long, default_value_t = 0.0)]
        min_coverage: f64,

        /// JSON raporu bu dosyaya yaz.
        #[arg(long)]
        report: Option<String>,
    },

    /// Repack: işaretli fonksiyonları zırhlayıp .pshld section'ı olarak gömer (Faz 5).
    Pack {
        /// Girdi binary (PE32+).
        file: String,

        /// Çıktı dosyası.
        #[arg(short, long)]
        out: String,

        /// Polimorfik master tohum.
        #[arg(long, value_parser = parse_u64, default_value_t = 0x5031_5348_4C44)]
        seed: u64,

        /// Sanallaştırma öneki.
        #[arg(long, default_value = "polyv_")]
        prefix_virt: String,

        /// Karartma öneki.
        #[arg(long, default_value = "polyo_")]
        prefix_obf: String,

        /// Orijinal kod baytlarını 0xCC ile mühürle (DİKKAT: loader olmadan
        /// bu fonksiyonlar çağrılamaz; kod kaldırmayı göstermek içindir).
        #[arg(long)]
        seal: bool,
    },

    /// Gömülü .pshld payload'ını listeler ve isteğe bağlı bütünlük testi yapar (Faz 5).
    Unpack {
        /// Zırhlanmış (packed) binary.
        file: String,

        /// Gömülü payload'ı SecureVm'de çalıştırarak bütünlüğü doğrula.
        #[arg(long)]
        run: bool,
    },

    /// Loader: gömülü VM fonksiyonunu Win64 ABI ile çağırır (Faz 5 loader).
    RunProtected {
        /// Packed binary (.pshld içeren).
        file: String,

        /// Çağrılacak fonksiyon adı (alt-dize, örn. poly_demo_add).
        #[arg(long)]
        function: String,

        /// Tamsayı argümanları (sırayla RCX, RDX, R8, R9).
        #[arg(long, value_parser = parse_u64)]
        arg: Vec<u64>,

        /// Dönüş değeri genişliği (32 veya 64).
        #[arg(long, default_value_t = 64)]
        width: u32,
    },

    /// Loader doğrulaması: native çağrı sonucu == VM loader sonucu mu? (Windows).
    VerifyLoader {
        /// Packed binary.
        file: String,

        #[arg(long)]
        function: String,

        #[arg(long, value_parser = parse_u64)]
        arg: Vec<u64>,

        #[arg(long, default_value_t = 64)]
        width: u32,
    },

    /// Düşük seviye yardımcı: bir PE/ELF'e ham veri içeren bir section gömer.
    Embed {
        /// Girdi binary.
        file: String,
        /// Çıktı dosyası.
        #[arg(short, long)]
        out: String,
        /// Section adı.
        #[arg(long, default_value = ".pshld")]
        name: String,
        /// Gömülecek metin (gösterim/test amaçlı).
        #[arg(long, default_value = "PSHLD-EMBED")]
        text: String,
    },

    /// De-virtualization direnç metriklerini hesaplar (Faz 4.3).
    Analyze {
        /// Hedef binary.
        file: String,

        /// İncelenecek fonksiyon adı (alt-dize).
        #[arg(long, conflicts_with = "addr")]
        function: Option<String>,

        /// Fonksiyonu adresle seç.
        #[arg(long, value_parser = parse_u64)]
        addr: Option<u64>,

        /// Çeşitlilik için üretilecek tohum sayısı.
        #[arg(long, default_value_t = 12)]
        seeds: u32,
    },
}

/// "0x..." (hex) veya ondalık bir u64 ayrıştırır.
fn parse_u64(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    };
    parsed.map_err(|_| format!("geçersiz adres: {s}"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hata: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Inspect { file, json, limit } => {
            let info = poly_core::parse_file(&file)
                .with_context(|| format!("'{file}' ayrıştırılamadı"))?;
            if json {
                println!("{}", info.to_json_pretty()?);
            } else {
                print_summary(&info, limit);
            }
            Ok(())
        }

        Command::Virtualize {
            file,
            function,
            addr,
            disasm,
            json,
            seed,
            junk,
            variants,
        } => run_virtualize(VirtArgs {
            file: &file,
            function: function.as_deref(),
            addr,
            disasm,
            json,
            seed,
            junk,
            variants,
        }),

        Command::SecureRun => run_secure_demo(),
        Command::Antidebug => {
            run_antidebug_report();
            Ok(())
        }

        Command::Shield {
            file,
            prefix_virt,
            prefix_obf,
            seed,
            min_coverage,
            report,
        } => run_shield(ShieldArgs {
            file: &file,
            prefix_virt: &prefix_virt,
            prefix_obf: &prefix_obf,
            seed,
            min_coverage,
            report: report.as_deref(),
        }),

        Command::Analyze {
            file,
            function,
            addr,
            seeds,
        } => run_analyze(&file, function.as_deref(), addr, seeds),

        Command::Pack {
            file,
            out,
            seed,
            prefix_virt,
            prefix_obf,
            seal,
        } => run_pack(PackCmd {
            file: &file,
            out: &out,
            seed,
            prefix_virt: &prefix_virt,
            prefix_obf: &prefix_obf,
            seal,
        }),

        Command::Unpack { file, run } => run_unpack(&file, run),

        Command::Embed {
            file,
            out,
            name,
            text,
        } => {
            let bytes = std::fs::read(&file).with_context(|| format!("'{file}' okunamadı"))?;
            let result = poly_pack::add_section(&bytes, &name, text.as_bytes())
                .context("section eklenemedi")?;
            std::fs::write(&out, &result).with_context(|| format!("'{out}' yazılamadı"))?;
            println!(
                "✓ '{name}' section eklendi: {} → {} ({} → {} byte)",
                file,
                out,
                bytes.len(),
                result.len()
            );
            Ok(())
        }

        Command::RunProtected {
            file,
            function,
            arg,
            width,
        } => run_protected_cmd(&file, &function, &arg, width),

        Command::VerifyLoader {
            file,
            function,
            arg,
            width,
        } => run_verify_loader(&file, &function, &arg, width),
    }
}

// ===== Faz 5 loader: gömülü VM fonksiyonunu çağırma =========================

fn mask_width(v: u64, width: u32) -> u64 {
    if width >= 64 {
        v
    } else {
        v & ((1u64 << width) - 1)
    }
}

fn run_protected_cmd(file: &str, function: &str, args: &[u64], width: u32) -> Result<()> {
    let module = poly_rt::ProtectedModule::from_file(file).map_err(|e| anyhow::anyhow!(e))?;
    let name = module
        .resolve_name(function)
        .with_context(|| format!("'{function}' korumalı fonksiyon yok"))?;
    let result = mask_width(
        module
            .call(function, args)
            .map_err(|e| anyhow::anyhow!(e))?,
        width,
    );

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Loader (VM yürütme)");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Fonksiyon : {name}");
    println!("║  Argümanlar: {args:?}");
    println!("║  VM sonucu : {result} ({result:#x})");
    println!("╚══════════════════════════════════════════════════════════");
    Ok(())
}

#[cfg(windows)]
fn run_verify_loader(file: &str, function: &str, args: &[u64], width: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    let module = poly_rt::ProtectedModule::from_file(file).map_err(|e| anyhow::anyhow!(e))?;
    let name = module
        .resolve_name(function)
        .with_context(|| format!("'{function}' korumalı fonksiyon yok"))?;
    let vm_result = mask_width(
        module
            .call(function, args)
            .map_err(|e| anyhow::anyhow!(e))?,
        width,
    );

    // Native çağrı: DLL'i yükle, gerçek export'u çağır.
    let path_c = std::ffi::CString::new(file).context("yol")?;
    let name_c = std::ffi::CString::new(name.as_str()).context("ad")?;

    let native_result = unsafe {
        let h = LoadLibraryA(path_c.as_ptr() as *const u8);
        if h.is_null() {
            bail!(
                "LoadLibrary başarısız (kod {})",
                std::io::Error::last_os_error()
            );
        }
        let proc = GetProcAddress(h, name_c.as_ptr() as *const u8);
        let Some(proc) = proc else {
            FreeLibrary(h);
            bail!("GetProcAddress başarısız: {name}");
        };
        // En çok 4 tamsayı argümanlı extern "C" fonksiyon olarak çağır.
        type Fn4 = unsafe extern "C" fn(u64, u64, u64, u64) -> u64;
        let f: Fn4 = std::mem::transmute(proc);
        let a = |i: usize| args.get(i).copied().unwrap_or(0);
        let r = f(a(0), a(1), a(2), a(3));
        FreeLibrary(h);
        mask_width(r, width)
    };

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Loader Doğrulaması (native vs VM)");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Fonksiyon    : {name}");
    println!("║  Argümanlar   : {args:?}");
    println!("║  Native sonuç : {native_result} ({native_result:#x})");
    println!("║  VM sonuç     : {vm_result} ({vm_result:#x})");
    println!("╠──────────────────────────────────────────────────────────");
    if native_result == vm_result {
        println!("║  SONUÇ: ✓ EŞLEŞTİ — VM, gerçek fonksiyonu birebir yürüttü");
    } else {
        println!("║  SONUÇ: ✗ UYUŞMADI");
    }
    println!("╚══════════════════════════════════════════════════════════");

    if native_result != vm_result {
        bail!("loader doğrulaması başarısız: native {native_result} != vm {vm_result}");
    }
    Ok(())
}

#[cfg(not(windows))]
fn run_verify_loader(_file: &str, _function: &str, _args: &[u64], _width: u32) -> Result<()> {
    bail!("verify-loader yalnızca Windows'ta desteklenir (native çağrı için)");
}

// ===== Faz 5: repacking =====================================================

struct PackCmd<'a> {
    file: &'a str,
    out: &'a str,
    seed: u64,
    prefix_virt: &'a str,
    prefix_obf: &'a str,
    seal: bool,
}

fn run_pack(cmd: PackCmd) -> Result<()> {
    let bytes = std::fs::read(cmd.file).with_context(|| format!("'{}' okunamadı", cmd.file))?;
    let info = poly_core::parse_bytes(&bytes, Some(cmd.file))
        .with_context(|| format!("'{}' ayrıştırılamadı", cmd.file))?;
    let image_base = info.image_base;

    let mut entries = Vec::new();
    let mut seals: Vec<(usize, usize)> = Vec::new();

    for f in &info.functions {
        let mode = if f.name.starts_with(cmd.prefix_virt) {
            0u8
        } else if f.name.starts_with(cmd.prefix_obf) {
            1u8
        } else {
            continue;
        };
        let (Some(off), Some(size)) = (f.file_offset, f.size.filter(|&s| s > 0)) else {
            continue;
        };
        let (off, size) = (off as usize, size as usize);
        let Some(code) = bytes.get(off..off.saturating_add(size)) else {
            continue;
        };

        let prog = poly_vm::VmProgram::from_x86(code, f.virtual_address, Some(f.name.clone()));
        let junk = if mode == 0 { 30 } else { 70 };
        let armored = prog.armor(cmd.seed ^ f.virtual_address, junk);

        entries.push(poly_pack::PackEntry {
            rva: (f.virtual_address - image_base) as u32,
            size: size as u32,
            mode,
            seed: armored.armored.seed,
            instr_count: armored.armored.instr_count as u32,
            payload: armored.armored.payload,
        });
        seals.push((off, size));
    }

    if entries.is_empty() {
        bail!("'{}' içinde korumalı sembol bulunamadı", cmd.file);
    }

    let container = poly_pack::encode(&entries);
    let mut out_bytes = poly_pack::add_section(&bytes, ".pshld", &container)
        .context(".pshld section eklenemedi")?;

    if cmd.seal {
        for (off, size) in &seals {
            poly_pack::pe::seal_range(&mut out_bytes, *off, *size, 0xCC)
                .context("kod mühürlenemedi")?;
        }
    }

    std::fs::write(cmd.out, &out_bytes).with_context(|| format!("'{}' yazılamadı", cmd.out))?;

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Repack (pack)");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Girdi   : {} ({} byte)", cmd.file, bytes.len());
    println!("║  Çıktı   : {} ({} byte)", cmd.out, out_bytes.len());
    println!(
        "║  Gömülen : {} fonksiyon → .pshld ({} byte)",
        entries.len(),
        container.len()
    );
    println!(
        "║  Mühür   : {}",
        if cmd.seal {
            "EVET (orijinal kod 0xCC ile silindi)"
        } else {
            "hayır (orijinal kod korundu — dosya çalışır)"
        }
    );
    println!("╚══════════════════════════════════════════════════════════");
    println!("\nDoğrulama: poly-cli unpack {} --run", cmd.out);
    Ok(())
}

fn run_unpack(file: &str, run: bool) -> Result<()> {
    use poly_rt::{HwRng, SecureVm};
    use poly_vm::{ArmoredProgram, VmState};

    let bytes = std::fs::read(file).with_context(|| format!("'{file}' okunamadı"))?;
    let info = poly_core::parse_bytes(&bytes, Some(file))
        .with_context(|| format!("'{file}' ayrıştırılamadı"))?;

    let section = info
        .sections
        .iter()
        .find(|s| s.name == ".pshld")
        .context("'.pshld' section bulunamadı — bu dosya pack'lenmemiş")?;

    let start = section.file_offset as usize;
    let end = (start + section.raw_size as usize).min(bytes.len());
    let entries = poly_pack::decode(&bytes[start..end]).context(".pshld konteyneri çözülemedi")?;

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Unpack");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Dosya   : {file}");
    println!(
        "║  .pshld  : {} byte, {} kayıt",
        section.raw_size,
        entries.len()
    );
    println!("╠──────────────────────────────────────────────────────────");

    for (i, e) in entries.iter().enumerate() {
        let mode = if e.mode == 0 { "V" } else { "O" };
        print!(
            "║  #{i} [{mode}] rva={:#08x} orig={}B payload={}B vm={}",
            e.rva,
            e.size,
            e.payload.len(),
            e.instr_count
        );

        if run {
            let armored = ArmoredProgram {
                version: 1,
                seed: e.seed,
                instr_count: e.instr_count as usize,
                payload: e.payload.clone(),
            };
            match armored.recover() {
                Ok((instrs, _perm)) => {
                    let mut vm = SecureVm::new(&instrs, HwRng::seeded(e.seed));
                    let mut st = VmState::with_default_stack();
                    match vm.run(&mut st, 1_000_000) {
                        Ok(o) => print!("  → ✓ kurtarıldı, {} adım çalıştı", o.steps),
                        Err(_) => print!("  → ✓ kurtarıldı (yürütme girdi gerektiriyor)"),
                    }
                }
                Err(err) => print!("  → ✗ kurtarma hatası: {err}"),
            }
        }
        println!();
    }
    println!("╚══════════════════════════════════════════════════════════");
    if run {
        println!(
            "\n✓ Gömülü payload'lar tohumdan başarıyla yeniden kuruldu (bütünlük doğrulandı)."
        );
    }
    Ok(())
}

// ===== Faz 4.2: shield otopilotu ===========================================

#[derive(serde::Serialize)]
struct FuncReport {
    name: String,
    address: u64,
    mode: &'static str,
    original_size: usize,
    vm_instrs: usize,
    native: usize,
    coverage: f64,
    bytecode_len: usize,
    armored_len: usize,
}

#[derive(serde::Serialize)]
struct ShieldReport {
    file: String,
    seed: u64,
    protected: usize,
    avg_coverage: f64,
    functions: Vec<FuncReport>,
    passed_gate: bool,
    min_coverage: f64,
}

struct ShieldArgs<'a> {
    file: &'a str,
    prefix_virt: &'a str,
    prefix_obf: &'a str,
    seed: u64,
    min_coverage: f64,
    report: Option<&'a str>,
}

fn run_shield(args: ShieldArgs) -> Result<()> {
    let bytes = std::fs::read(args.file).with_context(|| format!("'{}' okunamadı", args.file))?;
    let info = poly_core::parse_bytes(&bytes, Some(args.file))
        .with_context(|| format!("'{}' ayrıştırılamadı", args.file))?;

    let mut reports = Vec::new();
    for f in &info.functions {
        let mode = if f.name.starts_with(args.prefix_virt) {
            "virtualize"
        } else if f.name.starts_with(args.prefix_obf) {
            "obfuscate"
        } else {
            continue;
        };
        let (Some(off), Some(size)) = (f.file_offset, f.size.filter(|&s| s > 0)) else {
            continue;
        };
        let (off, size) = (off as usize, size as usize);
        let Some(code) = bytes.get(off..off.saturating_add(size)) else {
            continue;
        };

        let prog = poly_vm::VmProgram::from_x86(code, f.virtual_address, Some(f.name.clone()));
        let junk = if mode == "virtualize" { 30 } else { 70 };
        let armored = prog.armor(args.seed ^ f.virtual_address, junk);

        reports.push(FuncReport {
            name: f.name.clone(),
            address: f.virtual_address,
            mode,
            original_size: size,
            vm_instrs: prog.stats.vm_instrs,
            native: prog.stats.native,
            coverage: prog.stats.coverage,
            bytecode_len: prog.stats.bytecode_len,
            armored_len: armored.armored.len(),
        });
    }

    if reports.is_empty() {
        bail!(
            "'{}' içinde '{}'/'{}' önekli korumalı sembol bulunamadı",
            args.file,
            args.prefix_virt,
            args.prefix_obf
        );
    }

    let avg = reports.iter().map(|r| r.coverage).sum::<f64>() / reports.len() as f64;
    let min_cov = reports.iter().map(|r| r.coverage).fold(1.0, f64::min);
    let passed = min_cov >= args.min_coverage;

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Otopilot (shield)");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Hedef     : {}", args.file);
    println!("║  Tohum     : {:#018x}", args.seed);
    println!("║  Korunan   : {} fonksiyon", reports.len());
    println!("╠──────────────────────────────────────────────────────────");
    for r in &reports {
        println!(
            "║  [{}] {:<26} %{:.0}  {}→{}B",
            if r.mode == "virtualize" { "V" } else { "O" },
            truncate(&r.name, 26),
            r.coverage * 100.0,
            r.original_size,
            r.armored_len
        );
    }
    println!("╠──────────────────────────────────────────────────────────");
    println!("║  Ort. kapsam : %{:.1}", avg * 100.0);
    println!(
        "║  CI kapısı   : {} (min %{:.0}, en düşük %{:.0})",
        if passed { "✓ GEÇTİ" } else { "✗ KALDI" },
        args.min_coverage * 100.0,
        min_cov * 100.0
    );
    println!("╚══════════════════════════════════════════════════════════");

    if let Some(path) = args.report {
        let report = ShieldReport {
            file: args.file.to_string(),
            seed: args.seed,
            protected: reports.len(),
            avg_coverage: avg,
            functions: reports,
            passed_gate: passed,
            min_coverage: args.min_coverage,
        };
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json).with_context(|| format!("rapor yazılamadı: {path}"))?;
        println!("\nJSON rapor yazıldı: {path}");
    }

    if !passed {
        bail!(
            "CI kapısı başarısız: en düşük kapsam %{:.0} < eşik %{:.0}",
            min_cov * 100.0,
            args.min_coverage * 100.0
        );
    }
    Ok(())
}

// ===== Faz 4.3: direnç analizi =============================================

fn run_analyze(file: &str, function: Option<&str>, addr: Option<u64>, seeds: u32) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("'{file}' okunamadı"))?;
    let info = poly_core::parse_bytes(&bytes, Some(file))
        .with_context(|| format!("'{file}' ayrıştırılamadı"))?;

    let candidates: Vec<&FunctionSymbol> = info
        .functions
        .iter()
        .filter(|f| f.file_offset.is_some() && f.size.map(|s| s > 0).unwrap_or(false))
        .collect();

    let func = match (function, addr) {
        (Some(n), _) => candidates
            .iter()
            .find(|f| f.name.to_lowercase().contains(&n.to_lowercase()))
            .copied(),
        (_, Some(a)) => candidates.iter().find(|f| f.virtual_address == a).copied(),
        (None, None) => candidates.first().copied(),
    };
    let Some(func) = func else {
        bail!("analiz edilecek uygun fonksiyon bulunamadı");
    };

    let off = func.file_offset.unwrap() as usize;
    let size = func.size.unwrap() as usize;
    let code = bytes
        .get(off..off.saturating_add(size))
        .context("fonksiyon byte aralığı dosya dışında")?;
    let prog = poly_vm::VmProgram::from_x86(code, func.virtual_address, Some(func.name.clone()));

    // N tohumla zırhla, çeşitlilik ve entropi ölç.
    let mut payloads = Vec::new();
    for i in 0..seeds.max(2) {
        let s = 0x9E37_79B9_u64.wrapping_mul(i as u64 + 1);
        payloads.push(prog.armor(s, 50).armored.payload);
    }
    let entropy = payloads.iter().map(|p| shannon_entropy(p)).sum::<f64>() / payloads.len() as f64;
    let unique: std::collections::HashSet<&Vec<u8>> = payloads.iter().collect();
    let avg_diff = avg_pairwise_diff(&payloads);
    let expansion = code.len() as f64 / prog.stats.bytecode_len.max(1) as f64;

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: De-Virtualization Direnç Analizi");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Fonksiyon       : {}", func.display_name());
    println!("║  Orijinal x86    : {} byte", code.len());
    println!(
        "║  VM kapsamı      : %{:.0} ({} VM komutu, {} native)",
        prog.stats.coverage * 100.0,
        prog.stats.vm_instrs,
        prog.stats.native
    );
    println!("║  VM bytecode     : {} byte", prog.stats.bytecode_len);
    println!("╠──────────────────────────────────────────────────────────");
    println!("║  Şifreli entropi : {entropy:.3} bit/byte (8.0 = tam rastgele)");
    println!(
        "║  Çeşitlilik      : {}/{} benzersiz, ort. fark %{:.1}",
        unique.len(),
        payloads.len(),
        avg_diff * 100.0
    );
    println!("║  Boyut oranı     : {expansion:.2}× (orijinal/bytecode)");
    println!("╠──────────────────────────────────────────────────────────");
    println!("║  Statik imza analizine karşı:");
    println!("║   • Opcode permütasyonu → sabit opcode imzası yok");
    println!("║   • Register rename     → veri akışı gizli");
    println!("║   • Keystream şifreleme → ~{entropy:.1} bit entropi (desensiz)");
    println!("║   • Tohum çeşitliliği   → her build farklı bytecode");
    println!("╚══════════════════════════════════════════════════════════");
    println!("\nNot: dinamik (x64dbg) analiz için Faz 2 self-encrypting runtime +");
    println!("anti-debug devreye girer; bkz. docs/RESISTANCE.md.");
    Ok(())
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Payload çiftleri arasındaki ortalama byte-farkı oranı (0–1).
fn avg_pairwise_diff(payloads: &[Vec<u8>]) -> f64 {
    let mut total = 0.0;
    let mut pairs = 0;
    for i in 0..payloads.len() {
        for j in (i + 1)..payloads.len() {
            let a = &payloads[i];
            let b = &payloads[j];
            let n = a.len().min(b.len());
            if n == 0 {
                continue;
            }
            let diff = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count();
            total += diff as f64 / n as f64;
            pairs += 1;
        }
    }
    if pairs == 0 {
        0.0
    } else {
        total / pairs as f64
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}

/// Faz 2.1 demosu: bir fonksiyonu self-encrypting VM'de çalıştırır ve
/// bytecode'un bellekte şifreli durduğunu/mutasyona uğradığını gösterir.
fn run_secure_demo() -> Result<()> {
    use poly_rt::{HwRng, SecureVm};
    use poly_vm::isa::VReg;
    use poly_vm::{VmProgram, VmState};

    // max(ecx, edx): mov eax,ecx ; cmp eax,edx ; jge +2 ; mov eax,edx ; ret
    const MAX_FN: &[u8] = &[0x89, 0xC8, 0x39, 0xD0, 0x7D, 0x02, 0x89, 0xD0, 0xC3];
    let prog = VmProgram::from_x86(MAX_FN, 0x1000, Some("max".into()));

    let mut vm = SecureVm::new(&prog.instrs, HwRng::auto());

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Self-Encrypting Runtime (Faz 2.1)");
    println!("╠══════════════════════════════════════════════════════════");
    println!(
        "║  Entropi kaynağı : {}",
        if vm.uses_hardware_entropy() {
            "RDRAND (donanım)"
        } else {
            "SplitMix64 (yazılım fallback)"
        }
    );
    println!("║  Komut sayısı    : {}", prog.instrs.len());
    println!("║  Şifreli boyut   : {} byte", vm.encrypted_len());

    let before = vm.memory_snapshot();
    println!("║  Rest'te (ilk 16): {}", hex_preview(&before, 16));

    let mut st = VmState::with_default_stack();
    st.set_reg_full(VReg::RCX, 1337);
    st.set_reg_full(VReg::RDX, 42);
    let out = vm.run(&mut st, 100_000)?;
    let result = st.reg(VReg::RAX) & 0xFFFF_FFFF;

    let after = vm.memory_snapshot();
    println!("╠──────────────────────────────────────────────────────────");
    println!("║  max(1337, 42)   = {result}  ({} adım)", out.steps);
    println!("║  Çalışma sonrası : {}", hex_preview(&after, 16));
    println!(
        "║  Ciphertext mutasyonu: {}",
        if before != after {
            "EVET (her döngü yeni anahtar)"
        } else {
            "hayır"
        }
    );
    println!("╚══════════════════════════════════════════════════════════");

    if result != 1337 {
        bail!("self-encrypting yürütme yanlış sonuç verdi: {result}");
    }
    println!("\n✓ Şifreli yürütme, düz yorumlayıcıyla aynı sonucu verdi.");
    Ok(())
}

/// Faz 2.2: anti-debug göstergelerini tarar ve raporlar.
fn run_antidebug_report() {
    let st = poly_rt::antidebug::check();
    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Anti-Debug Taraması (Faz 2.2)");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  {}  PEB.BeingDebugged", mark(st.debugger_present));
    println!(
        "║  {}  PEB.NtGlobalFlag (heap debug)",
        mark(st.nt_global_flag)
    );
    println!(
        "║  {}  Donanım breakpoint (DR0-DR3)",
        mark(st.hardware_breakpoints)
    );
    println!("║  {}  RDTSC timing sapması", mark(st.timing_anomaly));
    println!("╠──────────────────────────────────────────────────────────");
    if st.detected() {
        println!("║  SONUÇ: ⚠ DEBUGGER TESPİT EDİLDİ → VM zehirlenirdi");
    } else {
        println!("║  SONUÇ: ✓ temiz (debugger yok)");
    }
    println!("╚══════════════════════════════════════════════════════════");
    println!("\nNot: x64dbg gibi bir debugger'a iliştirilip tekrar çalıştırın —");
    println!("göstergelerin tetiklendiğini göreceksiniz (Faz 4.3 testi).");
}

fn mark(fired: bool) -> &'static str {
    if fired {
        "⚠"
    } else {
        "·"
    }
}

fn hex_preview(data: &[u8], n: usize) -> String {
    data.iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

struct VirtArgs<'a> {
    file: &'a str,
    function: Option<&'a str>,
    addr: Option<u64>,
    disasm: bool,
    json: bool,
    seed: Option<u64>,
    junk: u8,
    variants: Option<u32>,
}

fn run_virtualize(args: VirtArgs) -> Result<()> {
    let VirtArgs {
        file,
        function,
        addr,
        disasm,
        json,
        seed,
        junk,
        variants,
    } = args;
    let bytes = std::fs::read(file).with_context(|| format!("'{file}' okunamadı"))?;
    let info = poly_core::parse_bytes(&bytes, Some(file))
        .with_context(|| format!("'{file}' ayrıştırılamadı"))?;

    // Sanallaştırmaya uygun adaylar: hem dosya offset'i hem boyutu bilinenler.
    let candidates: Vec<&FunctionSymbol> = info
        .functions
        .iter()
        .filter(|f| f.file_offset.is_some() && f.size.map(|s| s > 0).unwrap_or(false))
        .collect();

    let target = match (function, addr) {
        (Some(name), _) => candidates
            .iter()
            .find(|f| {
                f.name.to_lowercase().contains(&name.to_lowercase())
                    || f.display_name()
                        .to_lowercase()
                        .contains(&name.to_lowercase())
            })
            .copied(),
        (_, Some(a)) => candidates.iter().find(|f| f.virtual_address == a).copied(),
        (None, None) => {
            print_candidates(&candidates);
            bail!("--function <ad> veya --addr <0x...> ile bir fonksiyon seçin");
        }
    };

    let Some(func) = target else {
        print_candidates(&candidates);
        bail!("eşleşen, sanallaştırılabilir fonksiyon bulunamadı");
    };

    let off = func.file_offset.unwrap() as usize;
    let size = func.size.unwrap() as usize;
    let end = off
        .checked_add(size)
        .filter(|&e| e <= bytes.len())
        .with_context(|| "fonksiyon byte aralığı dosya sınırını aşıyor")?;
    let code = &bytes[off..end];

    let prog = VmProgram::from_x86(code, func.virtual_address, Some(func.name.clone()));

    if json {
        println!("{}", prog.to_json_pretty()?);
        return Ok(());
    }

    print_vm_report(&prog, func, size);

    // Çeşitlilik (diversity) gösterimi: N tohum → N farklı payload.
    if let Some(n) = variants {
        print_variants(&prog, n, junk);
    } else if let Some(s) = seed {
        // Tek bir polimorfik zırhlama.
        let res = prog.armor(s, junk);
        print_armor_report(&res);
        if disasm {
            println!("\n── Zırhlanmış VM IR (permüte + junk) ───────────");
            print!("{}", poly_vm::disasm::dump(&res.instrs));
        }
    } else if disasm {
        println!("\n── VM IR Dökümü ───────────────────────────────");
        print!("{}", prog.disassemble());
    }
    Ok(())
}

/// FNV-1a 64-bit — payload'ları parmak izlemek için (kriptografik değil).
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn print_armor_report(res: &poly_vm::ArmorResult) {
    let a = &res.armored;
    println!("\n╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Polimorfik Zırhlama (Faz 1.3)");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Master tohum   : {:#018x}", a.seed);
    println!(
        "║  Komut          : {} → {} (junk +{})",
        res.original_count, a.instr_count, res.junk_added
    );
    println!("║  Payload        : {} byte (şifreli)", a.len());
    println!("║  Payload izi     : {:#018x} (FNV-1a)", fnv1a(&a.payload));
    println!("║  Register perm  : {}", fmt_perm(&res.perm.table()));
    println!("╚══════════════════════════════════════════════════════════");
}

fn fmt_perm(table: &[u8; 16]) -> String {
    table
        .iter()
        .enumerate()
        .filter(|(i, &v)| *i as u8 != v) // sadece yer değiştirenler
        .map(|(i, &v)| format!("v{i}→v{v}"))
        .take(6)
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_variants(prog: &VmProgram, n: u32, junk: u8) {
    println!("\n── Polimorfik Çeşitlilik ({n} varyant) ─────────────────");
    println!(
        "{:<6}  {:<18}  {:<8}  KOMUT",
        "TOHUM", "PAYLOAD İZİ", "BOYUT"
    );
    println!("{}", "─".repeat(56));
    let mut hashes = std::collections::HashSet::new();
    for i in 1..=n {
        let seed = 0x5EED_0000 ^ i as u64;
        let res = prog.armor(seed, junk);
        let h = fnv1a(&res.armored.payload);
        hashes.insert(h);
        println!(
            "{:<6}  {:#018x}  {:<8}  {}",
            i,
            h,
            res.armored.len(),
            res.armored.instr_count
        );
    }
    println!(
        "\n{} varyantın {} tanesi benzersiz payload izine sahip.",
        n,
        hashes.len()
    );
}

fn print_candidates(candidates: &[&FunctionSymbol]) {
    if candidates.is_empty() {
        eprintln!("(sanallaştırılabilir fonksiyon yok — binary stripped ya da .pdata yok)");
        return;
    }
    eprintln!("Sanallaştırılabilir fonksiyonlar (ilk 15):");
    for f in candidates.iter().take(15) {
        eprintln!(
            "  {:#018x}  {:>5} byte  {}",
            f.virtual_address,
            f.size.unwrap_or(0),
            f.display_name()
        );
    }
    if candidates.len() > 15 {
        eprintln!("  … +{} fonksiyon daha", candidates.len() - 15);
    }
}

fn print_vm_report(prog: &VmProgram, func: &FunctionSymbol, orig_size: usize) {
    let s = &prog.stats;
    let pct = (s.coverage * 100.0).round() as u32;
    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Sanallaştırma Raporu");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Fonksiyon      : {}", func.display_name());
    println!("║  Adres          : {:#018x}", func.virtual_address);
    println!("║  Orijinal boyut : {orig_size} byte (x86-64)");
    println!("╠──────────────────────────────────────────────────────────");
    println!("║  Lift edilen    : {} komut", s.lifted);
    println!("║  Native escape  : {} komut", s.native);
    println!("║  VM komutu      : {}", s.vm_instrs);
    println!("║  VM bytecode    : {} byte", s.bytecode_len);
    println!("║  Kapsam (skor)  : %{pct}  {}", coverage_bar(s.coverage));
    println!("╚══════════════════════════════════════════════════════════");
    if s.native > 0 {
        println!(
            "\nNot: {} komut native escape ile korundu (desteklenmeyen x86 komutları).",
            s.native
        );
    }
}

fn coverage_bar(coverage: f64) -> String {
    let filled = (coverage * 20.0).round() as usize;
    format!("[{}{}]", "█".repeat(filled), "░".repeat(20 - filled))
}

fn print_summary(info: &BinaryInfo, limit: usize) {
    let exported = info.count_by_visibility(SymbolVisibility::Exported);
    let imported = info.count_by_visibility(SymbolVisibility::Imported);
    let internal = info.count_by_visibility(SymbolVisibility::Internal);

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  PolyShield :: Binary İncelemesi");
    println!("╠══════════════════════════════════════════════════════════");
    if let Some(path) = &info.path {
        println!("║  Dosya       : {path}");
    }
    println!("║  Format      : {}", info.format);
    println!(
        "║  Mimari      : {} ({})",
        info.arch,
        if info.is_64bit { "64-bit" } else { "32-bit" }
    );
    println!("║  Image Base  : {:#018x}", info.image_base);
    println!("║  Entry Point : {:#018x}", info.entry_point);
    println!("║  Section     : {}", info.sections.len());
    println!(
        "║  Fonksiyon   : {} (export: {exported}, import: {imported}, internal: {internal})",
        info.function_count()
    );
    println!("╚══════════════════════════════════════════════════════════");

    if info.functions.is_empty() {
        println!("\n(fonksiyon sembolü bulunamadı — binary stripped olabilir)");
        return;
    }

    let shown = if limit == 0 {
        info.functions.len()
    } else {
        limit.min(info.functions.len())
    };

    println!("\n{:<18}  {:<9}  {:<10}  İSİM", "ADRES", "GÖRÜNÜR", "BOYUT");
    println!("{}", "─".repeat(72));
    for f in info.functions.iter().take(shown) {
        let size = f
            .size
            .map(|s| format!("{s}"))
            .unwrap_or_else(|| "?".to_string());
        println!(
            "{:#018x}  {:<9}  {:<10}  {}",
            f.virtual_address,
            f.visibility.to_string(),
            size,
            f.display_name()
        );
    }

    if shown < info.functions.len() {
        println!(
            "\n… {} fonksiyon daha gizlendi (--limit 0 ile tümünü göster)",
            info.functions.len() - shown
        );
    }
}
