//! Örnek "korumalı uygulama": `poly-rt` runtime'ını **gömer** ve korumalı bir
//! fonksiyonu native çağırmak yerine gömülü VM üzerinde çalıştırır.
//!
//! Bu, protector'ın SDK modelini gösterir: geliştirici, packed bir modülü
//! yükler ve korumalı fonksiyonları `module.call(...)` ile dispatch eder.
//! VM, uygulamanın **kendi sürecinde** çalışır (in-process); kod bellekte
//! şifrelidir ve RDRAND ile her döngü yeniden şifrelenir.
//!
//! Kullanım:
//! ```text
//! protected-app <packed.dll> [fonksiyon] [arg...]
//! ```
//! Argüman verilmezse yerleşik bir gösterim çalıştırır.

use std::process::ExitCode;

use poly_rt::ProtectedModule;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let path = match args.get(1) {
        Some(p) => p.clone(),
        None => {
            eprintln!("kullanım: protected-app <packed.dll> [fonksiyon] [arg...]");
            return ExitCode::FAILURE;
        }
    };

    let module = match ProtectedModule::from_file(&path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("modül yüklenemedi: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  Korumalı Uygulama — gömülü poly-rt loader");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Modül: {path}");
    let mut names: Vec<&String> = module.names().collect();
    names.sort();
    println!("║  Korumalı fonksiyonlar: {names:?}");
    println!("╚══════════════════════════════════════════════════════════");

    // Açık fonksiyon verildiyse onu çağır, yoksa yerleşik gösterim.
    if let Some(func) = args.get(2) {
        let call_args: Vec<u64> = args[3..].iter().filter_map(|s| parse_u64(s)).collect();
        match module.call(func, &call_args) {
            Ok(r) => {
                println!("\n{func}({call_args:?}) [VM] = {r} ({r:#x})");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("çağrı hatası: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        // Yerleşik gösterim: birkaç korumalı çağrıyı VM'de çalıştır.
        let demos: [(&str, &[u64]); 3] = [
            ("poly_demo_add", &[100, 23]),
            ("table_lookup", &[2]),
            ("secret_value", &[0x1357]),
        ];
        println!("\nGömülü VM üzerinde çalıştırma:");
        for (name, a) in demos {
            match module.call(name, a) {
                Ok(r) => println!("  ✓ {name}({a:?}) = {r} ({r:#x})"),
                Err(e) => println!("  · {name}: {e}"),
            }
        }
        ExitCode::SUCCESS
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}
