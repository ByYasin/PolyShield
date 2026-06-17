//! Entegrasyon testi: host platformunun GERÇEK bir binary'sini ayrıştırır.
//!
//! `current_exe()` Windows'ta bir PE, Linux'ta bir ELF döndürür; böylece
//! ayrıştırıcı tek bir testte uçtan uca, gerçek bir dosya üzerinde doğrulanır.

use poly_core::{parse_file, BinaryFormat};

#[test]
fn parses_host_test_binary() {
    let exe = std::env::current_exe().expect("test binary yolu alınamadı");
    let info = parse_file(&exe).expect("host binary ayrıştırılamalı");

    // Platforma göre beklenen format.
    #[cfg(windows)]
    assert_eq!(info.format, BinaryFormat::Pe);
    #[cfg(unix)]
    assert_eq!(info.format, BinaryFormat::Elf);

    // Temel alanlar dolu olmalı.
    assert!(info.entry_point != 0, "entry point sıfır olmamalı");
    assert!(!info.sections.is_empty(), "en az bir section olmalı");
    assert!(
        info.function_count() > 0,
        "gerçek bir binary'de en az bir fonksiyon bulunmalı"
    );

    // En az bir çalıştırılabilir section olmalı.
    assert!(
        info.sections.iter().any(|s| s.executable),
        "çalıştırılabilir section bulunmalı"
    );
}

#[test]
fn json_roundtrips() {
    let exe = std::env::current_exe().unwrap();
    let info = parse_file(&exe).unwrap();
    let json = info.to_json_pretty().expect("JSON üretilmeli");
    let back: poly_core::BinaryInfo = serde_json::from_str(&json).expect("JSON geri okunmalı");
    assert_eq!(info.format, back.format);
    assert_eq!(info.function_count(), back.function_count());
}
