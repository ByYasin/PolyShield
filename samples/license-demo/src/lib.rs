//! PolyShield örnek hedef (cdylib).
//!
//! Korunması istenen fonksiyonlar `#[poly_virtualize]` / `#[poly_obfuscate]` ile
//! işaretlenir; cdylib olarak derlendiğinde `polyv_*` / `polyo_*` export'ları
//! oluşur. `extern "C"` ABI'si, loader'ın çağrı konvansiyonunu (Win64) kesin
//! bilmesini sağlar.
//!
//! ```text
//! cargo build -p license-demo
//! cargo run -p poly-cli -- pack target/debug/license_demo.dll -o shielded.dll
//! cargo run -p poly-cli -- verify-loader shielded.dll --function poly_demo_add --arg 100 --arg 23
//! ```

use poly_macros::{poly_obfuscate, poly_virtualize};

/// Tamamen saf, %100 sanallaştırılabilir bir fonksiyon — loader eşitlik testi.
/// Yalnızca add/xor/sub kullanır (çarpma yok), böylece VM tam yürütebilir.
#[poly_virtualize]
pub extern "C" fn poly_demo_add(a: u64, b: u64) -> u64 {
    let s = a.wrapping_add(b);
    (s ^ 0x55AA).wrapping_sub(7)
}

/// Basit bir lisans doğrulaması — korunması kritik bir fonksiyon örneği.
#[poly_virtualize]
pub extern "C" fn check_license(key: u64) -> u64 {
    let scrambled = key ^ 0xDEAD_BEEF_0000_1337;
    if scrambled.rotate_left(13) & 0xFFFF == 0x4242 {
        1
    } else {
        0
    }
}

/// Salt-okunur bir tabloyu RIP-relative okur — loader image desteğini sınar.
static LOOKUP: [u64; 4] = [0x1111, 0x2222, 0x3333, 0x4444];

#[poly_virtualize]
pub extern "C" fn table_lookup(i: u64) -> u64 {
    // Ham pointer aritmetiği: debug'da bile sınır-kontrolü çağrısı üretmez,
    // saf bir RIP-relative + indeksli okuma kalır.
    let idx = (i & 3) as usize;
    unsafe { *LOOKUP.as_ptr().add(idx) }
}

/// Gizli bir sabiti türeten yardımcı — karartma örneği (xorshift).
#[poly_obfuscate]
pub extern "C" fn secret_value(seed: u64) -> u64 {
    let mut x = seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x.wrapping_add(0xC0FF_EE00)
}
