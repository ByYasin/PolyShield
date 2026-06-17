//! # poly-pack
//!
//! PolyShield repacker (Faz 5): zırhlı VM payload'larını bir `.pshld` section'ı
//! olarak PE dosyasına gömer ve isteğe bağlı olarak orijinal kod bölgelerini
//! mühürler (0xCC).
//!
//! - [`pe::add_section`] — PE'ye yeni section ekler (header fixup).
//! - [`pe::seal_range`] — orijinal kodu üzerine yazar.
//! - [`container`] — `.pshld` kendini-tanımlayıcı konteyner formatı.
//!
//! ## Kapsam (dürüst)
//! Bu modül **PE cerrahisini** ve **payload gömmeyi** yapar; üretilen dosya
//! geçerli bir PE olarak yüklenir ve payload bütünlüğü doğrulanabilir
//! (`poly-cli unpack --run`). Çalışma anında bu payload'ı host süreçte yürüten
//! tam bir **in-process loader/stub enjeksiyonu** ayrı, daha büyük bir adımdır
//! ve bu sürümün kapsamı dışındadır (bkz. `docs/RESISTANCE.md`).

pub mod container;
pub mod elf;
pub mod error;
pub mod pe;

pub use container::{decode, encode, PackEntry};
pub use error::{PackError, Result};

/// Formatı (PE/ELF) magic byte'tan tespit edip uygun section ekleyiciyi çağırır.
pub fn add_section(input: &[u8], name: &str, data: &[u8]) -> Result<Vec<u8>> {
    if input.len() >= 4 && input[0..4] == [0x7f, b'E', b'L', b'F'] {
        elf::add_section(input, name, data)
    } else {
        pe::add_section(input, name, data)
    }
}
