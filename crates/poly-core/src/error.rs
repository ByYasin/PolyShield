//! PolyShield çekirdek motorunun hata tipleri.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Çekirdek motorun tüm public API'lerinin döndürdüğü hata türü.
///
/// `parse_*` fonksiyonları hiçbir koşulda panic atmaz; geçersiz girdiler
/// daima bu enum'un bir varyantı olarak geri döner.
#[derive(Debug, Error)]
pub enum PolyError {
    /// Dosya okunamadı (yol yok, izin yok, vb.).
    #[error("dosya okunamadı: {path} ({source})")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// Girdi çok kısa ya da boş; format tespiti için yeterli byte yok.
    #[error("girdi çok kısa: format tespiti için en az {needed} byte gerekli, {got} byte var")]
    TooShort { needed: usize, got: usize },

    /// Magic byte'lar ne PE ('MZ') ne de ELF ('\\x7fELF') ile eşleşmedi.
    #[error("desteklenmeyen ya da tanınmayan binary formatı (magic: {magic})")]
    UnknownFormat { magic: String },

    /// Format tanındı ama goblin ayrıştırma sırasında bir hata üretti.
    #[error("binary ayrıştırma hatası: {0}")]
    Parse(String),

    /// JSON serileştirme hatası.
    #[error("JSON serileştirme hatası: {0}")]
    Json(#[from] serde_json::Error),
}

/// Çekirdek motor genelinde kullanılan kısa `Result` takma adı.
pub type Result<T> = std::result::Result<T, PolyError>;

impl From<goblin::error::Error> for PolyError {
    fn from(e: goblin::error::Error) -> Self {
        PolyError::Parse(e.to_string())
    }
}
