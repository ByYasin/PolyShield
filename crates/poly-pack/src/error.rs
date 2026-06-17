//! poly-pack hata tipleri.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackError {
    #[error("PE ayrıştırma hatası: {0}")]
    Parse(String),

    #[error("yalnızca PE32+ (x64) destekleniyor (magic {0:#06x})")]
    NotPe64(u16),

    #[error("yalnızca ELF64 little-endian destekleniyor")]
    NotElf64,

    #[error("ELF section header tablosu geçersiz")]
    BadElf,

    #[error("başlık alanında yeni section için yer yok (SizeOfHeaders dolu)")]
    NoHeaderRoom,

    #[error("optional header bulunamadı")]
    NoOptionalHeader,

    #[error("geçersiz .pshld konteyneri: {0}")]
    BadContainer(String),
}

impl From<goblin::error::Error> for PackError {
    fn from(e: goblin::error::Error) -> Self {
        PackError::Parse(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, PackError>;
