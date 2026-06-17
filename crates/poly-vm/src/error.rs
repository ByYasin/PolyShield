//! poly-vm hata tipleri.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VmError {
    #[error("bytecode beklenenden kısa (offset {offset}, gereken {needed} byte)")]
    Truncated { offset: usize, needed: usize },

    #[error("geçersiz opcode byte'ı: 0x{0:02x}")]
    BadOpcode(u8),

    #[error("geçersiz operand türü etiketi: {0}")]
    BadOperandTag(u8),

    #[error("geçersiz boyut/koşul kodu")]
    BadField,

    #[error("yorumlayıcı hatası: {0}")]
    Interp(String),
}

pub type Result<T> = std::result::Result<T, VmError>;
