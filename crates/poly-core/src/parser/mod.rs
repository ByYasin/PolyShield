//! Binary ayrıştırma modülü.
//!
//! Tek giriş noktaları [`parse_file`] ve [`parse_bytes`]'tir. Bunlar magic
//! byte'lara bakarak formatı tespit eder ve uygun alt ayrıştırıcıya (PE/ELF)
//! yönlendirir. Çıktı, formattan bağımsız [`BinaryInfo`] modelidir.

mod demangle;
mod elf;
pub mod model;
mod pe;

use std::fs;
use std::path::Path;

use crate::error::{PolyError, Result};
pub use model::{Arch, BinaryFormat, BinaryInfo, FunctionSymbol, SectionInfo, SymbolVisibility};

/// Format tespiti için gereken minimum byte sayısı (`\x7fELF` = 4 byte).
const MIN_MAGIC_LEN: usize = 4;

/// Diskteki bir dosyayı okuyup ayrıştırır.
///
/// # Hatalar
/// Dosya okunamazsa, format tanınmazsa ya da ayrıştırma başarısız olursa
/// [`PolyError`] döner. Panic atmaz.
pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<BinaryInfo> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| PolyError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let mut info = parse_bytes(&bytes, Some(&path.to_string_lossy()))?;
    info.path = Some(path.to_string_lossy().into_owned());
    Ok(info)
}

/// Bellekteki byte dizisini ayrıştırır.
///
/// `path_hint` yalnızca raporlama amaçlıdır; ayrıştırma davranışını etkilemez.
pub fn parse_bytes(bytes: &[u8], path_hint: Option<&str>) -> Result<BinaryInfo> {
    if bytes.len() < MIN_MAGIC_LEN {
        return Err(PolyError::TooShort {
            needed: MIN_MAGIC_LEN,
            got: bytes.len(),
        });
    }

    match detect_format(bytes) {
        Some(BinaryFormat::Pe) => {
            let mut info = pe::parse(bytes)?;
            info.path = path_hint.map(str::to_owned);
            Ok(info)
        }
        Some(BinaryFormat::Elf) => {
            let mut info = elf::parse(bytes)?;
            info.path = path_hint.map(str::to_owned);
            Ok(info)
        }
        None => Err(PolyError::UnknownFormat {
            magic: magic_hex(bytes),
        }),
    }
}

/// Magic byte'lara bakarak formatı tespit eder.
fn detect_format(bytes: &[u8]) -> Option<BinaryFormat> {
    // PE: 'M' 'Z' (DOS stub) ile başlar.
    if bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z' {
        return Some(BinaryFormat::Pe);
    }
    // ELF: 0x7F 'E' 'L' 'F'
    if bytes.len() >= 4 && bytes[0..4] == [0x7f, b'E', b'L', b'F'] {
        return Some(BinaryFormat::Elf);
    }
    None
}

/// İlk birkaç byte'ı hata mesajı için hex string'e çevirir.
fn magic_hex(bytes: &[u8]) -> String {
    let n = bytes.len().min(MIN_MAGIC_LEN);
    bytes[..n]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pe_magic() {
        let buf = b"MZ\x90\x00rest";
        assert_eq!(detect_format(buf), Some(BinaryFormat::Pe));
    }

    #[test]
    fn detects_elf_magic() {
        let buf = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(detect_format(buf), Some(BinaryFormat::Elf));
    }

    #[test]
    fn rejects_unknown_magic() {
        let buf = b"%PDF-1.7";
        assert_eq!(detect_format(buf), None);
    }

    #[test]
    fn too_short_input_errors() {
        let err = parse_bytes(b"MZ", None).unwrap_err();
        matches!(err, PolyError::TooShort { .. });
    }

    #[test]
    fn unknown_format_errors_without_panic() {
        let err = parse_bytes(b"not a binary file at all", None).unwrap_err();
        matches!(err, PolyError::UnknownFormat { .. });
    }
}
