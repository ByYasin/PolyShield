//! `.pshld` section konteyner formatı.
//!
//! Zırhlı her fonksiyonun meta verisini ve şifreli payload'ını taşır. Kendini
//! tanımlayıcıdır: bir loader yalnızca bu section'ı okuyarak tüm korumalı
//! fonksiyonları yeniden kurabilir.
//!
//! ```text
//! magic   : "PSHLD1\0\0"  (8 byte)
//! count   : u32
//! entry[] :
//!   rva         : u32   (fonksiyonun image base'e göreli adresi)
//!   size        : u32   (orijinal x86 boyutu)
//!   mode        : u8    (0 = virtualize, 1 = obfuscate)
//!   seed        : u64   (bu fonksiyona özgü efektif polimorfik tohum)
//!   instr_count : u32   (zırhlı VM komutu sayısı)
//!   payload_len : u32
//!   payload     : [u8]  (şifreli bytecode)
//! ```

use crate::error::{PackError, Result};

const MAGIC: &[u8; 8] = b"PSHLD1\0\0";

/// Bir korumalı fonksiyonun konteyner kaydı.
#[derive(Debug, Clone)]
pub struct PackEntry {
    pub rva: u32,
    pub size: u32,
    pub mode: u8,
    pub seed: u64,
    pub instr_count: u32,
    pub payload: Vec<u8>,
}

/// Kayıtları ikili konteynere serileştirir.
pub fn encode(entries: &[PackEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.rva.to_le_bytes());
        out.extend_from_slice(&e.size.to_le_bytes());
        out.push(e.mode);
        out.extend_from_slice(&e.seed.to_le_bytes());
        out.extend_from_slice(&e.instr_count.to_le_bytes());
        out.extend_from_slice(&(e.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.payload);
    }
    out
}

/// Konteyneri çözer (trailing padding'i yok sayar).
pub fn decode(bytes: &[u8]) -> Result<Vec<PackEntry>> {
    let mut c = Cursor::new(bytes);
    let magic = c.take(8)?;
    if magic != MAGIC {
        return Err(PackError::BadContainer("magic eşleşmedi".into()));
    }
    let count = c.u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let rva = c.u32()?;
        let size = c.u32()?;
        let mode = c.u8()?;
        let seed = c.u64()?;
        let instr_count = c.u32()?;
        let payload_len = c.u32()? as usize;
        let payload = c.take(payload_len)?.to_vec();
        entries.push(PackEntry {
            rva,
            size,
            mode,
            seed,
            instr_count,
            payload,
        });
    }
    Ok(entries)
}

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p + n;
        if end > self.b.len() {
            return Err(PackError::BadContainer("beklenmedik dosya sonu".into()));
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let entries = vec![
            PackEntry {
                rva: 0x1000,
                size: 80,
                mode: 0,
                seed: 0xDEAD_BEEF,
                instr_count: 17,
                payload: vec![1, 2, 3, 4, 5],
            },
            PackEntry {
                rva: 0x2000,
                size: 40,
                mode: 1,
                seed: 0x1234,
                instr_count: 9,
                payload: vec![9, 8, 7],
            },
        ];
        let bytes = encode(&entries);
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0u8; 64]); // section padding'i taklit et
        let back = decode(&padded).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].rva, 0x1000);
        assert_eq!(back[0].payload, vec![1, 2, 3, 4, 5]);
        assert_eq!(back[1].mode, 1);
        assert_eq!(back[1].seed, 0x1234);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(decode(b"XXXXXXXX\0\0\0\0").is_err());
    }
}
