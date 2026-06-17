//! Sanallaştırılmış bir fonksiyonun tam tanımı: `VmProgram`.
//!
//! IR komutlarını, kaynak meta verisini ve lift istatistiklerini bir arada
//! tutar; serde ile JSON'a serileştirilebilir (Faz 3 GUI / Faz 4 CLI raporları).

use serde::{Deserialize, Serialize};

use crate::disasm;
use crate::encoder::{self, OpcodeMap};
use crate::isa::VmInstr;
use crate::lifter::{self, LiftResult};

/// Sanallaştırma istatistikleri (güvenlik skoru ve raporlama için).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VmStats {
    /// Lift edilen (sanallaştırılan) x86 komutu sayısı.
    pub lifted: usize,
    /// Native escape'e düşen komut sayısı.
    pub native: usize,
    /// Üretilen VM komutu sayısı.
    pub vm_instrs: usize,
    /// Üretilen bytecode boyutu (byte).
    pub bytecode_len: usize,
    /// Sanallaştırma kapsamı (0.0–1.0).
    pub coverage: f64,
}

/// Bir fonksiyonun sanallaştırılmış hali.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmProgram {
    /// Kaynak fonksiyonun adı (varsa).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// Kaynak fonksiyonun orijinal sanal adresi.
    pub source_addr: u64,
    /// VM komutları (IR).
    pub instrs: Vec<VmInstr>,
    pub stats: VmStats,
}

impl VmProgram {
    /// Bir fonksiyonun x86-64 byte'larını sanallaştırır.
    ///
    /// `base`, byte'ların başladığı sanal adrestir. Bytecode boyutu, varsayılan
    /// (identity) opcode eşlemesiyle hesaplanır.
    pub fn from_x86(code: &[u8], base: u64, name: Option<String>) -> Self {
        let LiftResult {
            instrs,
            lifted,
            native,
        } = lifter::lift(code, base);

        let bytecode = encoder::encode(&instrs, &OpcodeMap::identity());
        let coverage = {
            let total = lifted + native;
            if total == 0 {
                0.0
            } else {
                lifted as f64 / total as f64
            }
        };

        VmProgram {
            source_name: name,
            source_addr: base,
            stats: VmStats {
                lifted,
                native,
                vm_instrs: instrs.len(),
                bytecode_len: bytecode.len(),
                coverage,
            },
            instrs,
        }
    }

    /// Programı verilen opcode eşlemesiyle kompakt bytecode'a serileştirir.
    pub fn encode(&self, map: &OpcodeMap) -> Vec<u8> {
        encoder::encode(&self.instrs, map)
    }

    /// Programı polimorfik motorla zırhlar (Faz 1.3). Aynı tohum → aynı çıktı.
    pub fn armor(&self, seed: u64, junk_density: u8) -> crate::polymorph::ArmorResult {
        crate::polymorph::armor(&self.instrs, seed, junk_density)
    }

    /// IR'ın okunabilir metin dökümü.
    pub fn disassemble(&self) -> String {
        disasm::dump(&self.instrs)
    }

    /// JSON (pretty) çıktısı.
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}
