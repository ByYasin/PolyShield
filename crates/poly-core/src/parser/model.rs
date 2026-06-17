//! Ayrıştırılmış bir binary'i temsil eden, formattan bağımsız veri modeli.
//!
//! Bu yapılar PE ve ELF ayrıştırıcılarının ortak çıktısıdır ve `serde` ile
//! JSON'a serileştirilebilir. JSON formatı, Faz 3'teki C++ GUI ile kurulacak
//! IPC (Named Pipe) köprüsünün sözleşmesidir.

use serde::{Deserialize, Serialize};

/// Tanınan binary dosya formatları.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BinaryFormat {
    /// Windows Portable Executable (.exe / .dll / .sys).
    Pe,
    /// Unix/Linux Executable and Linkable Format.
    Elf,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::Pe => write!(f, "PE"),
            BinaryFormat::Elf => write!(f, "ELF"),
        }
    }
}

/// Hedef işlemci mimarisi.
///
/// Bilinmeyen makine tipleri ham değeriyle birlikte saklanır; böylece ileride
/// desteklenecek mimariler veri kaybı olmadan raporlanabilir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Unknown(u16),
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86 => write!(f, "x86"),
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Arm => write!(f, "arm"),
            Arch::Aarch64 => write!(f, "aarch64"),
            Arch::Unknown(v) => write!(f, "unknown(0x{v:04x})"),
        }
    }
}

/// Bir sembolün dış dünyaya görünürlüğü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolVisibility {
    /// Dosyadan dışa aktarılan (export edilen) fonksiyon.
    Exported,
    /// Başka bir modülden içe aktarılan (import edilen) fonksiyon.
    Imported,
    /// Yalnızca modül içinde görünen yerel fonksiyon.
    Internal,
}

impl std::fmt::Display for SymbolVisibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolVisibility::Exported => write!(f, "exported"),
            SymbolVisibility::Imported => write!(f, "imported"),
            SymbolVisibility::Internal => write!(f, "internal"),
        }
    }
}

/// Binary içindeki bir bölüm (section) hakkında özet bilgi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    /// Bölümün yüklendikten sonraki sanal adresi (image base dahil mutlak adres).
    pub virtual_address: u64,
    pub virtual_size: u64,
    /// Bölümün dosya içindeki ham offset'i.
    pub file_offset: u64,
    pub raw_size: u64,
    pub executable: bool,
    pub readable: bool,
    pub writable: bool,
}

/// Tek bir fonksiyon sembolü.
///
/// Sanallaştırma/karartma için aday birim budur. `virtual_address` ve
/// (varsa) `size`/`file_offset`, sonraki fazlarda kodun çıkarılıp dönüştürülmesi
/// için gereken konumsal bilgidir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSymbol {
    /// Ham sembol adı (mangled olabilir). Sembol yoksa `sub_<adres>`.
    pub name: String,
    /// İnsana okunabilir, çözülmüş (demangled) ad — varsa.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    /// Mutlak sanal adres (image base dahil).
    pub virtual_address: u64,
    /// Dosya içindeki ham offset — hesaplanabildiyse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    /// Fonksiyonun byte cinsinden boyutu — biliniyorsa.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub visibility: SymbolVisibility,
    /// Fonksiyonun bulunduğu bölümün adı — çözülebildiyse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

impl FunctionSymbol {
    /// Görüntülenmek için en uygun adı döndürür (varsa demangled).
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

/// Ayrıştırılmış bir binary'in tam tanımı — parser çıktısının kök yapısı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// Ayrıştırılan dosyanın yolu (varsa).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub format: BinaryFormat,
    pub arch: Arch,
    pub is_64bit: bool,
    /// Modülün tercih edilen yükleme adresi (image base).
    pub image_base: u64,
    /// Giriş noktasının mutlak sanal adresi.
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub functions: Vec<FunctionSymbol>,
}

impl BinaryInfo {
    /// Toplam fonksiyon sembolü sayısı.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Yalnızca dışa aktarılan (export) fonksiyonlar.
    pub fn exported_functions(&self) -> impl Iterator<Item = &FunctionSymbol> {
        self.functions
            .iter()
            .filter(|f| f.visibility == SymbolVisibility::Exported)
    }

    /// Belirli bir görünürlükteki fonksiyon sayısı.
    pub fn count_by_visibility(&self, vis: SymbolVisibility) -> usize {
        self.functions
            .iter()
            .filter(|f| f.visibility == vis)
            .count()
    }

    /// Modeli okunabilir (pretty) JSON metnine serileştirir.
    pub fn to_json_pretty(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
