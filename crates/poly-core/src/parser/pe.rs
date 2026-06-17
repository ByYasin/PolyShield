//! Windows PE (Portable Executable) ayrıştırıcısı (goblin tabanlı).
//!
//! Fonksiyon sembollerini üç kaynaktan toplar:
//!   1. **Export tablosu** → dışa aktarılan fonksiyonlar (adlı).
//!   2. **Import tablosu** → içe aktarılan fonksiyonlar.
//!   3. **`.pdata` exception verisi** (x64) → sembol stripped olsa bile gerçek
//!      fonksiyon sınırları (`begin`/`end` adresleri). Adı bilinmeyenler için
//!      `sub_<rva>` placeholder üretilir.
//!
//! Aynı adrese düşen kayıtlar birleştirilir; adlı sembol daima placeholder'a
//! tercih edilir, eksik boyut/section bilgisi tamamlanır.

use std::collections::BTreeMap;

use goblin::pe::PE;

use super::demangle::demangle;
use super::model::{Arch, BinaryFormat, BinaryInfo, FunctionSymbol, SectionInfo, SymbolVisibility};
use crate::error::Result;

// PE section characteristics bayrakları (winnt.h).
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// COFF makine tipleri (winnt.h).
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

pub fn parse(bytes: &[u8]) -> Result<BinaryInfo> {
    let pe = PE::parse(bytes)?;

    let image_base = pe.image_base as u64;
    let arch = map_arch(pe.header.coff_header.machine);
    let sections = collect_sections(&pe);

    // Adrese göre indekslenmiş birleşik fonksiyon haritası.
    let mut funcs: BTreeMap<u64, FunctionSymbol> = BTreeMap::new();

    collect_exports(&pe, image_base, &sections, &mut funcs);
    collect_imports(&pe, image_base, &mut funcs);
    collect_exception_functions(&pe, image_base, &sections, &mut funcs);

    Ok(BinaryInfo {
        path: None,
        format: BinaryFormat::Pe,
        arch,
        is_64bit: pe.is_64,
        image_base,
        entry_point: image_base + pe.entry as u64,
        sections,
        functions: funcs.into_values().collect(),
    })
}

fn map_arch(machine: u16) -> Arch {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Arch::X86,
        IMAGE_FILE_MACHINE_AMD64 => Arch::X86_64,
        IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARMNT => Arch::Arm,
        IMAGE_FILE_MACHINE_ARM64 => Arch::Aarch64,
        other => Arch::Unknown(other),
    }
}

fn collect_sections(pe: &PE) -> Vec<SectionInfo> {
    pe.sections
        .iter()
        .map(|s| {
            let name = s.name().map(str::to_owned).unwrap_or_else(|_| {
                String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string()
            });
            let ch = s.characteristics;
            SectionInfo {
                name,
                virtual_address: pe.image_base as u64 + s.virtual_address as u64,
                virtual_size: s.virtual_size as u64,
                file_offset: s.pointer_to_raw_data as u64,
                raw_size: s.size_of_raw_data as u64,
                executable: ch & IMAGE_SCN_MEM_EXECUTE != 0,
                readable: ch & IMAGE_SCN_MEM_READ != 0,
                writable: ch & IMAGE_SCN_MEM_WRITE != 0,
            }
        })
        .collect()
}

fn collect_exports(
    pe: &PE,
    image_base: u64,
    sections: &[SectionInfo],
    funcs: &mut BTreeMap<u64, FunctionSymbol>,
) {
    for exp in &pe.exports {
        // Reexport'lar (forwarder) gerçek kod içermez; atla.
        if exp.reexport.is_some() {
            continue;
        }
        let va = image_base + exp.rva as u64;
        let name = exp
            .name
            .map(str::to_owned)
            .unwrap_or_else(|| format!("sub_{va:x}"));
        let size = if exp.size > 0 {
            Some(exp.size as u64)
        } else {
            None
        };

        insert_or_merge(
            funcs,
            FunctionSymbol {
                demangled: demangle(&name),
                name,
                virtual_address: va,
                file_offset: exp.offset.map(|o| o as u64),
                size,
                visibility: SymbolVisibility::Exported,
                section: section_name_for(sections, va),
            },
        );
    }
}

fn collect_imports(pe: &PE, image_base: u64, funcs: &mut BTreeMap<u64, FunctionSymbol>) {
    for imp in &pe.imports {
        // Import'lar IAT slot adresine (thunk) bağlanır; gerçek hedef başka
        // modüldedir. Adresi yine de raporlarız ama section çözmeyiz.
        let va = image_base + imp.rva as u64;
        let name = format!("{}!{}", imp.dll, imp.name);
        insert_or_merge(
            funcs,
            FunctionSymbol {
                demangled: demangle(&imp.name),
                name,
                virtual_address: va,
                file_offset: Some(imp.offset as u64),
                size: if imp.size > 0 {
                    Some(imp.size as u64)
                } else {
                    None
                },
                visibility: SymbolVisibility::Imported,
                section: None,
            },
        );
    }
}

/// x64 `.pdata` bölümündeki RUNTIME_FUNCTION kayıtlarından fonksiyon sınırları.
fn collect_exception_functions(
    pe: &PE,
    image_base: u64,
    sections: &[SectionInfo],
    funcs: &mut BTreeMap<u64, FunctionSymbol>,
) {
    let Some(exception_data) = pe.exception_data.as_ref() else {
        return;
    };

    for rf in exception_data.functions().flatten() {
        let va = image_base + rf.begin_address as u64;
        let size = (rf.end_address.saturating_sub(rf.begin_address)) as u64;
        insert_or_merge(
            funcs,
            FunctionSymbol {
                name: format!("sub_{va:x}"),
                demangled: None,
                virtual_address: va,
                file_offset: file_offset_for(sections, va),
                size: if size > 0 { Some(size) } else { None },
                visibility: SymbolVisibility::Internal,
                section: section_name_for(sections, va),
            },
        );
    }
}

/// Yeni sembolü ekler; aynı adres zaten varsa daha bilgilendirici olanı korur.
fn insert_or_merge(funcs: &mut BTreeMap<u64, FunctionSymbol>, incoming: FunctionSymbol) {
    use std::collections::btree_map::Entry;
    match funcs.entry(incoming.virtual_address) {
        Entry::Vacant(e) => {
            e.insert(incoming);
        }
        Entry::Occupied(mut e) => {
            let existing = e.get_mut();
            // Adlı sembol, `sub_` placeholder'a tercih edilir.
            let existing_is_placeholder = existing.name.starts_with("sub_");
            let incoming_is_placeholder = incoming.name.starts_with("sub_");
            if existing_is_placeholder && !incoming_is_placeholder {
                existing.name = incoming.name;
                existing.demangled = incoming.demangled;
                existing.visibility = incoming.visibility;
            }
            // Eksik alanları tamamla.
            existing.size = existing.size.or(incoming.size);
            existing.file_offset = existing.file_offset.or(incoming.file_offset);
            existing.section = existing.section.take().or(incoming.section);
        }
    }
}

/// Verilen sanal adresi içeren bölümün adını döndürür.
fn section_name_for(sections: &[SectionInfo], va: u64) -> Option<String> {
    sections
        .iter()
        .find(|s| va >= s.virtual_address && va < s.virtual_address + s.virtual_size.max(1))
        .map(|s| s.name.clone())
}

/// Sanal adresi dosya offset'ine çevirir (RVA → file offset eşlemesi).
fn file_offset_for(sections: &[SectionInfo], va: u64) -> Option<u64> {
    sections.iter().find_map(|s| {
        let end = s.virtual_address + s.virtual_size.max(1);
        if va >= s.virtual_address && va < end {
            let delta = va - s.virtual_address;
            if delta < s.raw_size {
                return Some(s.file_offset + delta);
            }
        }
        None
    })
}
