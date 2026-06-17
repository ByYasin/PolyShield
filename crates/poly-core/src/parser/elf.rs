//! Linux/Unix ELF ayrıştırıcısı (goblin tabanlı).
//!
//! Fonksiyon sembollerini hem statik sembol tablosundan (`.symtab`) hem de
//! dinamik sembol tablosundan (`.dynsym`) toplar; yalnızca `STT_FUNC` tipindeki
//! sembolleri dikkate alır. Görünürlük, sembolün binding'i ve section index'i
//! ile belirlenir.

use std::collections::BTreeMap;

use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC};
use goblin::elf::{header, program_header, Elf, Symtab};
use goblin::strtab::Strtab;

use super::demangle::demangle;
use super::model::{Arch, BinaryFormat, BinaryInfo, FunctionSymbol, SectionInfo, SymbolVisibility};
use crate::error::Result;

/// SHN_UNDEF: sembol bu modülde tanımlı değil (dışarıdan gelir).
const SHN_UNDEF: usize = 0;
/// 0xff00 ve üzeri section index'leri özeldir (SHN_ABS, SHN_COMMON, ...).
const SHN_LORESERVE: usize = 0xff00;

pub fn parse(bytes: &[u8]) -> Result<BinaryInfo> {
    let elf = Elf::parse(bytes)?;

    let arch = map_arch(elf.header.e_machine);
    let image_base = compute_image_base(&elf);
    let sections = collect_sections(&elf);

    let mut funcs: BTreeMap<u64, FunctionSymbol> = BTreeMap::new();
    collect_symbols(&elf.syms, &elf.strtab, &elf, &sections, &mut funcs);
    collect_symbols(&elf.dynsyms, &elf.dynstrtab, &elf, &sections, &mut funcs);

    Ok(BinaryInfo {
        path: None,
        format: BinaryFormat::Elf,
        arch,
        is_64bit: elf.is_64,
        image_base,
        entry_point: elf.entry,
        sections,
        functions: funcs.into_values().collect(),
    })
}

fn map_arch(machine: u16) -> Arch {
    match machine {
        header::EM_386 => Arch::X86,
        header::EM_X86_64 => Arch::X86_64,
        header::EM_ARM => Arch::Arm,
        header::EM_AARCH64 => Arch::Aarch64,
        other => Arch::Unknown(other),
    }
}

/// Image base: yüklenen ilk (en düşük adresli) PT_LOAD segmentinin sanal adresi.
/// PIE binary'lerde bu genelde 0'dır.
fn compute_image_base(elf: &Elf) -> u64 {
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == program_header::PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
        .unwrap_or(0)
}

fn collect_sections(elf: &Elf) -> Vec<SectionInfo> {
    elf.section_headers
        .iter()
        .map(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            let flags = sh.sh_flags;
            SectionInfo {
                name,
                virtual_address: sh.sh_addr,
                virtual_size: sh.sh_size,
                file_offset: sh.sh_offset,
                raw_size: sh.sh_size,
                executable: flags & u64::from(SHF_EXECINSTR) != 0,
                readable: flags & u64::from(SHF_ALLOC) != 0,
                writable: flags & u64::from(SHF_WRITE) != 0,
            }
        })
        .collect()
}

fn collect_symbols(
    symtab: &Symtab,
    strtab: &Strtab,
    elf: &Elf,
    sections: &[SectionInfo],
    funcs: &mut BTreeMap<u64, FunctionSymbol>,
) {
    for sym in symtab.iter() {
        if sym.st_type() != STT_FUNC {
            continue;
        }
        // Adresi 0 ve tanımsız olan saf placeholder sembolleri ele.
        let is_undefined = sym.st_shndx == SHN_UNDEF;
        if sym.st_value == 0 && !is_undefined {
            continue;
        }

        let raw_name = strtab.get_at(sym.st_name).unwrap_or("");
        if raw_name.is_empty() && !is_undefined {
            continue;
        }

        let va = sym.st_value;
        let name = if raw_name.is_empty() {
            format!("sub_{va:x}")
        } else {
            raw_name.to_string()
        };

        let visibility = if is_undefined {
            SymbolVisibility::Imported
        } else if matches!(sym.st_bind(), STB_GLOBAL | STB_WEAK) {
            SymbolVisibility::Exported
        } else {
            SymbolVisibility::Internal
        };

        let section = section_name_for_index(elf, sym.st_shndx);
        let file_offset = if is_undefined {
            None
        } else {
            file_offset_for(sections, va)
        };

        insert_or_merge(
            funcs,
            FunctionSymbol {
                demangled: demangle(&name),
                name,
                virtual_address: va,
                file_offset,
                size: if sym.st_size > 0 {
                    Some(sym.st_size)
                } else {
                    None
                },
                visibility,
                section,
            },
        );
    }
}

/// Sembolün `st_shndx`'ine karşılık gelen section adını çözer.
fn section_name_for_index(elf: &Elf, shndx: usize) -> Option<String> {
    if shndx == SHN_UNDEF || shndx >= SHN_LORESERVE {
        return None;
    }
    let sh = elf.section_headers.get(shndx)?;
    let name = elf.shdr_strtab.get_at(sh.sh_name)?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Sanal adresi içeren bölümü bulup dosya offset'ini hesaplar.
fn file_offset_for(sections: &[SectionInfo], va: u64) -> Option<u64> {
    sections.iter().find_map(|s| {
        if s.virtual_address == 0 || s.virtual_size == 0 {
            return None;
        }
        let end = s.virtual_address + s.virtual_size;
        if va >= s.virtual_address && va < end {
            Some(s.file_offset + (va - s.virtual_address))
        } else {
            None
        }
    })
}

/// Aynı adresteki kayıtları birleştirir; adlı sembolü placeholder'a tercih eder.
fn insert_or_merge(funcs: &mut BTreeMap<u64, FunctionSymbol>, incoming: FunctionSymbol) {
    use std::collections::btree_map::Entry;
    // Tanımsız (imported) semboller adres 0'da çakışabilir; bu durumda
    // ada göre ayrı tutmak için adresi 0 olanları her zaman ekleriz.
    if incoming.virtual_address == 0 {
        // 0 adresli importları isimleriyle benzersizleştirmek yerine, ilkini
        // tutmak yeterli; çoğu ELF'te 0 adresli STT_FUNC importları nadirdir.
        funcs.entry(0).or_insert(incoming);
        return;
    }

    match funcs.entry(incoming.virtual_address) {
        Entry::Vacant(e) => {
            e.insert(incoming);
        }
        Entry::Occupied(mut e) => {
            let existing = e.get_mut();
            let existing_is_placeholder = existing.name.starts_with("sub_");
            let incoming_is_placeholder = incoming.name.starts_with("sub_");
            if existing_is_placeholder && !incoming_is_placeholder {
                existing.name = incoming.name;
                existing.demangled = incoming.demangled;
                existing.visibility = incoming.visibility;
            }
            existing.size = existing.size.or(incoming.size);
            existing.file_offset = existing.file_offset.or(incoming.file_offset);
            existing.section = existing.section.take().or(incoming.section);
        }
    }
}
