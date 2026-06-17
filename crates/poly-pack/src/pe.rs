//! PE (PE32+) cerrahisi: yeni section ekleme ve kod bölgesi mühürleme.
//!
//! Yalnızca dosyanın **sonuna** veri ekler ve başlıkları günceller; mevcut
//! section'ların yeri değişmez (relocation gerekmez). Bu, repacking'in güvenli
//! ve doğrulanabilir bir alt kümesidir.

use goblin::pe::PE;

use crate::error::{PackError, Result};

// PE32+ optional header alan offsetleri (opt header başlangıcına göre).
const OPT_SECTION_ALIGNMENT: usize = 32;
const OPT_FILE_ALIGNMENT: usize = 36;
const OPT_SIZE_OF_IMAGE: usize = 56;
const OPT_CHECKSUM: usize = 64;
const PE32PLUS_MAGIC: u16 = 0x20b;

const SECTION_HEADER_SIZE: usize = 40;
// IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
const SECTION_CHARACTERISTICS: u32 = 0x4000_0040;

fn align_up(x: u64, a: u64) -> u64 {
    if a == 0 {
        x
    } else {
        x.div_ceil(a) * a
    }
}

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Bir PE dosyasına yeni bir section ekler ve güncellenmiş baytları döndürür.
///
/// `name` 8 byte'a kırpılır. `data` ham olarak gömülür (file alignment'a
/// yuvarlanarak). Header güncellemeleri: NumberOfSections, SizeOfImage, yeni
/// section header'ı; CheckSum sıfırlanır (kullanıcı modu yükleyici için yeterli).
pub fn add_section(input: &[u8], name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let pe = PE::parse(input)?;
    let opt = pe
        .header
        .optional_header
        .ok_or(PackError::NoOptionalHeader)?;

    let e_lfanew = pe.header.dos_header.pe_pointer as usize;
    let coff_off = e_lfanew + 4;
    let num_sections = pe.header.coff_header.number_of_sections as usize;
    let size_opt = pe.header.coff_header.size_of_optional_header as usize;
    let opt_off = coff_off + 20;

    let magic = opt.standard_fields.magic;
    if magic != PE32PLUS_MAGIC {
        return Err(PackError::NotPe64(magic));
    }

    let sect_align = opt.windows_fields.section_alignment as u64;
    let file_align = opt.windows_fields.file_alignment as u64;
    let size_of_headers = opt.windows_fields.size_of_headers as usize;

    // Yeni section header için başlık alanında yer var mı?
    let sec_table_off = opt_off + size_opt;
    let new_hdr_off = sec_table_off + num_sections * SECTION_HEADER_SIZE;
    if new_hdr_off + SECTION_HEADER_SIZE > size_of_headers {
        return Err(PackError::NoHeaderRoom);
    }

    // Yeni section'ın sanal adresi: en yüksek section sonundan sonra, hizalı.
    let last_end = pe
        .sections
        .iter()
        .map(|s| s.virtual_address as u64 + s.virtual_size as u64)
        .max()
        .unwrap_or(size_of_headers as u64);
    let new_va = align_up(last_end, sect_align);
    let new_vsize = data.len() as u64;

    // Ham veri dosyanın sonuna (file alignment'a hizalı) eklenir.
    let mut out = input.to_vec();
    let new_raw_ptr = align_up(out.len() as u64, file_align);
    out.resize(new_raw_ptr as usize, 0); // hizalama boşluğunu doldur
    out.extend_from_slice(data);
    let new_raw_size = align_up(new_vsize, file_align);
    out.resize((new_raw_ptr + new_raw_size) as usize, 0); // section sonunu doldur

    // Yeni section header'ını yaz.
    let mut name_bytes = [0u8; 8];
    let nb = name.as_bytes();
    let n = nb.len().min(8);
    name_bytes[..n].copy_from_slice(&nb[..n]);
    out[new_hdr_off..new_hdr_off + 8].copy_from_slice(&name_bytes);
    w32(&mut out, new_hdr_off + 8, new_vsize as u32); // VirtualSize
    w32(&mut out, new_hdr_off + 12, new_va as u32); // VirtualAddress
    w32(&mut out, new_hdr_off + 16, new_raw_size as u32); // SizeOfRawData
    w32(&mut out, new_hdr_off + 20, new_raw_ptr as u32); // PointerToRawData
    w32(&mut out, new_hdr_off + 24, 0); // PointerToRelocations
    w32(&mut out, new_hdr_off + 28, 0); // PointerToLinenumbers
    w16(&mut out, new_hdr_off + 32, 0); // NumberOfRelocations
    w16(&mut out, new_hdr_off + 34, 0); // NumberOfLinenumbers
    w32(&mut out, new_hdr_off + 36, SECTION_CHARACTERISTICS);

    // Header alanlarını güncelle.
    w16(&mut out, coff_off + 2, (num_sections + 1) as u16); // NumberOfSections
    let new_size_of_image = align_up(new_va + new_vsize, sect_align) as u32;
    w32(&mut out, opt_off + OPT_SIZE_OF_IMAGE, new_size_of_image);
    w32(&mut out, opt_off + OPT_CHECKSUM, 0); // CheckSum (kullanıcı DLL için 0 yeterli)

    // (SectionAlignment/FileAlignment değişmedi — sadece okundu.)
    let _ = (OPT_SECTION_ALIGNMENT, OPT_FILE_ALIGNMENT);

    Ok(out)
}

/// Bir dosya offset aralığını sabit bir byte ile üzerine yazar (kod mühürleme).
/// Orijinal x86 kodunu 0xCC (int3) ile silmek için kullanılır.
pub fn seal_range(buf: &mut [u8], file_offset: usize, len: usize, fill: u8) -> Result<()> {
    let end = file_offset
        .checked_add(len)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| PackError::BadContainer("mühürleme aralığı dosya dışında".into()))?;
    for b in &mut buf[file_offset..end] {
        *b = fill;
    }
    Ok(())
}
