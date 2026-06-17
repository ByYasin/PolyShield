//! ELF64 (little-endian) cerrahisi: yeni section ekleme.
//!
//! Klasik "append section" tekniği: veri, yeni `.shstrtab` ve yeni section
//! header tablosu dosyanın **sonuna** eklenir; ELF header'daki `e_shoff`/`e_shnum`
//! güncellenir. Mevcut içerik kaymaz. Eklenen section yüklenebilir (PT_LOAD)
//! değildir — `.pshld` meta verisi için yeterlidir (loader dosya offset'inden okur).

use crate::error::{PackError, Result};

// ELF64 header offsetleri.
const E_SHOFF: usize = 40;
const E_SHENTSIZE: usize = 58;
const E_SHNUM: usize = 60;
const E_SHSTRNDX: usize = 62;
const SHENT: usize = 64; // section header entry boyutu (ELF64)

// Section header alan offsetleri (entry içinde).
const SH_OFFSET: usize = 24;
const SH_SIZE: usize = 32;

const SHT_PROGBITS: u32 = 1;

fn align8(x: usize) -> usize {
    (x + 7) & !7
}
fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
fn wr_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn wr_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn wr_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Bir ELF64-LE dosyasına yeni bir section ekler.
pub fn add_section(input: &[u8], name: &str, data: &[u8]) -> Result<Vec<u8>> {
    if input.len() < 64 || input[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(PackError::NotElf64);
    }
    if input[4] != 2 || input[5] != 1 {
        return Err(PackError::NotElf64); // class != ELF64 ya da data != LE
    }

    let e_shoff = rd_u64(input, E_SHOFF) as usize;
    let e_shentsize = rd_u16(input, E_SHENTSIZE) as usize;
    let e_shnum = rd_u16(input, E_SHNUM) as usize;
    let e_shstrndx = rd_u16(input, E_SHSTRNDX) as usize;

    if e_shentsize != SHENT || e_shoff == 0 || e_shoff + e_shnum * SHENT > input.len() {
        return Err(PackError::BadElf);
    }
    if e_shstrndx >= e_shnum {
        return Err(PackError::BadElf);
    }

    let mut out = input.to_vec();

    // Mevcut .shstrtab içeriğini oku.
    let shstr_hdr = e_shoff + e_shstrndx * SHENT;
    let shstr_off = rd_u64(&out, shstr_hdr + SH_OFFSET) as usize;
    let shstr_size = rd_u64(&out, shstr_hdr + SH_SIZE) as usize;
    if shstr_off + shstr_size > out.len() {
        return Err(PackError::BadElf);
    }

    let mut new_shstr = out[shstr_off..shstr_off + shstr_size].to_vec();
    let name_index = new_shstr.len() as u32;
    new_shstr.extend_from_slice(name.as_bytes());
    new_shstr.push(0);

    // Mevcut section header tablosunu (büyütmeden önce) kopyala.
    let mut table = out[e_shoff..e_shoff + e_shnum * SHENT].to_vec();

    // 1) Payload'ı dosya sonuna ekle.
    let payload_off = align8(out.len());
    out.resize(payload_off, 0);
    out.extend_from_slice(data);

    // 2) Yeni .shstrtab'ı ekle.
    let new_shstr_off = align8(out.len());
    out.resize(new_shstr_off, 0);
    out.extend_from_slice(&new_shstr);

    // 3) Yeni section header tablosunu inşa et.
    //    .shstrtab girişini yeni konuma yönlendir.
    wr_u64(
        &mut table,
        e_shstrndx * SHENT + SH_OFFSET,
        new_shstr_off as u64,
    );
    wr_u64(
        &mut table,
        e_shstrndx * SHENT + SH_SIZE,
        new_shstr.len() as u64,
    );

    // Yeni section header'ı ekle.
    let mut nh = [0u8; SHENT];
    wr_u32(&mut nh, 0, name_index); // sh_name
    wr_u32(&mut nh, 4, SHT_PROGBITS); // sh_type
    wr_u64(&mut nh, 8, 0); // sh_flags (alloc değil)
    wr_u64(&mut nh, 16, 0); // sh_addr
    wr_u64(&mut nh, SH_OFFSET, payload_off as u64);
    wr_u64(&mut nh, SH_SIZE, data.len() as u64);
    wr_u32(&mut nh, 40, 0); // sh_link
    wr_u32(&mut nh, 44, 0); // sh_info
    wr_u64(&mut nh, 48, 1); // sh_addralign
    wr_u64(&mut nh, 56, 0); // sh_entsize
    table.extend_from_slice(&nh);

    let new_shoff = align8(out.len());
    out.resize(new_shoff, 0);
    out.extend_from_slice(&table);

    // 4) ELF header'ı güncelle.
    wr_u64(&mut out, E_SHOFF, new_shoff as u64);
    wr_u16(&mut out, E_SHNUM, (e_shnum + 1) as u16);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ama geçerli bir ELF64-LE (null + .shstrtab section) kurar.
    fn minimal_elf() -> Vec<u8> {
        let shstr = b"\0.shstrtab\0"; // idx 1 = ".shstrtab"
        let ehdr_size = 64usize;
        let shstr_off = ehdr_size;
        let shoff = align8(shstr_off + shstr.len());

        let mut f = vec![0u8; shoff + 2 * SHENT];
        // e_ident
        f[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        f[4] = 2; // ELF64
        f[5] = 1; // LE
        f[6] = 1; // version
        wr_u16(&mut f, 16, 3); // e_type = DYN
        wr_u16(&mut f, 18, 0x3e); // e_machine = x86-64
        wr_u32(&mut f, 20, 1); // e_version
        wr_u64(&mut f, E_SHOFF, shoff as u64);
        wr_u16(&mut f, 52, 64); // e_ehsize
        wr_u16(&mut f, E_SHENTSIZE, 64);
        wr_u16(&mut f, E_SHNUM, 2);
        wr_u16(&mut f, E_SHSTRNDX, 1);
        // shstrtab içeriği
        f[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
        // shdr[1] = .shstrtab
        let h1 = shoff + SHENT;
        wr_u32(&mut f, h1, 1); // sh_name = ".shstrtab"
        wr_u32(&mut f, h1 + 4, 3); // sh_type = STRTAB
        wr_u64(&mut f, h1 + SH_OFFSET, shstr_off as u64);
        wr_u64(&mut f, h1 + SH_SIZE, shstr.len() as u64);
        wr_u64(&mut f, h1 + 48, 1); // addralign
        f
    }

    #[test]
    fn appends_named_section() {
        let elf = minimal_elf();
        let payload = b"POLYSHIELD-TEST-PAYLOAD";
        let out = add_section(&elf, ".pshld", payload).expect("section eklenmeli");

        // goblin ile geçerli ELF olarak parse edilmeli ve .pshld görünmeli.
        let parsed = goblin::elf::Elf::parse(&out).expect("geçerli ELF olmalı");
        let mut found = None;
        for sh in &parsed.section_headers {
            if let Some(n) = parsed.shdr_strtab.get_at(sh.sh_name) {
                if n == ".pshld" {
                    found = Some(sh.clone());
                }
            }
        }
        let sh = found.expect(".pshld section bulunmalı");
        let off = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        assert_eq!(&out[off..off + size], payload, "payload korunmalı");
    }
}
