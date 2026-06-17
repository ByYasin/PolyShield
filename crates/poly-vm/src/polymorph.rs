//! Polimorfik zırhlama motoru (Faz 1.3).
//!
//! Aynı fonksiyonun iki zırhlı çıktısının **birbirine benzememesini** ve statik
//! bir opcode tablosuyla saldırıya direnmesini sağlar. Tek bir *master tohumdan*
//! deterministik olarak dört dönüşüm türetilir:
//!
//! 1. **Opcode permütasyonu** — her VM opcode'u farklı bir byte'a eşlenir.
//! 2. **Register yeniden adlandırma** — sanal register indeksleri permüte edilir
//!    (yığın işaretçisi RSP sabit tutulur; aksi halde push/pop/call/ret bozulur).
//! 3. **Junk enjeksiyonu** — anlamı değiştirmeyen (nötr) komutlar serpiştirilir;
//!    dallanma hedefleri (label) otomatik yeniden bağlanır.
//! 4. **Bytecode şifreleme** — üretilen bytecode bir anahtar akışıyla XOR'lanır.
//!
//! Her şey tohumdan türediği için zırhlı konteyner yalnızca tohumu + şifreli
//! payload'ı taşır; çözücü (runtime) hepsini yeniden kurar.

use serde::{Deserialize, Serialize};

use crate::encoder::{self, OpcodeMap};
use crate::error::Result;
use crate::isa::{MemRef, OpSize, VReg, VmInstr, VmOp, VmOperand};
use crate::rng::SplitMix64;

/// RSP register indeksi — permütasyondan muaf tutulur.
const SP_INDEX: u8 = 4;

/// Master tohumdan türetilen alt tohumlar. Türetme sırası, `armor` ve
/// `recover` arasında **aynı** olmalıdır.
struct Seeds {
    opcode: u64,
    perm: u64,
    junk: u64,
    key: u64,
}

fn derive(seed: u64) -> Seeds {
    let mut r = SplitMix64::new(seed);
    Seeds {
        opcode: r.next_u64(),
        perm: r.next_u64(),
        junk: r.next_u64(),
        key: r.next_u64(),
    }
}

/// Sanal register yeniden adlandırma eşlemesi (RSP sabit).
#[derive(Debug, Clone)]
pub struct RegPerm {
    fwd: [u8; 16],
}

impl RegPerm {
    /// Tohumdan deterministik bir permütasyon üretir.
    pub fn from_seed(seed: u64) -> Self {
        let movable: Vec<u8> = (0u8..16).filter(|&i| i != SP_INDEX).collect();
        let mut shuffled = movable.clone();
        SplitMix64::new(seed).shuffle(&mut shuffled);

        let mut fwd = [0u8; 16];
        fwd[SP_INDEX as usize] = SP_INDEX;
        for (&slot, &val) in movable.iter().zip(shuffled.iter()) {
            fwd[slot as usize] = val;
        }
        RegPerm { fwd }
    }

    /// Orijinal register'ı yeni (yeniden adlandırılmış) register'a eşler.
    pub fn map(&self, r: VReg) -> VReg {
        VReg(self.fwd[r.0 as usize])
    }

    /// Ham ileri eşleme tablosu (denetim/raporlama için).
    pub fn table(&self) -> [u8; 16] {
        self.fwd
    }
}

/// Zırhlı (korunmuş) program konteyneri — kendini-tanımlayan, taşınabilir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmoredProgram {
    pub version: u8,
    /// Master tohum — tüm dönüşümler bundan yeniden türetilir.
    pub seed: u64,
    /// Şifre çözüldükten sonra beklenen VM komutu sayısı.
    pub instr_count: usize,
    /// Şifrelenmiş bytecode.
    pub payload: Vec<u8>,
}

impl ArmoredProgram {
    /// Zırhı çözer: payload'ı deşifre edip VM IR'ına decode eder ve kullanılan
    /// register permütasyonunu döndürür (konuk bağlam dönüşümü için gerekli).
    pub fn recover(&self) -> Result<(Vec<VmInstr>, RegPerm)> {
        let seeds = derive(self.seed);
        let mut data = self.payload.clone();
        xor_keystream(&mut data, seeds.key);
        let map = OpcodeMap::shuffled(seeds.opcode);
        let instrs = encoder::decode(&data, &map)?;
        let perm = RegPerm::from_seed(seeds.perm);
        Ok((instrs, perm))
    }

    /// Şifreli payload boyutu (byte).
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Zırhlama sonucu: konteyner + denetim bilgisi.
#[derive(Debug, Clone)]
pub struct ArmorResult {
    pub armored: ArmoredProgram,
    /// Uygulanan register permütasyonu.
    pub perm: RegPerm,
    /// Dönüştürülmüş IR (permüte + junk eklenmiş) — denetim/disasm için.
    pub instrs: Vec<VmInstr>,
    /// Eklenen junk komutu sayısı.
    pub junk_added: usize,
    /// Orijinal komut sayısı.
    pub original_count: usize,
}

/// Bir VM IR programını verilen tohum ve junk yoğunluğuyla zırhlar.
///
/// `junk_density`, her gerçek komuttan önce junk eklenme olasılığıdır (0–100).
pub fn armor(instrs: &[VmInstr], seed: u64, junk_density: u8) -> ArmorResult {
    let seeds = derive(seed);
    let perm = RegPerm::from_seed(seeds.perm);

    // 1) Register yeniden adlandırma.
    let permuted = permute_program(instrs, &perm);

    // 2) Junk enjeksiyonu (label fixup ile).
    let mut junk_rng = SplitMix64::new(seeds.junk);
    let (transformed, junk_added) = insert_junk(&permuted, &mut junk_rng, junk_density);

    // 3) Opcode permütasyonuyla encode + 4) keystream şifreleme.
    let map = OpcodeMap::shuffled(seeds.opcode);
    let mut payload = encoder::encode(&transformed, &map);
    xor_keystream(&mut payload, seeds.key);

    ArmorResult {
        armored: ArmoredProgram {
            version: 1,
            seed,
            instr_count: transformed.len(),
            payload,
        },
        perm,
        instrs: transformed,
        junk_added,
        original_count: instrs.len(),
    }
}

// ---- register permütasyonu -------------------------------------------------

fn permute_program(instrs: &[VmInstr], perm: &RegPerm) -> Vec<VmInstr> {
    instrs
        .iter()
        .map(|instr| {
            let mut new = instr.clone();
            for op in new.operands.iter_mut() {
                *op = permute_operand(*op, perm);
            }
            new
        })
        .collect()
}

fn permute_operand(op: VmOperand, perm: &RegPerm) -> VmOperand {
    match op {
        VmOperand::Reg(r) => VmOperand::Reg(perm.map(r)),
        VmOperand::Mem(m) => VmOperand::Mem(MemRef {
            base: m.base.map(|r| perm.map(r)),
            index: m.index.map(|r| perm.map(r)),
            scale: m.scale,
            disp: m.disp,
        }),
        other => other,
    }
}

// ---- junk enjeksiyonu ------------------------------------------------------

/// Programa nötr junk komutları serpiştirir ve label hedeflerini yeniden bağlar.
fn insert_junk(instrs: &[VmInstr], rng: &mut SplitMix64, density: u8) -> (Vec<VmInstr>, usize) {
    let scratch = free_scratch_register(instrs);
    let density = density.min(100) as usize;

    let mut out: Vec<VmInstr> = Vec::with_capacity(instrs.len());
    // orijinal indeks -> yeni indeks eşlemesi (gerçek komutun yeni konumu).
    let mut remap = vec![0u32; instrs.len()];
    let mut added = 0usize;

    for (i, instr) in instrs.iter().enumerate() {
        if density > 0 && rng.below(100) < density {
            for j in junk_sequence(rng, scratch) {
                out.push(j);
                added += 1;
            }
        }
        remap[i] = out.len() as u32;
        out.push(instr.clone());
    }

    // Tüm label hedeflerini yeni indekslere taşı.
    for instr in out.iter_mut() {
        for op in instr.operands.iter_mut() {
            if let VmOperand::Label(old) = op {
                *op = VmOperand::Label(remap[*old as usize]);
            }
        }
    }

    (out, added)
}

/// Programda hiç kullanılmayan bir register bulur (junk için güvenli scratch).
fn free_scratch_register(instrs: &[VmInstr]) -> Option<VReg> {
    let mut used = [false; 16];
    for instr in instrs {
        for op in &instr.operands {
            match op {
                VmOperand::Reg(r) => used[r.0 as usize] = true,
                VmOperand::Mem(m) => {
                    if let Some(b) = m.base {
                        used[b.0 as usize] = true;
                    }
                    if let Some(i) = m.index {
                        used[i.0 as usize] = true;
                    }
                }
                _ => {}
            }
        }
    }
    (0u8..16)
        .find(|&i| i != SP_INDEX && !used[i as usize])
        .map(VReg)
}

/// Nötr junk dizisi üretir: bayrakları ve belleği **etkilemez**, gözlemlenebilir
/// durumu değiştirmez. (`nop`, veya kullanılmayan scratch register'a `mov`.)
fn junk_sequence(rng: &mut SplitMix64, scratch: Option<VReg>) -> Vec<VmInstr> {
    match rng.below(3) {
        0 => vec![VmInstr::new(VmOp::Nop, OpSize::Qword)],
        1 => vec![
            VmInstr::new(VmOp::Nop, OpSize::Qword),
            VmInstr::new(VmOp::Nop, OpSize::Qword),
        ],
        _ => match scratch {
            // Kullanılmayan register'a yazmak tamamen nötrdür (mov bayrak set etmez).
            Some(s) => vec![VmInstr::new(VmOp::Mov, OpSize::Qword)
                .with_operands([VmOperand::Reg(s), VmOperand::Imm(rng.next_u64() as i64)])],
            None => vec![VmInstr::new(VmOp::Nop, OpSize::Qword)],
        },
    }
}

// ---- keystream şifreleme ---------------------------------------------------

/// Veriyi tohumdan türeyen anahtar akışıyla XOR'lar (simetrik).
fn xor_keystream(data: &mut [u8], seed: u64) {
    let mut r = SplitMix64::new(seed);
    for b in data.iter_mut() {
        *b ^= r.next_u8();
    }
}
