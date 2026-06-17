//! PolyShield VM yorumlayıcısı (register tabanlı).
//!
//! Lift edilen IR'ı çalıştırır; öncelikli amacı **doğruluk doğrulamasıdır**:
//! "lift edilmiş kod, orijinal x86 ile aynı sonucu üretiyor mu?" sorusunu
//! cevaplar. Bellek düz (flat) bir tampon olarak modellenir.
//!
//! Bilinçli sadeleştirme: `call`/`ret`, dönüş adresleri için konuk RSP yerine
//! bir host gölge yığını (shadow stack) kullanır; bu, saf hesaplama
//! fonksiyonlarını doğrulamak için yeterlidir.

use crate::error::{Result, VmError};
use crate::isa::{Cond, MemRef, OpSize, VReg, VmInstr, VmOp, VmOperand};

/// Lift edilemeyen (`Native`) ham x86 byte'larını yürüten köprü.
///
/// poly-vm bunu yalnızca bir arayüz olarak tanımlar; somut bir gerçekleştirme
/// (örn. `poly-rt`'deki native trampoline) çağıran tarafça [`VmState`]'e
/// takılır. Böylece poly-vm, platforma özgü/unsafe yürütmeye bağımlı kalmaz.
pub trait NativeHandler {
    /// `bytes`'i çalıştırır ve `state`'in register/flag'lerini günceller.
    fn handle(&mut self, bytes: &[u8], state: &mut VmState) -> Result<()>;
}

/// VM'in çalışma zamanı durumu.
pub struct VmState {
    pub regs: [u64; VReg::COUNT],
    pub zf: bool,
    pub sf: bool,
    pub cf: bool,
    pub of: bool,
    pub pf: bool,
    mem: Vec<u8>,
    mem_base: u64,
    /// Salt-okunur modül bölgeleri (RIP-relative sabit/global okumaları için).
    image: Vec<ImageRegion>,
    /// Native escape'leri yürüten opsiyonel köprü (yoksa escape hata verir).
    native_handler: Option<Box<dyn NativeHandler>>,
}

impl std::fmt::Debug for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmState")
            .field("regs", &self.regs)
            .field("zf", &self.zf)
            .field("sf", &self.sf)
            .field("cf", &self.cf)
            .field("of", &self.of)
            .field("pf", &self.pf)
            .field("mem_base", &self.mem_base)
            .finish_non_exhaustive()
    }
}

/// Yüklü modülün bir bölümünün salt-okunur görüntüsü.
#[derive(Debug, Clone)]
struct ImageRegion {
    va: u64,
    data: Vec<u8>,
}

impl VmState {
    /// `mem_size` byte'lık düz bellekle yeni bir durum. RSP, belleğin üst
    /// kısmına (16 byte pay bırakılarak) ayarlanır.
    pub fn new(mem_base: u64, mem_size: usize) -> Self {
        let mut st = VmState {
            regs: [0; VReg::COUNT],
            zf: false,
            sf: false,
            cf: false,
            of: false,
            pf: false,
            mem: vec![0; mem_size],
            mem_base,
            image: Vec::new(),
            native_handler: None,
        };
        st.regs[VReg::RSP.0 as usize] = mem_base + mem_size as u64 - 16;
        st
    }

    /// Salt-okunur bir modül bölgesi ekler (RIP-relative okumaların çözülmesi için).
    pub fn add_image_region(&mut self, va: u64, data: Vec<u8>) {
        self.image.push(ImageRegion { va, data });
    }

    /// Native escape'leri yürütecek köprüyü takar.
    pub fn set_native_handler(&mut self, handler: Box<dyn NativeHandler>) {
        self.native_handler = Some(handler);
    }

    /// Hesaplama doğrulaması için tipik varsayılan (64 KiB yığın).
    pub fn with_default_stack() -> Self {
        Self::new(0x10_0000, 64 * 1024)
    }

    pub fn reg(&self, r: VReg) -> u64 {
        self.regs[r.0 as usize]
    }

    pub fn set_reg_full(&mut self, r: VReg, v: u64) {
        self.regs[r.0 as usize] = v;
    }
}

/// Çalıştırma sonucu özeti.
#[derive(Debug, Clone, Copy)]
pub struct RunOutcome {
    /// Çalıştırılan komut adımı sayısı.
    pub steps: usize,
    /// `ret`/`vmexit` ile normal sonlanma mı?
    pub halted: bool,
}

/// Tek bir komut çalıştırıldıktan sonraki kontrol akışı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepFlow {
    /// Sıradaki komuta geç (vip + 1).
    Next,
    /// Belirtilen komut indeksine dallan.
    Goto(usize),
    /// Programı durdur (ret/vmexit).
    Halt,
}

/// Tek bir VM komutunu çalıştırır ve sonraki kontrol akışını döndürür.
///
/// `run`'ın ve self-encrypting [`crate::polymorph`] runtime'ının ortak adım
/// motoru — komut semantiği için **tek doğruluk kaynağıdır**. `call_stack`,
/// `call`/`ret` için çağıran tarafından tutulur; `vip` mevcut komutun indeksidir.
pub fn step(
    instr: &VmInstr,
    state: &mut VmState,
    call_stack: &mut Vec<usize>,
    vip: usize,
) -> Result<StepFlow> {
    match instr.op {
        VmOp::Nop => {}
        VmOp::Mov => {
            let v = read(state, src(instr)?, instr.size)?;
            write(state, dst(instr)?, instr.size, v)?;
        }
        VmOp::Lea => {
            let VmOperand::Mem(m) = src(instr)? else {
                return Err(VmError::Interp("lea kaynağı bellek olmalı".into()));
            };
            let addr = effective_addr(state, m);
            write(state, dst(instr)?, instr.size, addr)?;
        }
        // imul r, r/m, imm (3 operand): dst = src * imm.
        VmOp::Imul if instr.operands.len() >= 3 => {
            let b = read(state, &instr.operands[1], instr.size)?;
            let c = read(state, &instr.operands[2], instr.size)?;
            let r = alu(state, VmOp::Imul, b, c, instr.size);
            write(state, &instr.operands[0], instr.size, r)?;
        }
        VmOp::Add | VmOp::Sub | VmOp::And | VmOp::Or | VmOp::Xor | VmOp::Imul => {
            let a = read(state, dst(instr)?, instr.size)?;
            let b = read(state, src(instr)?, instr.size)?;
            let r = alu(state, instr.op, a, b, instr.size);
            write(state, dst(instr)?, instr.size, r)?;
        }
        VmOp::Shl | VmOp::Shr | VmOp::Sar => {
            let a = read(state, dst(instr)?, instr.size)?;
            let b = read(state, src(instr)?, instr.size)? & 0x3f;
            let r = shift(state, instr.op, a, b as u32, instr.size);
            write(state, dst(instr)?, instr.size, r)?;
        }
        VmOp::Neg => {
            let a = read(state, dst(instr)?, instr.size)?;
            let r = alu(state, VmOp::Sub, 0, a, instr.size);
            write(state, dst(instr)?, instr.size, r)?;
        }
        VmOp::Not => {
            let a = read(state, dst(instr)?, instr.size)?;
            write(state, dst(instr)?, instr.size, !a & instr.size.mask())?;
        }
        VmOp::Inc => {
            let a = read(state, dst(instr)?, instr.size)?;
            let r = alu(state, VmOp::Add, a, 1, instr.size);
            write(state, dst(instr)?, instr.size, r)?;
        }
        VmOp::Dec => {
            let a = read(state, dst(instr)?, instr.size)?;
            let r = alu(state, VmOp::Sub, a, 1, instr.size);
            write(state, dst(instr)?, instr.size, r)?;
        }
        VmOp::Cmp => {
            let a = read(state, dst(instr)?, instr.size)?;
            let b = read(state, src(instr)?, instr.size)?;
            alu(state, VmOp::Sub, a, b, instr.size); // sadece flag'leri günceller
        }
        VmOp::Test => {
            let a = read(state, dst(instr)?, instr.size)?;
            let b = read(state, src(instr)?, instr.size)?;
            alu(state, VmOp::And, a, b, instr.size);
        }
        VmOp::Push => {
            let v = read(state, dst(instr)?, instr.size)?;
            push(state, v, instr.size)?;
        }
        VmOp::Pop => {
            let v = pop(state, instr.size)?;
            write(state, dst(instr)?, instr.size, v)?;
        }
        VmOp::Rol | VmOp::Ror => {
            let a = read(state, dst(instr)?, instr.size)?;
            let cnt = (read(state, src(instr)?, instr.size)? as u32) & (instr.size.bits() - 1);
            let r = rotate(state, instr.op, a, cnt, instr.size);
            write(state, dst(instr)?, instr.size, r)?;
        }
        VmOp::Movzx => {
            let ssz = instr.src_size.unwrap_or(instr.size);
            let v = read(state, src(instr)?, ssz)?;
            write(state, dst(instr)?, instr.size, v)?; // zero-extend
        }
        VmOp::Movsx => {
            let ssz = instr.src_size.unwrap_or(instr.size);
            let v = read(state, src(instr)?, ssz)?;
            let sx = sign_extend(v, ssz) as u64;
            write(state, dst(instr)?, instr.size, sx)?;
        }
        VmOp::Cmov => {
            let cond = instr
                .cond
                .ok_or_else(|| VmError::Interp("cmov koşulsuz".into()))?;
            if eval_cond(state, cond) {
                let v = read(state, src(instr)?, instr.size)?;
                write(state, dst(instr)?, instr.size, v)?;
            }
        }
        VmOp::Setcc => {
            let cond = instr
                .cond
                .ok_or_else(|| VmError::Interp("setcc koşulsuz".into()))?;
            let v = u64::from(eval_cond(state, cond));
            write(state, dst(instr)?, OpSize::Byte, v)?;
        }
        VmOp::Bt | VmOp::Bts | VmOp::Btr | VmOp::Btc => {
            let a = read(state, dst(instr)?, instr.size)?;
            let pos = (read(state, src(instr)?, instr.size)? as u32) & (instr.size.bits() - 1);
            state.cf = (a >> pos) & 1 != 0;
            if instr.op != VmOp::Bt {
                let bit = 1u64 << pos;
                let r = match instr.op {
                    VmOp::Bts => a | bit,
                    VmOp::Btr => a & !bit,
                    VmOp::Btc => a ^ bit,
                    _ => a,
                } & instr.size.mask();
                write(state, dst(instr)?, instr.size, r)?;
            }
        }
        VmOp::Xchg => {
            let a = read(state, dst(instr)?, instr.size)?;
            let b = read(state, src(instr)?, instr.size)?;
            write(state, dst(instr)?, instr.size, b)?;
            write(state, src(instr)?, instr.size, a)?;
        }
        VmOp::Bswap => {
            let a = read(state, dst(instr)?, instr.size)?;
            let r = match instr.size {
                OpSize::Qword => a.swap_bytes(),
                OpSize::Dword => (a as u32).swap_bytes() as u64,
                OpSize::Word => (a as u16).swap_bytes() as u64,
                OpSize::Byte => a,
            };
            write(state, dst(instr)?, instr.size, r)?;
        }
        VmOp::Cqo => {
            // RAX işaret bitine göre RDX'i 0 veya tüm-1 yapar.
            let a = state.reg(VReg::RAX) & instr.size.mask();
            let val = if a & instr.size.sign_bit() != 0 {
                instr.size.mask()
            } else {
                0
            };
            set_reg_sized(state, VReg::RDX, instr.size, val);
        }
        VmOp::Mul => {
            let bits = instr.size.bits();
            let a = (state.reg(VReg::RAX) & instr.size.mask()) as u128;
            let b = read(state, dst(instr)?, instr.size)? as u128;
            let full = a * b;
            set_reg_sized(state, VReg::RAX, instr.size, full as u64);
            set_reg_sized(state, VReg::RDX, instr.size, (full >> bits) as u64);
            let hi_nonzero = (full >> bits) != 0;
            state.cf = hi_nonzero;
            state.of = hi_nonzero;
        }
        VmOp::Imul1 => {
            let bits = instr.size.bits();
            let a = sign_extend(state.reg(VReg::RAX) & instr.size.mask(), instr.size) as i128;
            let b = sign_extend(read(state, dst(instr)?, instr.size)?, instr.size) as i128;
            let full = a * b;
            set_reg_sized(state, VReg::RAX, instr.size, full as u64);
            set_reg_sized(state, VReg::RDX, instr.size, (full >> bits) as u64);
        }
        VmOp::Div => {
            let bits = instr.size.bits();
            let hi = (state.reg(VReg::RDX) & instr.size.mask()) as u128;
            let lo = (state.reg(VReg::RAX) & instr.size.mask()) as u128;
            let dividend = (hi << bits) | lo;
            let divisor = (read(state, dst(instr)?, instr.size)? & instr.size.mask()) as u128;
            if divisor == 0 {
                return Err(VmError::Interp("sıfıra bölme (div)".into()));
            }
            let q = dividend / divisor;
            if q > instr.size.mask() as u128 {
                return Err(VmError::Interp("bölme taşması (div)".into()));
            }
            set_reg_sized(state, VReg::RAX, instr.size, q as u64);
            set_reg_sized(state, VReg::RDX, instr.size, (dividend % divisor) as u64);
        }
        VmOp::Idiv => {
            let bits = instr.size.bits();
            let hi = (state.reg(VReg::RDX) & instr.size.mask()) as u128;
            let lo = (state.reg(VReg::RAX) & instr.size.mask()) as u128;
            let raw = (hi << bits) | lo;
            let total = 2 * bits;
            let dividend = if total < 128 {
                ((raw << (128 - total)) as i128) >> (128 - total)
            } else {
                raw as i128
            };
            let divisor = sign_extend(read(state, dst(instr)?, instr.size)?, instr.size) as i128;
            if divisor == 0 {
                return Err(VmError::Interp("sıfıra bölme (idiv)".into()));
            }
            set_reg_sized(state, VReg::RAX, instr.size, (dividend / divisor) as u64);
            set_reg_sized(state, VReg::RDX, instr.size, (dividend % divisor) as u64);
        }
        VmOp::Shld | VmOp::Shrd => {
            let bits = instr.size.bits();
            let mask = instr.size.mask();
            let d = read(state, dst(instr)?, instr.size)?;
            let s = read(state, src(instr)?, instr.size)?;
            let cnt_op = instr
                .operands
                .get(2)
                .ok_or_else(|| VmError::Interp("shld/shrd 3 operand bekler".into()))?;
            let cnt = (read(state, cnt_op, instr.size)? as u32) & (bits - 1);
            if cnt != 0 {
                let (r, cf) = if instr.op == VmOp::Shld {
                    (
                        ((d << cnt) | (s >> (bits - cnt))) & mask,
                        (d >> (bits - cnt)) & 1 != 0,
                    )
                } else {
                    (
                        ((d >> cnt) | (s << (bits - cnt))) & mask,
                        (d >> (cnt - 1)) & 1 != 0,
                    )
                };
                set_zsp(state, r, instr.size);
                state.cf = cf;
                write(state, dst(instr)?, instr.size, r)?;
            }
        }
        VmOp::Xadd => {
            let d = read(state, dst(instr)?, instr.size)?;
            let s = read(state, src(instr)?, instr.size)?;
            let sum = alu(state, VmOp::Add, d, s, instr.size);
            write(state, src(instr)?, instr.size, d)?; // src = eski dst
            write(state, dst(instr)?, instr.size, sum)?; // dst = toplam
        }
        VmOp::Cmpxchg => {
            let acc = state.reg(VReg::RAX) & instr.size.mask();
            let d = read(state, dst(instr)?, instr.size)?;
            alu(state, VmOp::Sub, acc, d, instr.size); // cmp RAX, dst
            if acc == d {
                let s = read(state, src(instr)?, instr.size)?;
                write(state, dst(instr)?, instr.size, s)?;
            } else {
                set_reg_sized(state, VReg::RAX, instr.size, d);
            }
        }
        VmOp::Jmp => return Ok(StepFlow::Goto(branch_target(instr)?)),
        VmOp::Jcc => {
            let cond = instr
                .cond
                .ok_or_else(|| VmError::Interp("jcc koşulsuz".into()))?;
            if eval_cond(state, cond) {
                return Ok(StepFlow::Goto(branch_target(instr)?));
            }
        }
        VmOp::Call => {
            call_stack.push(vip + 1);
            return Ok(StepFlow::Goto(branch_target(instr)?));
        }
        VmOp::Ret => {
            return Ok(match call_stack.pop() {
                Some(ret_vip) => StepFlow::Goto(ret_vip),
                None => StepFlow::Halt,
            })
        }
        VmOp::VmExit => return Ok(StepFlow::Halt),
        VmOp::Native => match state.native_handler.take() {
            Some(mut h) => {
                let result = h.handle(&instr.native_bytes, state);
                state.native_handler = Some(h);
                result?;
            }
            None => {
                return Err(VmError::Interp(format!(
                    "native escape (0x{:x}) yorumlanamaz (handler yok)",
                    instr.orig_addr
                )));
            }
        },
    }
    Ok(StepFlow::Next)
}

/// IR programını verilen başlangıç durumundan çalıştırır.
///
/// `max_steps`, sonsuz döngülere karşı güvenlik sınırıdır.
pub fn run(instrs: &[VmInstr], state: &mut VmState, max_steps: usize) -> Result<RunOutcome> {
    let mut vip: usize = 0;
    let mut call_stack: Vec<usize> = Vec::new();
    let mut steps = 0;

    while vip < instrs.len() {
        if steps >= max_steps {
            return Err(VmError::Interp(format!(
                "adım sınırı aşıldı ({max_steps}) — olası sonsuz döngü"
            )));
        }
        steps += 1;

        match step(&instrs[vip], state, &mut call_stack, vip)? {
            StepFlow::Next => vip += 1,
            StepFlow::Goto(t) => vip = t,
            StepFlow::Halt => {
                return Ok(RunOutcome {
                    steps,
                    halted: true,
                })
            }
        }
    }

    Ok(RunOutcome {
        steps,
        halted: false,
    })
}

// ---- operand erişimi -------------------------------------------------------

fn dst(instr: &VmInstr) -> Result<&VmOperand> {
    instr
        .dst()
        .ok_or_else(|| VmError::Interp(format!("{} hedef operand bekliyor", instr.op.mnemonic())))
}

fn src(instr: &VmInstr) -> Result<&VmOperand> {
    instr
        .src()
        .ok_or_else(|| VmError::Interp(format!("{} kaynak operand bekliyor", instr.op.mnemonic())))
}

fn branch_target(instr: &VmInstr) -> Result<usize> {
    match instr.operands.first() {
        Some(VmOperand::Label(idx)) => Ok(*idx as usize),
        Some(VmOperand::Imm(_)) => Err(VmError::Interp(
            "fonksiyon dışı (harici) dallanma yorumlanamaz".into(),
        )),
        _ => Err(VmError::Interp("dallanma hedefi yok".into())),
    }
}

fn read(state: &VmState, op: &VmOperand, size: OpSize) -> Result<u64> {
    match op {
        VmOperand::Reg(r) => Ok(state.reg(*r) & size.mask()),
        VmOperand::Imm(v) => Ok((*v as u64) & size.mask()),
        VmOperand::Mem(m) => load(state, effective_addr(state, m), size),
        VmOperand::Label(_) => Err(VmError::Interp("label değer olarak okunamaz".into())),
    }
}

fn write(state: &mut VmState, op: &VmOperand, size: OpSize, val: u64) -> Result<()> {
    match op {
        VmOperand::Reg(r) => {
            set_reg_sized(state, *r, size, val);
            Ok(())
        }
        VmOperand::Mem(m) => {
            let addr = effective_addr(state, m);
            store(state, addr, size, val)
        }
        _ => Err(VmError::Interp("bu operanda yazılamaz".into())),
    }
}

/// x86 boyut semantiği: 32-bit yazım üst 32 biti sıfırlar; 8/16-bit korur.
fn set_reg_sized(state: &mut VmState, r: VReg, size: OpSize, val: u64) {
    let idx = r.0 as usize;
    let v = val & size.mask();
    state.regs[idx] = match size {
        OpSize::Qword | OpSize::Dword => v,
        OpSize::Word => (state.regs[idx] & !0xFFFF) | v,
        OpSize::Byte => (state.regs[idx] & !0xFF) | v,
    };
}

fn effective_addr(state: &VmState, m: &MemRef) -> u64 {
    let mut addr = m.disp as u64;
    if let Some(b) = m.base {
        addr = addr.wrapping_add(state.reg(b));
    }
    if let Some(i) = m.index {
        addr = addr.wrapping_add(state.reg(i).wrapping_mul(m.scale as u64));
    }
    addr
}

// ---- bellek ----------------------------------------------------------------

fn mem_index(state: &VmState, addr: u64, size: OpSize) -> Result<usize> {
    let off = addr
        .checked_sub(state.mem_base)
        .ok_or_else(|| VmError::Interp(format!("bellek erişimi aralık dışı: 0x{addr:x}")))?;
    let off = off as usize;
    if off + size.bytes() as usize > state.mem.len() {
        return Err(VmError::Interp(format!(
            "bellek erişimi aralık dışı: 0x{addr:x}"
        )));
    }
    Ok(off)
}

fn load(state: &VmState, addr: u64, size: OpSize) -> Result<u64> {
    let n = size.bytes() as u64;
    // Önce yığın (flat mem).
    if addr >= state.mem_base && addr + n <= state.mem_base + state.mem.len() as u64 {
        let off = (addr - state.mem_base) as usize;
        return Ok(read_le(&state.mem[off..off + n as usize]));
    }
    // Sonra salt-okunur modül bölgeleri (RIP-relative sabitler/globaller).
    for r in &state.image {
        if addr >= r.va && addr + n <= r.va + r.data.len() as u64 {
            let off = (addr - r.va) as usize;
            return Ok(read_le(&r.data[off..off + n as usize]));
        }
    }
    Err(VmError::Interp(format!("okuma aralık dışı: 0x{addr:x}")))
}

fn read_le(bytes: &[u8]) -> u64 {
    let mut val = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        val |= (b as u64) << (8 * i);
    }
    val
}

fn store(state: &mut VmState, addr: u64, size: OpSize, val: u64) -> Result<()> {
    let off = mem_index(state, addr, size)?;
    for i in 0..size.bytes() as usize {
        state.mem[off + i] = (val >> (8 * i)) as u8;
    }
    Ok(())
}

fn push(state: &mut VmState, val: u64, size: OpSize) -> Result<()> {
    let sp = state.reg(VReg::RSP).wrapping_sub(size.bytes() as u64);
    state.set_reg_full(VReg::RSP, sp);
    store(state, sp, size, val)
}

fn pop(state: &mut VmState, size: OpSize) -> Result<u64> {
    let sp = state.reg(VReg::RSP);
    let val = load(state, sp, size)?;
    state.set_reg_full(VReg::RSP, sp.wrapping_add(size.bytes() as u64));
    Ok(val)
}

// ---- ALU & flag'ler --------------------------------------------------------

fn alu(state: &mut VmState, op: VmOp, a: u64, b: u64, size: OpSize) -> u64 {
    let mask = size.mask();
    let (res, cf, of) = match op {
        VmOp::Add => {
            let r = a.wrapping_add(b) & mask;
            let cf = (a & mask)
                .checked_add(b & mask)
                .map(|s| s > mask)
                .unwrap_or(true);
            let of = (((a ^ r) & (b ^ r)) & size.sign_bit()) != 0;
            (r, cf, of)
        }
        VmOp::Sub => {
            let r = a.wrapping_sub(b) & mask;
            let cf = (a & mask) < (b & mask);
            let of = (((a ^ b) & (a ^ r)) & size.sign_bit()) != 0;
            (r, cf, of)
        }
        VmOp::And => ((a & b) & mask, false, false),
        VmOp::Or => ((a | b) & mask, false, false),
        VmOp::Xor => ((a ^ b) & mask, false, false),
        VmOp::Imul => (a.wrapping_mul(b) & mask, false, false),
        _ => (a & mask, false, false),
    };
    set_zsp(state, res, size);
    state.cf = cf;
    state.of = of;
    res
}

fn shift(state: &mut VmState, op: VmOp, a: u64, count: u32, size: OpSize) -> u64 {
    let mask = size.mask();
    if count == 0 {
        return a & mask;
    }
    let res = match op {
        VmOp::Shl => (a << count) & mask,
        VmOp::Shr => (a & mask) >> count,
        VmOp::Sar => {
            let bits = size.bits();
            let signed = sign_extend(a & mask, size);
            ((signed >> count.min(bits - 1)) as u64) & mask
        }
        _ => a & mask,
    };
    set_zsp(state, res, size);
    res
}

/// rol/ror — döndürme; CF'yi sonucun ilgili ucundaki bite ayarlar.
fn rotate(state: &mut VmState, op: VmOp, a: u64, count: u32, size: OpSize) -> u64 {
    let bits = size.bits();
    let mask = size.mask();
    let a = a & mask;
    if count == 0 {
        return a;
    }
    let r = match op {
        VmOp::Rol => ((a << count) | (a >> (bits - count))) & mask,
        VmOp::Ror => ((a >> count) | (a << (bits - count))) & mask,
        _ => a,
    };
    // rol → CF = sonucun LSB'si; ror → CF = sonucun MSB'si.
    state.cf = match op {
        VmOp::Rol => r & 1 != 0,
        VmOp::Ror => r & size.sign_bit() != 0,
        _ => state.cf,
    };
    r
}

/// ZF, SF ve PF bayraklarını sonuca göre ayarlar.
fn set_zsp(state: &mut VmState, res: u64, size: OpSize) {
    state.zf = (res & size.mask()) == 0;
    state.sf = (res & size.sign_bit()) != 0;
    state.pf = (res as u8).count_ones() % 2 == 0;
}

fn sign_extend(val: u64, size: OpSize) -> i64 {
    let shift = 64 - size.bits();
    ((val << shift) as i64) >> shift
}

fn eval_cond(state: &VmState, cond: Cond) -> bool {
    match cond {
        Cond::O => state.of,
        Cond::No => !state.of,
        Cond::B => state.cf,
        Cond::Ae => !state.cf,
        Cond::E => state.zf,
        Cond::Ne => !state.zf,
        Cond::Be => state.cf || state.zf,
        Cond::A => !state.cf && !state.zf,
        Cond::S => state.sf,
        Cond::Ns => !state.sf,
        Cond::P => state.pf,
        Cond::Np => !state.pf,
        Cond::L => state.sf != state.of,
        Cond::Ge => state.sf == state.of,
        Cond::Le => state.zf || (state.sf != state.of),
        Cond::G => !state.zf && (state.sf == state.of),
    }
}
