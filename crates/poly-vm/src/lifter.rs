//! x86-64 makine kodunu PolyShield VM IR'ına (`VmInstr`) çeviren lifter.
//!
//! `iced-x86` ile fonksiyonun byte'ları decode edilir; her x86 komutu uygun VM
//! komutuna eşlenir. Eşlenemeyen komutlar **kaybedilmez**: ham byte'larıyla
//! birlikte `VmOp::Native` olarak saklanır (gerçek virtualizer'lardaki
//! "native escape"). Dallanma hedefleri ikinci geçişte program içi komut
//! indeksine (vip) çözülür.

use std::collections::HashMap;

use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

use crate::isa::{Cond, MemRef, OpSize, VReg, VmInstr, VmOp, VmOperand};

/// Lift sonucu: VM komutları + istatistikler.
#[derive(Debug, Clone)]
pub struct LiftResult {
    pub instrs: Vec<VmInstr>,
    /// Lift edilebilen x86 komutu sayısı.
    pub lifted: usize,
    /// Native escape'e düşen komut sayısı.
    pub native: usize,
}

impl LiftResult {
    /// Lift edilen komutların toplam komuta oranı (1.0 = tamamı sanallaştırıldı).
    pub fn coverage(&self) -> f64 {
        let total = self.lifted + self.native;
        if total == 0 {
            0.0
        } else {
            self.lifted as f64 / total as f64
        }
    }
}

/// Verilen x86-64 byte dizisini (bir fonksiyonun gövdesi) VM IR'ına çevirir.
///
/// `base` parametresi, byte'ların başlangıcına karşılık gelen sanal adrestir;
/// dallanma hedeflerinin doğru çözülmesi için gereklidir.
pub fn lift(code: &[u8], base: u64) -> LiftResult {
    let mut decoder = Decoder::with_ip(64, code, base, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    let mut instrs: Vec<VmInstr> = Vec::new();
    // x86 adresi -> VM komut indeksi eşlemesi (dallanma çözümü için).
    let mut addr_to_idx: HashMap<u64, u32> = HashMap::new();
    // (vm_idx, mutlak_hedef) — ikinci geçişte çözülecek dallanmalar.
    let mut pending_branches: Vec<(usize, u64)> = Vec::new();

    let mut lifted = 0usize;
    let mut native = 0usize;

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        let addr = instr.ip();
        let vm_idx = instrs.len() as u32;
        addr_to_idx.insert(addr, vm_idx);

        match lift_one(&instr) {
            Lifted::Instr(mut vi) => {
                vi.orig_addr = addr;
                instrs.push(vi);
                lifted += 1;
            }
            Lifted::Branch(mut vi, target) => {
                vi.orig_addr = addr;
                pending_branches.push((instrs.len(), target));
                instrs.push(vi);
                lifted += 1;
            }
            Lifted::Unsupported => {
                let off = (addr - base) as usize;
                let end = off + instr.len();
                let bytes = code.get(off..end).unwrap_or(&[]).to_vec();
                let mut vi = VmInstr::new(VmOp::Native, OpSize::Qword);
                vi.native_bytes = bytes;
                vi.orig_addr = addr;
                instrs.push(vi);
                native += 1;
            }
        }
    }

    // İkinci geçiş: dallanma hedeflerini vip indeksine çöz.
    for (idx, target) in pending_branches {
        let operand = match addr_to_idx.get(&target) {
            Some(&label) => VmOperand::Label(label),
            // Fonksiyon dışına dallanma: mutlak adresi koru (harici hedef).
            None => VmOperand::Imm(target as i64),
        };
        // Dallanma hedefi daima son (tek) operand olarak tutulur.
        instrs[idx].operands = vec![operand];
    }

    LiftResult {
        instrs,
        lifted,
        native,
    }
}

/// Tek bir x86 komutunu lift etmenin olası sonuçları.
enum Lifted {
    Instr(VmInstr),
    /// Dallanma komutu + mutlak hedef adres (sonradan çözülür).
    Branch(VmInstr, u64),
    Unsupported,
}

fn lift_one(instr: &Instruction) -> Lifted {
    // Önce kontrol akışı (dallanma/çağrı/dönüş).
    match instr.flow_control() {
        FlowControl::ConditionalBranch => {
            let Some(cond) = map_cond(instr.condition_code()) else {
                return Lifted::Unsupported;
            };
            let target = instr.near_branch_target();
            if target == 0 && !is_near_branch(instr) {
                return Lifted::Unsupported;
            }
            let vi = VmInstr::new(VmOp::Jcc, OpSize::Qword).with_cond(cond);
            return Lifted::Branch(vi, target);
        }
        FlowControl::UnconditionalBranch => {
            if !is_near_branch(instr) {
                return Lifted::Unsupported; // dolaylı jmp (reg/mem)
            }
            let target = instr.near_branch_target();
            return Lifted::Branch(VmInstr::new(VmOp::Jmp, OpSize::Qword), target);
        }
        FlowControl::Call => {
            if !is_near_branch(instr) {
                return Lifted::Unsupported; // dolaylı call
            }
            let target = instr.near_branch_target();
            return Lifted::Branch(VmInstr::new(VmOp::Call, OpSize::Qword), target);
        }
        FlowControl::Return => {
            return Lifted::Instr(VmInstr::new(VmOp::Ret, OpSize::Qword));
        }
        _ => {}
    }

    // Koşullu taşıma / setcc (kontrol akışı değil ama koşula bağlı).
    let cc = instr.condition_code();
    if cc != ConditionCode::None {
        if let Some(cond) = map_cond(cc) {
            match instr.op_count() {
                1 => {
                    // setcc r/m8
                    let Some(d) = lift_operand(instr, 0) else {
                        return Lifted::Unsupported;
                    };
                    return Lifted::Instr(
                        VmInstr::new(VmOp::Setcc, OpSize::Byte)
                            .with_operands([d])
                            .with_cond(cond),
                    );
                }
                2 => {
                    // cmovcc r, r/m
                    let (Some(d), Some(s)) = (lift_operand(instr, 0), lift_operand(instr, 1))
                    else {
                        return Lifted::Unsupported;
                    };
                    return Lifted::Instr(
                        VmInstr::new(VmOp::Cmov, operation_size(instr))
                            .with_operands([d, s])
                            .with_cond(cond),
                    );
                }
                _ => return Lifted::Unsupported,
            }
        }
    }

    // Genişletme taşımaları (kaynak ve hedef boyutları farklı).
    match instr.mnemonic() {
        Mnemonic::Movzx => return lift_ext(instr, VmOp::Movzx),
        Mnemonic::Movsx | Mnemonic::Movsxd => return lift_ext(instr, VmOp::Movsx),
        Mnemonic::Cbw => return acc_sext(OpSize::Word, OpSize::Byte), // al → ax
        Mnemonic::Cwde => return acc_sext(OpSize::Dword, OpSize::Word), // ax → eax
        Mnemonic::Cdqe => return acc_sext(OpSize::Qword, OpSize::Dword), // eax → rax
        // İşaret yayma (cqo/cdq/cwd) — operandsız, RAX işaretini RDX'e koyar.
        Mnemonic::Cqo => return Lifted::Instr(VmInstr::new(VmOp::Cqo, OpSize::Qword)),
        Mnemonic::Cdq => return Lifted::Instr(VmInstr::new(VmOp::Cqo, OpSize::Dword)),
        Mnemonic::Cwd => return Lifted::Instr(VmInstr::new(VmOp::Cqo, OpSize::Word)),
        _ => {}
    }

    // Tek-operandlı mul/imul/div/idiv (örtük RAX/RDX).
    if matches!(
        instr.mnemonic(),
        Mnemonic::Mul | Mnemonic::Div | Mnemonic::Idiv
    ) || (instr.mnemonic() == Mnemonic::Imul && instr.op_count() == 1)
    {
        let op = match instr.mnemonic() {
            Mnemonic::Mul => VmOp::Mul,
            Mnemonic::Imul => VmOp::Imul1,
            Mnemonic::Div => VmOp::Div,
            Mnemonic::Idiv => VmOp::Idiv,
            _ => unreachable!(),
        };
        let Some(s) = lift_operand(instr, 0) else {
            return Lifted::Unsupported;
        };
        return Lifted::Instr(VmInstr::new(op, operand_size_at(instr, 0)).with_operands([s]));
    }

    // Veri işleme komutları — mnemonic'e göre eşle.
    let op = match instr.mnemonic() {
        Mnemonic::Mov => VmOp::Mov,
        Mnemonic::Lea => VmOp::Lea,
        Mnemonic::Add => VmOp::Add,
        Mnemonic::Sub => VmOp::Sub,
        Mnemonic::And => VmOp::And,
        Mnemonic::Or => VmOp::Or,
        Mnemonic::Xor => VmOp::Xor,
        Mnemonic::Shl => VmOp::Shl,
        Mnemonic::Shr => VmOp::Shr,
        Mnemonic::Sar => VmOp::Sar,
        Mnemonic::Imul => VmOp::Imul,
        Mnemonic::Neg => VmOp::Neg,
        Mnemonic::Not => VmOp::Not,
        Mnemonic::Inc => VmOp::Inc,
        Mnemonic::Dec => VmOp::Dec,
        Mnemonic::Cmp => VmOp::Cmp,
        Mnemonic::Test => VmOp::Test,
        Mnemonic::Push => VmOp::Push,
        Mnemonic::Pop => VmOp::Pop,
        Mnemonic::Rol => VmOp::Rol,
        Mnemonic::Ror => VmOp::Ror,
        Mnemonic::Bt => VmOp::Bt,
        Mnemonic::Bts => VmOp::Bts,
        Mnemonic::Btr => VmOp::Btr,
        Mnemonic::Btc => VmOp::Btc,
        Mnemonic::Xchg => VmOp::Xchg,
        Mnemonic::Bswap => VmOp::Bswap,
        Mnemonic::Shld => VmOp::Shld,
        Mnemonic::Shrd => VmOp::Shrd,
        Mnemonic::Xadd => VmOp::Xadd,
        Mnemonic::Cmpxchg => VmOp::Cmpxchg,
        Mnemonic::Nop => return Lifted::Instr(VmInstr::new(VmOp::Nop, OpSize::Qword)),
        _ => return Lifted::Unsupported,
    };

    // Operand boyutu ve operandları çöz.
    let size = operation_size(instr);
    let mut operands = Vec::with_capacity(instr.op_count() as usize);
    for i in 0..instr.op_count() {
        match lift_operand(instr, i) {
            Some(o) => operands.push(o),
            None => return Lifted::Unsupported,
        }
    }

    Lifted::Instr(VmInstr {
        op,
        size,
        operands,
        cond: None,
        src_size: None,
        native_bytes: Vec::new(),
        orig_addr: 0,
    })
}

/// movzx / movsx: hedef ve kaynak boyutları farklı olabilir.
fn lift_ext(instr: &Instruction, op: VmOp) -> Lifted {
    let (Some(d), Some(s)) = (lift_operand(instr, 0), lift_operand(instr, 1)) else {
        return Lifted::Unsupported;
    };
    let dst_size = operand_size_at(instr, 0);
    let src_size = operand_size_at(instr, 1);
    Lifted::Instr(
        VmInstr::new(op, dst_size)
            .with_operands([d, s])
            .with_src_size(src_size),
    )
}

/// cbw/cwde/cdqe: RAX'i yerinde sign-extend eder.
fn acc_sext(dst: OpSize, src: OpSize) -> Lifted {
    Lifted::Instr(
        VmInstr::new(VmOp::Movsx, dst)
            .with_operands([VmOperand::Reg(VReg::RAX), VmOperand::Reg(VReg::RAX)])
            .with_src_size(src),
    )
}

/// Belirli bir operandın boyutunu döndürür.
fn operand_size_at(instr: &Instruction, i: u32) -> OpSize {
    match instr.op_kind(i) {
        OpKind::Register => {
            let sz = instr.op_register(i).size();
            if sz > 0 {
                OpSize::from_bytes(sz as u32)
            } else {
                OpSize::Qword
            }
        }
        OpKind::Memory => {
            let sz = instr.memory_size().size();
            if sz > 0 {
                OpSize::from_bytes(sz as u32)
            } else {
                OpSize::Qword
            }
        }
        _ => OpSize::Qword,
    }
}

fn is_near_branch(instr: &Instruction) -> bool {
    matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

/// Tek bir operandı VM operandına çevirir; desteklenmeyen tür → `None`.
fn lift_operand(instr: &Instruction, i: u32) -> Option<VmOperand> {
    match instr.op_kind(i) {
        OpKind::Register => map_gpr(instr.op_register(i)).map(VmOperand::Reg),
        OpKind::Immediate8 => Some(VmOperand::Imm(instr.immediate8() as i8 as i64)),
        OpKind::Immediate8to16 => Some(VmOperand::Imm(instr.immediate8to16() as i64)),
        OpKind::Immediate8to32 => Some(VmOperand::Imm(instr.immediate8to32() as i64)),
        OpKind::Immediate8to64 => Some(VmOperand::Imm(instr.immediate8to64())),
        OpKind::Immediate16 => Some(VmOperand::Imm(instr.immediate16() as i64)),
        OpKind::Immediate32 => Some(VmOperand::Imm(instr.immediate32() as i64)),
        OpKind::Immediate32to64 => Some(VmOperand::Imm(instr.immediate32to64())),
        OpKind::Immediate64 => Some(VmOperand::Imm(instr.immediate64() as i64)),
        OpKind::Memory => lift_memory(instr).map(VmOperand::Mem),
        _ => None,
    }
}

fn lift_memory(instr: &Instruction) -> Option<MemRef> {
    // RIP-relatif erişim: iced mutlak adresi displacement olarak verir.
    if instr.is_ip_rel_memory_operand() {
        return Some(MemRef {
            base: None,
            index: None,
            scale: 1,
            disp: instr.memory_displacement64() as i64,
        });
    }

    let base = reg_or_none(instr.memory_base());
    let index = reg_or_none(instr.memory_index());
    // Base/index var ama GPR'ye eşlenemiyorsa (örn. segment) → desteklenmez.
    if instr.memory_base() != Register::None && base.is_none() {
        return None;
    }
    if instr.memory_index() != Register::None && index.is_none() {
        return None;
    }

    Some(MemRef {
        base,
        index,
        scale: instr.memory_index_scale() as u8,
        disp: instr.memory_displacement64() as i64,
    })
}

fn reg_or_none(reg: Register) -> Option<VReg> {
    if reg == Register::None {
        None
    } else {
        map_gpr(reg)
    }
}

/// iced Register → VReg (yalnızca 64-bit GPR ailesi).
fn map_gpr(reg: Register) -> Option<VReg> {
    let full = reg.full_register();
    let idx = match full {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => return None, // RIP, XMM, segment, vb.
    };
    Some(VReg(idx))
}

/// Komutun etkin operand boyutunu belirler.
fn operation_size(instr: &Instruction) -> OpSize {
    for i in 0..instr.op_count() {
        match instr.op_kind(i) {
            OpKind::Register => {
                let sz = instr.op_register(i).size();
                if sz > 0 {
                    return OpSize::from_bytes(sz as u32);
                }
            }
            OpKind::Memory => {
                let sz = instr.memory_size().size();
                if sz > 0 {
                    return OpSize::from_bytes(sz as u32);
                }
            }
            _ => {}
        }
    }
    OpSize::Qword
}

fn map_cond(cc: ConditionCode) -> Option<Cond> {
    let c = match cc {
        ConditionCode::o => Cond::O,
        ConditionCode::no => Cond::No,
        ConditionCode::b => Cond::B,
        ConditionCode::ae => Cond::Ae,
        ConditionCode::e => Cond::E,
        ConditionCode::ne => Cond::Ne,
        ConditionCode::be => Cond::Be,
        ConditionCode::a => Cond::A,
        ConditionCode::s => Cond::S,
        ConditionCode::ns => Cond::Ns,
        ConditionCode::p => Cond::P,
        ConditionCode::np => Cond::Np,
        ConditionCode::l => Cond::L,
        ConditionCode::ge => Cond::Ge,
        ConditionCode::le => Cond::Le,
        ConditionCode::g => Cond::G,
        ConditionCode::None => return None,
    };
    Some(c)
}
