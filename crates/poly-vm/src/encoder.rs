//! VM IR ↔ kompakt bytecode serileştirme.
//!
//! Her `VmOp`, bir [`OpcodeMap`] üzerinden tek bir byte'a eşlenir. Varsayılan
//! eşleme kimliktir (identity); Faz 1.3'teki **polimorfik motor**, tohumdan
//! (seed) türetilen rastgele bir permütasyon üreterek her zırhlamada opcode
//! byte'larının yerini değiştirecek — altyapı burada hazırdır
//! ([`OpcodeMap::shuffled`]).

use crate::error::{Result, VmError};
use crate::isa::{Cond, MemRef, OpSize, VReg, VmInstr, VmOp, VmOperand};

const TAG_REG: u8 = 0;
const TAG_IMM: u8 = 1;
const TAG_MEM: u8 = 2;
const TAG_LABEL: u8 = 3;
const NONE_REG: u8 = 0xFF;

/// `VmOp` ↔ byte eşlemesi. 1.3 polimorfizminin temelidir.
#[derive(Debug, Clone)]
pub struct OpcodeMap {
    /// op.index() → emit edilen byte.
    enc: [u8; 256],
    /// byte → op.index() (yoksa 0xFF).
    dec: [u8; 256],
    used: usize,
}

impl OpcodeMap {
    /// Kimlik eşlemesi: her op kendi sıra indeksindeki byte'a gider.
    pub fn identity() -> Self {
        let mut enc = [0u8; 256];
        let mut dec = [0xFFu8; 256];
        for (i, _) in VmOp::ALL.iter().enumerate() {
            enc[i] = i as u8;
            dec[i] = i as u8;
        }
        OpcodeMap {
            enc,
            dec,
            used: VmOp::ALL.len(),
        }
    }

    /// Tohumdan türetilen deterministik rastgele permütasyon (polimorfik motor).
    ///
    /// 0..256 byte uzayı SplitMix64 ile Fisher-Yates karıştırılır; ilk `N` byte
    /// op'lara atanır. Aynı tohum → aynı eşleme (decode için gerekli).
    pub fn shuffled(seed: u64) -> Self {
        let mut perm: [u8; 256] = [0; 256];
        for (i, p) in perm.iter_mut().enumerate() {
            *p = i as u8;
        }
        crate::rng::SplitMix64::new(seed).shuffle(&mut perm);

        let mut enc = [0u8; 256];
        let mut dec = [0xFFu8; 256];
        let n = VmOp::ALL.len();
        for i in 0..n {
            let byte = perm[i];
            enc[i] = byte;
            dec[byte as usize] = i as u8;
        }
        OpcodeMap { enc, dec, used: n }
    }

    fn encode_op(&self, op: VmOp) -> u8 {
        self.enc[op.index()]
    }

    fn decode_op(&self, byte: u8) -> Result<VmOp> {
        let idx = self.dec[byte as usize];
        if idx as usize >= self.used {
            return Err(VmError::BadOpcode(byte));
        }
        Ok(VmOp::ALL[idx as usize])
    }
}

impl Default for OpcodeMap {
    fn default() -> Self {
        Self::identity()
    }
}

/// IR programını kompakt bytecode'a serileştirir.
pub fn encode(instrs: &[VmInstr], map: &OpcodeMap) -> Vec<u8> {
    let mut out = Vec::with_capacity(instrs.len() * 6);
    for instr in instrs {
        out.push(map.encode_op(instr.op));

        if instr.op == VmOp::Native {
            let len = instr.native_bytes.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&instr.native_bytes);
            continue;
        }

        let cond_present = instr.cond.is_some();
        let src_present = instr.src_size.is_some();
        let header = instr.size.code()
            | ((cond_present as u8) << 2)
            | (((instr.operands.len() as u8) & 0b11) << 3)
            | ((src_present as u8) << 5);
        out.push(header);

        if let Some(c) = instr.cond {
            out.push(c.code());
        }
        if let Some(s) = instr.src_size {
            out.push(s.code());
        }

        for operand in &instr.operands {
            encode_operand(&mut out, operand);
        }
    }
    out
}

fn encode_operand(out: &mut Vec<u8>, operand: &VmOperand) {
    match operand {
        VmOperand::Reg(r) => {
            out.push(TAG_REG);
            out.push(r.0);
        }
        VmOperand::Imm(v) => {
            out.push(TAG_IMM);
            out.extend_from_slice(&v.to_le_bytes());
        }
        VmOperand::Mem(m) => {
            out.push(TAG_MEM);
            out.push(m.base.map(|r| r.0).unwrap_or(NONE_REG));
            out.push(m.index.map(|r| r.0).unwrap_or(NONE_REG));
            out.push(m.scale);
            out.extend_from_slice(&m.disp.to_le_bytes());
        }
        VmOperand::Label(idx) => {
            out.push(TAG_LABEL);
            out.extend_from_slice(&idx.to_le_bytes());
        }
    }
}

/// Bytecode'u IR programına geri çözer.
pub fn decode(bytes: &[u8], map: &OpcodeMap) -> Result<Vec<VmInstr>> {
    let mut cur = Cursor::new(bytes);
    let mut instrs = Vec::new();

    while !cur.at_end() {
        let op_byte = cur.u8()?;
        let op = map.decode_op(op_byte)?;

        if op == VmOp::Native {
            let len = cur.u16()? as usize;
            let bytes = cur.take(len)?.to_vec();
            let mut vi = VmInstr::new(VmOp::Native, OpSize::Qword);
            vi.native_bytes = bytes;
            instrs.push(vi);
            continue;
        }

        let header = cur.u8()?;
        let size = OpSize::from_code(header & 0b11);
        let cond_present = (header >> 2) & 1 == 1;
        let op_count = ((header >> 3) & 0b11) as usize;
        let src_present = (header >> 5) & 1 == 1;

        let cond = if cond_present {
            Some(Cond::from_code(cur.u8()?).ok_or(VmError::BadField)?)
        } else {
            None
        };
        let src_size = if src_present {
            Some(OpSize::from_code(cur.u8()?))
        } else {
            None
        };

        let mut operands = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            operands.push(decode_operand(&mut cur)?);
        }

        instrs.push(VmInstr {
            op,
            size,
            operands,
            cond,
            src_size,
            native_bytes: Vec::new(),
            orig_addr: 0,
        });
    }

    Ok(instrs)
}

fn decode_operand(cur: &mut Cursor) -> Result<VmOperand> {
    let tag = cur.u8()?;
    match tag {
        TAG_REG => Ok(VmOperand::Reg(VReg(cur.u8()?))),
        TAG_IMM => Ok(VmOperand::Imm(cur.i64()?)),
        TAG_MEM => {
            let base = reg_opt(cur.u8()?);
            let index = reg_opt(cur.u8()?);
            let scale = cur.u8()?;
            let disp = cur.i64()?;
            Ok(VmOperand::Mem(MemRef {
                base,
                index,
                scale,
                disp,
            }))
        }
        TAG_LABEL => Ok(VmOperand::Label(cur.u32()?)),
        other => Err(VmError::BadOperandTag(other)),
    }
}

fn reg_opt(b: u8) -> Option<VReg> {
    if b == NONE_REG {
        None
    } else {
        Some(VReg(b))
    }
}

/// Basit, sınır kontrollü byte okuyucu.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }
    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos + n;
        if end > self.bytes.len() {
            return Err(VmError::Truncated {
                offset: self.pos,
                needed: n,
            });
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i64(&mut self) -> Result<i64> {
        let b = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(i64::from_le_bytes(arr))
    }
}
