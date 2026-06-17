//! VM IR'ının okunabilir metin dökümü (hata ayıklama ve raporlama için).

use crate::isa::{MemRef, OpSize, VmInstr, VmOp, VmOperand};

/// Tüm programı satır satır metne döker.
pub fn dump(instrs: &[VmInstr]) -> String {
    let mut out = String::new();
    for (i, instr) in instrs.iter().enumerate() {
        out.push_str(&format!("{i:04}: {}\n", format_instr(instr)));
    }
    out
}

/// Tek bir komutu biçimlendirir.
pub fn format_instr(instr: &VmInstr) -> String {
    let mut s = String::new();

    // Mnemonic (koşullu komutlarda koşulu ekle).
    match (instr.op, instr.cond) {
        (VmOp::Jcc, Some(c)) => s.push_str(&format!("j{}", c.mnemonic())),
        (VmOp::Setcc, Some(c)) => s.push_str(&format!("set{}", c.mnemonic())),
        (VmOp::Cmov, Some(c)) => s.push_str(&format!("cmov{}", c.mnemonic())),
        _ => s.push_str(instr.op.mnemonic()),
    }

    // Boyut soneki (kontrol akışı dışındaki komutlarda).
    if !matches!(
        instr.op,
        VmOp::Jmp | VmOp::Jcc | VmOp::Call | VmOp::Ret | VmOp::Nop | VmOp::VmExit
    ) {
        s.push('.');
        s.push_str(size_suffix(instr.size));
    }

    if instr.op == VmOp::Native {
        let hex: Vec<String> = instr
            .native_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return format!("native [{}]", hex.join(" "));
    }

    // Operandlar.
    let ops: Vec<String> = instr.operands.iter().map(format_operand).collect();
    if !ops.is_empty() {
        s.push(' ');
        s.push_str(&ops.join(", "));
    }
    s
}

fn format_operand(op: &VmOperand) -> String {
    match op {
        VmOperand::Reg(r) => r.name().to_string(),
        VmOperand::Imm(v) => {
            if *v < 0 {
                format!("-0x{:x}", v.unsigned_abs())
            } else {
                format!("0x{v:x}")
            }
        }
        VmOperand::Mem(m) => format_mem(m),
        VmOperand::Label(idx) => format!("@{idx:04}"),
    }
}

fn format_mem(m: &MemRef) -> String {
    let mut inner = String::new();
    if let Some(b) = m.base {
        inner.push_str(b.name());
    }
    if let Some(i) = m.index {
        if !inner.is_empty() {
            inner.push('+');
        }
        inner.push_str(&format!("{}*{}", i.name(), m.scale));
    }
    if m.disp != 0 || inner.is_empty() {
        if m.disp < 0 {
            inner.push_str(&format!("-0x{:x}", m.disp.unsigned_abs()));
        } else {
            if !inner.is_empty() {
                inner.push('+');
            }
            inner.push_str(&format!("0x{:x}", m.disp));
        }
    }
    format!("[{inner}]")
}

fn size_suffix(size: OpSize) -> &'static str {
    match size {
        OpSize::Byte => "b",
        OpSize::Word => "w",
        OpSize::Dword => "d",
        OpSize::Qword => "q",
    }
}
