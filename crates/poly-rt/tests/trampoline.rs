//! Native-escape trampoline testi (yalnızca Windows x64'te anlamlı).
//!
//! `popcnt` lift edilmez → native escape olur; trampoline onu gerçek CPU'da
//! çalıştırıp sonucu VM register'ına köprüler.

#![cfg(all(windows, target_arch = "x86_64"))]

use poly_rt::TrampolineHandler;
use poly_vm::interp::{run, VmState};
use poly_vm::isa::VReg;
use poly_vm::VmProgram;

#[test]
fn trampoline_runs_popcnt_escape() {
    // popcnt rax, rcx ; ret   (F3 48 0F B8 C1, C3) — popcnt lift edilmez.
    let code = &[0xF3, 0x48, 0x0F, 0xB8, 0xC1, 0xC3];
    let prog = VmProgram::from_x86(code, 0x1000, None);
    assert!(prog.stats.native >= 1, "popcnt native escape olmalı");

    let mut st = VmState::with_default_stack();
    st.set_native_handler(Box::new(TrampolineHandler::new()));
    st.set_reg_full(VReg::RCX, 0xFF); // 8 bit set
    run(&prog.instrs, &mut st, 1000).expect("trampoline ile çalışmalı");
    assert_eq!(st.reg(VReg::RAX), 8, "popcnt(0xFF) = 8");

    // Farklı girdi.
    let mut st2 = VmState::with_default_stack();
    st2.set_native_handler(Box::new(TrampolineHandler::new()));
    st2.set_reg_full(VReg::RCX, 0xFFFF_FFFF_FFFF_FFFF);
    run(&prog.instrs, &mut st2, 1000).unwrap();
    assert_eq!(st2.reg(VReg::RAX), 64, "popcnt(u64::MAX) = 64");
}

#[test]
fn without_handler_escape_errors() {
    let code = &[0xF3, 0x48, 0x0F, 0xB8, 0xC1, 0xC3];
    let prog = VmProgram::from_x86(code, 0x1000, None);
    let mut st = VmState::with_default_stack();
    // handler yok → escape hata vermeli.
    assert!(run(&prog.instrs, &mut st, 1000).is_err());
}
