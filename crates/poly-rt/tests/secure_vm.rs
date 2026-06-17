//! SecureVm entegrasyon testleri: doğruluk, at-rest şifreleme, self-mutation,
//! ve anti-debug zehirlemesi (poison).

use poly_rt::{HwRng, SecureVm};
use poly_vm::encoder::{encode, OpcodeMap};
use poly_vm::interp::{run, VmState};
use poly_vm::isa::VReg;
use poly_vm::VmProgram;

const BASE: u64 = 0x1000;
const ADD_FN: &[u8] = &[0x89, 0xC8, 0x01, 0xD0, 0xC3]; // eax = ecx + edx
const MAX_FN: &[u8] = &[0x89, 0xC8, 0x39, 0xD0, 0x7D, 0x02, 0x89, 0xD0, 0xC3];

fn id_encode(instrs: &[poly_vm::VmInstr]) -> Vec<u8> {
    encode(instrs, &OpcodeMap::identity())
}

#[test]
fn secure_run_matches_plain_add() {
    let prog = VmProgram::from_x86(ADD_FN, BASE, None);
    let mut vm = SecureVm::new(&prog.instrs, HwRng::seeded(1));

    let mut st = VmState::with_default_stack();
    st.set_reg_full(VReg::RCX, 15);
    st.set_reg_full(VReg::RDX, 27);
    let out = vm.run(&mut st, 10_000).unwrap();
    assert!(out.halted);
    assert_eq!(st.reg(VReg::RAX) & 0xFFFF_FFFF, 42);
}

#[test]
fn secure_run_matches_plain_branch() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);
    for (a, b, exp) in [(9u64, 4u64, 9u64), (4, 9, 9), (5, 5, 5)] {
        let mut vm = SecureVm::new(&prog.instrs, HwRng::seeded(7));
        let mut st = VmState::with_default_stack();
        st.set_reg_full(VReg::RCX, a);
        st.set_reg_full(VReg::RDX, b);
        vm.run(&mut st, 10_000).unwrap();
        assert_eq!(st.reg(VReg::RAX) & 0xFFFF_FFFF, exp, "max({a},{b})");
    }
}

#[test]
fn bytecode_is_encrypted_at_rest() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);
    let vm = SecureVm::new(&prog.instrs, HwRng::seeded(123));

    let plaintext = id_encode(&prog.instrs);
    let at_rest = vm.memory_snapshot();

    assert_eq!(at_rest.len(), plaintext.len(), "boyut korunmalı");
    assert_ne!(
        at_rest, plaintext,
        "rest'te bytecode düz olmamalı (şifreli)"
    );

    // İçerik yine de doğru çözülebilmeli (yapısal eşitlik).
    let recovered = vm.decrypt_all().unwrap();
    assert_eq!(
        id_encode(&recovered),
        plaintext,
        "deşifre içerik orijinalle aynı olmalı"
    );
}

#[test]
fn execution_mutates_ciphertext() {
    // Çalıştırma, çalıştırılan komutların şifreli halini değiştirmeli
    // (self-encrypting: her döngüde yeni anahtar).
    let prog = VmProgram::from_x86(ADD_FN, BASE, None);
    let mut vm = SecureVm::new(&prog.instrs, HwRng::seeded(55));

    let before = vm.memory_snapshot();
    let mut st = VmState::with_default_stack();
    st.set_reg_full(VReg::RCX, 1);
    st.set_reg_full(VReg::RDX, 2);
    vm.run(&mut st, 10_000).unwrap();
    let after = vm.memory_snapshot();

    assert_ne!(before, after, "çalıştırma ciphertext'i mutasyona uğratmalı");
    // Ama program hâlâ doğru çözülebilmeli.
    assert_eq!(
        id_encode(&vm.decrypt_all().unwrap()),
        id_encode(&prog.instrs)
    );
}

#[test]
fn deterministic_with_seeded_entropy() {
    // Aynı tohum → aynı sonuç (yeniden üretilebilirlik).
    let prog = VmProgram::from_x86(ADD_FN, BASE, None);
    let snap = |seed| {
        let mut vm = SecureVm::new(&prog.instrs, HwRng::seeded(seed));
        let mut st = VmState::with_default_stack();
        st.set_reg_full(VReg::RCX, 3);
        st.set_reg_full(VReg::RDX, 4);
        vm.run(&mut st, 10_000).unwrap();
        (st.reg(VReg::RAX) & 0xFFFF_FFFF, vm.memory_snapshot())
    };
    assert_eq!(snap(99), snap(99), "aynı tohum determinist olmalı");
}

#[test]
fn poison_destroys_and_blocks_execution() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);
    let mut vm = SecureVm::new(&prog.instrs, HwRng::seeded(2024));

    let before = vm.memory_snapshot();
    vm.poison();
    assert!(vm.is_poisoned());
    assert_ne!(vm.memory_snapshot(), before, "poison belleği bozmalı");

    let mut st = VmState::with_default_stack();
    assert!(
        vm.run(&mut st, 10_000).is_err(),
        "zehirlenmiş VM çalışmamalı"
    );
}

#[test]
fn matches_plain_interpreter_exactly() {
    // SecureVm sonucu, düz yorumlayıcının sonucuyla birebir aynı olmalı.
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);

    let mut plain_st = VmState::with_default_stack();
    plain_st.set_reg_full(VReg::RCX, 42);
    plain_st.set_reg_full(VReg::RDX, 17);
    run(&prog.instrs, &mut plain_st, 10_000).unwrap();

    let mut vm = SecureVm::new(&prog.instrs, HwRng::seeded(1));
    let mut sec_st = VmState::with_default_stack();
    sec_st.set_reg_full(VReg::RCX, 42);
    sec_st.set_reg_full(VReg::RDX, 17);
    vm.run(&mut sec_st, 10_000).unwrap();

    assert_eq!(
        plain_st.reg(VReg::RAX) & 0xFFFF_FFFF,
        sec_st.reg(VReg::RAX) & 0xFFFF_FFFF
    );
}
