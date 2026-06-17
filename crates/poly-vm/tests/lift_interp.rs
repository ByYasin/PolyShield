//! poly-vm entegrasyon testleri: lift → interpret → encode round-trip.
//!
//! Test girdileri elle-assemble edilmiş küçük x86-64 fonksiyonlarıdır; böylece
//! testler harici bir derleyiciye (cl/gcc) ihtiyaç duymaz.

use poly_vm::encoder::{self, OpcodeMap};
use poly_vm::interp::{run, VmState};
use poly_vm::isa::VReg;
use poly_vm::VmProgram;

const BASE: u64 = 0x1000;

/// mov eax, ecx ; add eax, edx ; ret  →  eax = ecx + edx
const ADD_FN: &[u8] = &[0x89, 0xC8, 0x01, 0xD0, 0xC3];

/// max(ecx, edx):
///   mov eax, ecx ; cmp eax, edx ; jge +2 ; mov eax, edx ; ret
const MAX_FN: &[u8] = &[0x89, 0xC8, 0x39, 0xD0, 0x7D, 0x02, 0x89, 0xD0, 0xC3];

/// Bir fonksiyonu lift edip çalıştırır; RCX/RDX girişiyle RAX'i döndürür.
fn run_fn(code: &[u8], rcx: u64, rdx: u64) -> u64 {
    let prog = VmProgram::from_x86(code, BASE, None);
    assert_eq!(
        prog.stats.native, 0,
        "tüm komutlar lift edilmeli: {code:02x?}"
    );
    let mut st = VmState::with_default_stack();
    st.set_reg_full(VReg::RCX, rcx);
    st.set_reg_full(VReg::RDX, rdx);
    run(&prog.instrs, &mut st, 10_000).unwrap();
    st.reg(VReg::RAX)
}

#[test]
fn movzx_zero_extends() {
    // movzx eax, cl ; ret  → RAX = RCX'in düşük byte'ı (zero-extend)
    let r = run_fn(&[0x0F, 0xB6, 0xC1, 0xC3], 0x1122_3344_5566_7788, 0);
    assert_eq!(r, 0x88);
}

#[test]
fn movsx_sign_extends() {
    // movsx eax, cl ; ret  → 0x88 sign-extend → 0xFFFFFF88 (eax), rax üst sıfır
    let r = run_fn(&[0x0F, 0xBE, 0xC1, 0xC3], 0x88, 0);
    assert_eq!(r & 0xFFFF_FFFF, 0xFFFF_FF88);
}

#[test]
fn cdqe_sign_extends_eax() {
    // mov eax, ecx ; cdqe ; ret → RAX = sign_extend(ECX)
    let r = run_fn(&[0x89, 0xC8, 0x48, 0x98, 0xC3], 0xFFFF_FFFF, 0);
    assert_eq!(r, u64::MAX);
}

#[test]
fn rol_rotates_left() {
    // mov rax, rcx ; rol rax, 8 ; ret
    let r = run_fn(&[0x48, 0x89, 0xC8, 0x48, 0xC1, 0xC0, 0x08, 0xC3], 0x1, 0);
    assert_eq!(r, 0x100);
}

#[test]
fn ror_rotates_right() {
    // mov rax, rcx ; ror rax, 4 ; ret
    let r = run_fn(&[0x48, 0x89, 0xC8, 0x48, 0xC1, 0xC8, 0x04, 0xC3], 0x10, 0);
    assert_eq!(r, 0x1);
}

#[test]
fn bts_sets_bit() {
    // mov rax, rcx ; bts rax, 5 ; ret  → bit 5 set
    let r = run_fn(
        &[0x48, 0x89, 0xC8, 0x48, 0x0F, 0xBA, 0xE8, 0x05, 0xC3],
        0,
        0,
    );
    assert_eq!(r, 0x20);
}

#[test]
fn setcc_sets_byte_on_condition() {
    // xor eax,eax ; cmp ecx,edx ; sete al ; ret
    let code = &[0x31, 0xC0, 0x39, 0xD1, 0x0F, 0x94, 0xC0, 0xC3];
    assert_eq!(run_fn(code, 5, 5) & 0xFF, 1, "eşitse 1");
    assert_eq!(run_fn(code, 5, 6) & 0xFF, 0, "eşit değilse 0");
}

#[test]
fn cmov_selects_conditionally() {
    // mov eax,ecx ; cmp eax,edx ; cmovl eax,edx ; ret  → signed max(ecx,edx)
    let code = &[0x89, 0xC8, 0x39, 0xD0, 0x0F, 0x4C, 0xC2, 0xC3];
    assert_eq!(run_fn(code, 3, 10) & 0xFFFF_FFFF, 10);
    assert_eq!(run_fn(code, 10, 3) & 0xFFFF_FFFF, 10);
}

#[test]
fn xchg_swaps() {
    // xchg rcx, rax ; ret  → RAX = eski RCX (RAX 0'dan başlar)
    let r = run_fn(&[0x48, 0x91, 0xC3], 0xABCD, 0);
    assert_eq!(r, 0xABCD);
}

#[test]
fn bswap_reverses_bytes() {
    // mov rax, rcx ; bswap rax ; ret
    let r = run_fn(
        &[0x48, 0x89, 0xC8, 0x48, 0x0F, 0xC8, 0xC3],
        0x1122_3344_5566_7788,
        0,
    );
    assert_eq!(r, 0x8877_6655_4433_2211);
}

#[test]
fn mul_unsigned() {
    // mov rax, rcx ; mul rdx ; ret  → RAX = RCX * RDX (düşük 64)
    let r = run_fn(&[0x48, 0x89, 0xC8, 0x48, 0xF7, 0xE2, 0xC3], 6, 7);
    assert_eq!(r, 42);
}

#[test]
fn div_unsigned() {
    // mov rax,rcx ; xor edx,edx ; mov r8d,7 ; div r8 ; ret  → RAX = RCX / 7
    let code = &[
        0x48, 0x89, 0xC8, 0x31, 0xD2, 0x41, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x49, 0xF7, 0xF0, 0xC3,
    ];
    assert_eq!(run_fn(code, 43, 0), 6);
}

#[test]
fn idiv_signed() {
    // mov rax,rcx ; xor edx,edx ; mov r8d,7 ; idiv r8 ; ret
    let code = &[
        0x48, 0x89, 0xC8, 0x31, 0xD2, 0x41, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x49, 0xF7, 0xF8, 0xC3,
    ];
    assert_eq!(run_fn(code, 100, 0), 14);
}

#[test]
fn cqo_sign_extends_to_rdx() {
    // mov rax,rcx ; cqo ; mov rax,rdx ; ret  → RDX = RAX'in işaret yayılımı
    let code = &[0x48, 0x89, 0xC8, 0x48, 0x99, 0x48, 0x89, 0xD0, 0xC3];
    assert_eq!(
        run_fn(code, 0x8000_0000_0000_0000, 0),
        u64::MAX,
        "negatif → tüm 1"
    );
    assert_eq!(run_fn(code, 5, 0), 0, "pozitif → 0");
}

#[test]
fn shld_double_shift_left() {
    // mov rax,rcx ; shld rax, rdx, 8 ; ret
    let code = &[0x48, 0x89, 0xC8, 0x48, 0x0F, 0xA4, 0xD0, 0x08, 0xC3];
    let r = run_fn(code, 0x1, 0xFF00_0000_0000_0000);
    assert_eq!(r, 0x1FF);
}

#[test]
fn shrd_double_shift_right() {
    // mov rax,rcx ; shrd rax, rdx, 8 ; ret
    let code = &[0x48, 0x89, 0xC8, 0x48, 0x0F, 0xAC, 0xD0, 0x08, 0xC3];
    let r = run_fn(code, 0x100, 0x1);
    assert_eq!(r, 0x0100_0000_0000_0001);
}

#[test]
fn xadd_exchange_and_add() {
    // mov rax,rdx ; xadd rax, rcx ; ret  → rax = rdx + rcx
    let code = &[0x48, 0x89, 0xD0, 0x48, 0x0F, 0xC1, 0xC8, 0xC3];
    assert_eq!(run_fn(code, 10, 32), 42);
}

#[test]
fn cmpxchg_equal_writes_dst() {
    // mov rax,rcx ; cmpxchg rcx,rdx ; mov rax,rcx ; ret
    // RAX==RCX olduğundan rcx=rdx olur → sonuç rdx.
    let code = &[
        0x48, 0x89, 0xC8, 0x48, 0x0F, 0xB1, 0xD1, 0x48, 0x89, 0xC8, 0xC3,
    ];
    assert_eq!(run_fn(code, 5, 99), 99);
}

#[test]
fn lifts_and_runs_add() {
    let prog = VmProgram::from_x86(ADD_FN, BASE, Some("add".into()));
    assert_eq!(prog.stats.native, 0, "tüm komutlar lift edilmeli");
    assert_eq!(prog.stats.coverage, 1.0);

    let mut st = VmState::with_default_stack();
    st.set_reg_full(VReg::RCX, 5);
    st.set_reg_full(VReg::RDX, 37);
    let out = run(&prog.instrs, &mut st, 1000).unwrap();
    assert!(out.halted);
    assert_eq!(st.reg(VReg::RAX) & 0xFFFF_FFFF, 42);
}

#[test]
fn lifts_and_runs_branch_max() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, Some("max".into()));
    assert_eq!(prog.stats.native, 0);

    for (a, b, expected) in [(10u64, 3u64, 10u64), (3, 10, 10), (7, 7, 7)] {
        let mut st = VmState::with_default_stack();
        st.set_reg_full(VReg::RCX, a);
        st.set_reg_full(VReg::RDX, b);
        run(&prog.instrs, &mut st, 1000).unwrap();
        assert_eq!(
            st.reg(VReg::RAX) & 0xFFFF_FFFF,
            expected,
            "max({a}, {b}) yanlış"
        );
    }
}

#[test]
fn bytecode_roundtrips() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);
    let map = OpcodeMap::identity();

    let bytes1 = encoder::encode(&prog.instrs, &map);
    let decoded = encoder::decode(&bytes1, &map).expect("decode başarılı olmalı");
    let bytes2 = encoder::encode(&decoded, &map);

    assert_eq!(bytes1, bytes2, "encode → decode → encode kararlı olmalı");
    assert_eq!(decoded.len(), prog.instrs.len());
}

#[test]
fn shuffled_opcode_map_roundtrips() {
    // Faz 1.3 polimorfizm temeli: karıştırılmış eşlemeyle de geri çözülebilmeli.
    let prog = VmProgram::from_x86(ADD_FN, BASE, None);
    let map = OpcodeMap::shuffled(0xDEAD_BEEF);

    let bytes = encoder::encode(&prog.instrs, &map);
    let decoded = encoder::decode(&bytes, &map).unwrap();

    // Karıştırılmış byte'lar identity'den farklı olmalı.
    let identity_bytes = encoder::encode(&prog.instrs, &OpcodeMap::identity());
    assert_ne!(
        bytes, identity_bytes,
        "polimorfik eşleme byte'ları değiştirmeli"
    );

    // Ama anlamsal olarak aynı program kalmalı → çalıştırınca aynı sonuç.
    let mut st = VmState::with_default_stack();
    st.set_reg_full(VReg::RCX, 100);
    st.set_reg_full(VReg::RDX, 23);
    run(&decoded, &mut st, 1000).unwrap();
    assert_eq!(st.reg(VReg::RAX) & 0xFFFF_FFFF, 123);
}

#[test]
fn unsupported_instruction_becomes_native() {
    // cpuid (0F A2) lift edilemez → native escape; ret (C3) lift edilir.
    let code = [0x0F, 0xA2, 0xC3];
    let prog = VmProgram::from_x86(&code, BASE, None);
    assert_eq!(prog.stats.native, 1, "cpuid native olmalı");
    assert!(prog.stats.coverage < 1.0);
}

#[test]
fn disassembly_is_readable() {
    let prog = VmProgram::from_x86(ADD_FN, BASE, None);
    let text = prog.disassemble();
    assert!(text.contains("mov"), "döküm mov içermeli:\n{text}");
    assert!(text.contains("add"), "döküm add içermeli:\n{text}");
    assert!(text.contains("ret"), "döküm ret içermeli:\n{text}");
}
