//! Polimorfik motor testleri: determinizm, çeşitlilik (diversity) ve en
//! önemlisi **semantik koruma** — zırhlama sonucun değişmediğini ispatlar.

use poly_vm::encoder::{encode, OpcodeMap};
use poly_vm::interp::{run, VmState};
use poly_vm::isa::VReg;
use poly_vm::VmProgram;

const BASE: u64 = 0x1000;

/// mov eax, ecx ; add eax, edx ; ret  →  eax = ecx + edx
const ADD_FN: &[u8] = &[0x89, 0xC8, 0x01, 0xD0, 0xC3];
/// max(ecx, edx) — dallanma içerir (label fixup'ı test eder).
const MAX_FN: &[u8] = &[0x89, 0xC8, 0x39, 0xD0, 0x7D, 0x02, 0x89, 0xD0, 0xC3];

/// Zırhlı programı kurtarıp, register permütasyonunu uygulayarak çalıştırır.
fn run_armored(seed: u64, density: u8, code: &[u8], rcx: u64, rdx: u64) -> u64 {
    let prog = VmProgram::from_x86(code, BASE, None);
    let res = prog.armor(seed, density);

    // Konteyneri çöz (sadece tohumdan).
    let (recovered, perm) = res.armored.recover().expect("recover başarılı olmalı");
    // Yapısal eşitlik (orig_addr meta verisi hariç): encode çıktıları aynı olmalı.
    let id = OpcodeMap::identity();
    assert_eq!(
        encode(&recovered, &id),
        encode(&res.instrs, &id),
        "recover, zırhlanan IR'ı yapısal olarak birebir vermeli"
    );

    // Konuk bağlamı permütasyona göre yerleştir, çalıştır, sonucu geri eşle.
    let mut st = VmState::with_default_stack();
    st.set_reg_full(perm.map(VReg::RCX), rcx);
    st.set_reg_full(perm.map(VReg::RDX), rdx);
    run(&recovered, &mut st, 100_000).expect("çalıştırma başarılı olmalı");
    st.reg(perm.map(VReg::RAX)) & 0xFFFF_FFFF
}

#[test]
fn armor_preserves_semantics_add() {
    // Çeşitli tohum ve junk yoğunluklarında sonuç hep aynı olmalı.
    for seed in [1u64, 0xC0FFEE, 0xDEAD_BEEF, 777] {
        for density in [0u8, 30, 100] {
            assert_eq!(
                run_armored(seed, density, ADD_FN, 5, 37),
                42,
                "seed={seed} density={density}"
            );
        }
    }
}

#[test]
fn armor_preserves_semantics_branch() {
    // Junk enjeksiyonu label hedeflerini bozmamalı.
    for seed in [2u64, 0xABCDEF, 12345] {
        for density in [0u8, 50, 100] {
            assert_eq!(run_armored(seed, density, MAX_FN, 10, 3), 10);
            assert_eq!(run_armored(seed, density, MAX_FN, 3, 99), 99);
        }
    }
}

#[test]
fn same_seed_is_deterministic() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);
    let a = prog.armor(0x1234, 50);
    let b = prog.armor(0x1234, 50);
    assert_eq!(
        a.armored.payload, b.armored.payload,
        "aynı tohum → aynı payload"
    );
}

#[test]
fn different_seeds_produce_diverse_output() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);
    let a = prog.armor(0x1111, 50);
    let b = prog.armor(0x2222, 50);
    assert_ne!(
        a.armored.payload, b.armored.payload,
        "farklı tohumlar farklı çıktı üretmeli (polimorfizm)"
    );
}

#[test]
fn junk_increases_instruction_count() {
    let prog = VmProgram::from_x86(MAX_FN, BASE, None);
    let none = prog.armor(0x55, 0);
    let lots = prog.armor(0x55, 100);
    assert_eq!(none.junk_added, 0, "yoğunluk 0 → junk yok");
    assert!(lots.junk_added > 0, "yoğunluk 100 → junk eklenmeli");
    assert!(
        lots.instrs.len() > none.instrs.len(),
        "junk komut sayısını artırmalı"
    );
}

#[test]
fn register_permutation_is_nontrivial() {
    // Tohum, RSP hariç register'ları gerçekten yeniden adlandırmalı.
    let prog = VmProgram::from_x86(ADD_FN, BASE, None);
    let res = prog.armor(0x9999, 0);
    let table = res.perm.table();
    assert_eq!(table[4], 4, "RSP sabit kalmalı");
    // En az bir register yer değiştirmiş olmalı.
    assert!(
        (0..16).any(|i| table[i] != i as u8),
        "permütasyon birim olmamalı"
    );
}
