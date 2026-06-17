//! Self-encrypting VM yürütücüsü (Faz 2.1).
//!
//! VM bytecode bellekte **komut başına şifreli** durur. Bir komut çalıştırılırken
//! yalnızca o komut anlık olarak deşifre edilir, decode edilip hemen **yeni bir
//! anahtarla yeniden şifrelenir**; anahtar her döngüde donanım entropisinden
//! (RDRAND) beslenerek mutasyona uğrar.
//!
//! Sonuç: herhangi bir anda alınan bir bellek dökümü (memory dump) neredeyse
//! tamamen şifreli görünür ve aynı baytlar iki ardışık çalıştırmada farklıdır.
//! Bu, VMProtect'in self-mutating handler'larının sadeleştirilmiş bir modelidir.
//!
//! > Not: anahtar tablosu burada düz bellektedir (mekanizmayı göstermek için).
//! > Üretimde anahtarlar türetilir/gizlenir; bu, mimariyi değiştirmez.

use poly_vm::encoder::{decode, encode, OpcodeMap};
use poly_vm::interp::{step, RunOutcome, StepFlow, VmState};
use poly_vm::{Result, SplitMix64, VmError, VmInstr};

use crate::hwrng::HwRng;

/// Şifreli bir komutun konumu ve mevcut anahtarı.
#[derive(Clone, Copy)]
struct Slot {
    off: usize,
    len: usize,
    key: u64,
}

/// Komutları şifreli tutan, çalıştırırken kendini yeniden şifreleyen VM.
pub struct SecureVm {
    /// Birleştirilmiş şifreli bytecode (rest'te daima şifreli).
    enc: Vec<u8>,
    slots: Vec<Slot>,
    map: OpcodeMap,
    rng: HwRng,
    poisoned: bool,
}

impl SecureVm {
    /// IR komutlarından şifreli bir VM kurar. Her komut bağımsız anahtarla
    /// şifrelenir; anahtarlar `rng`'den üretilir.
    pub fn new(instrs: &[VmInstr], mut rng: HwRng) -> Self {
        let map = OpcodeMap::identity();
        let mut enc = Vec::new();
        let mut slots = Vec::with_capacity(instrs.len());

        for instr in instrs {
            let plain = encode(std::slice::from_ref(instr), &map);
            let key = rng.next_u64();
            let off = enc.len();
            let len = plain.len();

            let mut buf = plain;
            xor_keystream(&mut buf, key);
            enc.extend_from_slice(&buf);
            slots.push(Slot { off, len, key });
        }

        SecureVm {
            enc,
            slots,
            map,
            rng,
            poisoned: false,
        }
    }

    /// Bu VM gerçek donanım entropisi (RDRAND) kullanıyor mu?
    pub fn uses_hardware_entropy(&self) -> bool {
        self.rng.is_hardware()
    }

    /// Şifreli tampon boyutu (byte).
    pub fn encrypted_len(&self) -> usize {
        self.enc.len()
    }

    /// Şifreli tamponun bir kopyası (dump simülasyonu / test karşılaştırması).
    pub fn memory_snapshot(&self) -> Vec<u8> {
        self.enc.clone()
    }

    /// VM'i şifreli durumdan çalıştırır.
    ///
    /// Her komut: **deşifre → decode → yeni anahtarla yeniden şifrele → çalıştır**.
    pub fn run(&mut self, state: &mut VmState, max_steps: usize) -> Result<RunOutcome> {
        if self.poisoned {
            return Err(VmError::Interp(
                "VM zehirlendi (anti-debug tetiklendi) — yürütme reddedildi".into(),
            ));
        }

        let mut vip = 0usize;
        let mut call_stack: Vec<usize> = Vec::new();
        let mut steps = 0usize;

        while vip < self.slots.len() {
            if steps >= max_steps {
                return Err(VmError::Interp(format!("adım sınırı aşıldı ({max_steps})")));
            }
            steps += 1;

            let instr = self.fetch_decrypt_remutate(vip)?;
            match step(&instr, state, &mut call_stack, vip)? {
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

    /// Bir komutu deşifre edip decode eder, ardından tamponu **yeni** bir
    /// anahtarla yeniden şifreler (self-mutation). Plaintext yalnızca bu
    /// fonksiyonun yerel tamponunda, çok kısa süre bulunur.
    fn fetch_decrypt_remutate(&mut self, vip: usize) -> Result<VmInstr> {
        let slot = self.slots[vip];
        let range = slot.off..slot.off + slot.len;

        let mut buf = self.enc[range.clone()].to_vec();
        xor_keystream(&mut buf, slot.key); // → plaintext

        let instr = decode(&buf, &self.map)?
            .into_iter()
            .next()
            .ok_or_else(|| VmError::Interp("şifreli komut decode edilemedi".into()))?;

        // Donanım entropisiyle anahtarı mutasyona uğrat ve hemen yeniden şifrele.
        let new_key = mutate_key(slot.key, self.rng.next_u64());
        xor_keystream(&mut buf, new_key); // → yeni ciphertext
        self.enc[range].copy_from_slice(&buf);
        self.slots[vip].key = new_key;

        Ok(instr)
    }

    /// Komutların düz (deşifre edilmiş) halini döndürür — yalnızca doğrulama
    /// amaçlı. Bytecode'u kalıcı olarak deşifre **etmez**.
    pub fn decrypt_all(&self) -> Result<Vec<VmInstr>> {
        let mut out = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let mut buf = self.enc[slot.off..slot.off + slot.len].to_vec();
            xor_keystream(&mut buf, slot.key);
            let instr = decode(&buf, &self.map)?
                .into_iter()
                .next()
                .ok_or_else(|| VmError::Interp("decode hatası".into()))?;
            out.push(instr);
        }
        Ok(out)
    }

    /// Anti-debug yanıtı: tamponu sahte baytlarla doldurur ve anahtarları bozar.
    /// Bundan sonra hem bellek dökümü hem de yürütme anlamsızdır.
    pub fn poison(&mut self) {
        for b in self.enc.iter_mut() {
            *b = self.rng.next_u64() as u8;
        }
        for slot in self.slots.iter_mut() {
            slot.key = self.rng.next_u64();
        }
        self.poisoned = true;
    }

    /// VM zehirlenmiş (anti-debug tetiklenmiş) mi?
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

/// Veriyi anahtardan türeyen akışla XOR'lar (simetrik).
fn xor_keystream(data: &mut [u8], key: u64) {
    let mut r = SplitMix64::new(key);
    for b in data.iter_mut() {
        *b ^= r.next_u8();
    }
}

/// Mevcut anahtarı donanım entropisiyle karıştırarak yeni anahtar türetir.
fn mutate_key(old: u64, entropy: u64) -> u64 {
    SplitMix64::new(old ^ entropy.rotate_left(17)).next_u64()
}
