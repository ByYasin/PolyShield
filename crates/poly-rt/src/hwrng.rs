//! Donanım destekli entropi kaynağı.
//!
//! Mümkünse CPU'nun **RDRAND** komutundan (Intel/AMD donanımsal RNG) beslenir;
//! yoksa yazılım `SplitMix64`'e düşer. Self-encrypting runtime'ın anahtar
//! mutasyonu buradan beslenir, böylece her çalıştırmada şifreleme farklıdır.
//!
//! Testler için [`HwRng::seeded`] deterministik bir kaynak verir.

use poly_vm::SplitMix64;

/// Entropi arka ucu.
enum Backend {
    /// CPU RDRAND mevcut; her çağrıda donanımdan okunur.
    Rdrand,
    /// Yazılım fallback (deterministik).
    Soft(SplitMix64),
}

/// Donanım/yazılım entropi üreteci.
pub struct HwRng {
    backend: Backend,
}

impl HwRng {
    /// En iyi mevcut kaynağı seçer: RDRAND varsa onu, yoksa adres+sayaç
    /// tohumlu yazılım üretecini.
    pub fn auto() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("rdrand") {
                return HwRng {
                    backend: Backend::Rdrand,
                };
            }
        }
        // Fallback tohumu: yığın adresi + ASLR ile her süreçte değişir.
        let stack_anchor = 0u8;
        let seed = (&stack_anchor as *const u8 as u64) ^ 0xA5A5_5A5A_DEAD_C0DE;
        HwRng {
            backend: Backend::Soft(SplitMix64::new(seed)),
        }
    }

    /// Deterministik yazılım kaynağı (testler / yeniden üretilebilirlik için).
    pub fn seeded(seed: u64) -> Self {
        HwRng {
            backend: Backend::Soft(SplitMix64::new(seed)),
        }
    }

    /// `true` → bu üreteç gerçek donanım RDRAND kullanıyor.
    pub fn is_hardware(&self) -> bool {
        matches!(self.backend, Backend::Rdrand)
    }

    /// Sıradaki 64-bit rastgele değer.
    pub fn next_u64(&mut self) -> u64 {
        match &mut self.backend {
            Backend::Rdrand => rdrand64().unwrap_or_else(|| {
                // Nadir RDRAND başarısızlığında geçici yazılım karışımı.
                let anchor = 0u8;
                SplitMix64::new(&anchor as *const u8 as u64).next_u64()
            }),
            Backend::Soft(sm) => sm.next_u64(),
        }
    }
}

/// Donanımdan tek bir 64-bit değer okumaya çalışır (10 deneme).
#[cfg(target_arch = "x86_64")]
fn rdrand64() -> Option<u64> {
    use core::arch::x86_64::_rdrand64_step;
    let mut val: u64 = 0;
    // RDRAND nadiren "hazır değil" döndürebilir; birkaç kez dene.
    for _ in 0..10 {
        // SAFETY: yalnızca rdrand özelliği tespit edildiğinde çağrılır.
        if unsafe { _rdrand64_step(&mut val) } == 1 {
            return Some(val);
        }
    }
    None
}

#[cfg(not(target_arch = "x86_64"))]
fn rdrand64() -> Option<u64> {
    None
}
