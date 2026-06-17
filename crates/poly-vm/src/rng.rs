//! Deterministik sözde-rastgele sayı üreteci (SplitMix64).
//!
//! Polimorfik motorun matematiksel çekirdeği. SplitMix64; hızlı, yüksek
//! kaliteli dağılıma sahip ve **tamamen deterministiktir**: aynı tohum daima
//! aynı diziyi üretir. Bu, zırhlı bir programı sadece tohumdan yeniden
//! kurabilmek (decode) için zorunludur.
//!
//! Algoritma (Steele, Lea, Flood 2014):
//! ```text
//! state += 0x9E3779B97F4A7C15
//! z = state
//! z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
//! z = (z ^ (z >> 27)) * 0x94D049BB133111EB
//! return z ^ (z >> 31)
//! ```

/// SplitMix64 üreteci.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Verilen tohumla başlatır.
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Sıradaki 64-bit değeri üretir.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Sıradaki byte.
    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    /// `[0, n)` aralığında, reddetme örneklemesiyle (rejection sampling) eğilimsiz
    /// (unbiased) bir indeks üretir. Fisher-Yates karıştırması için kullanılır.
    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        let n = n as u64;
        // 2^64'ün n'e tam bölünen en büyük katı; üstünü reddet → eğilim yok.
        let limit = u64::MAX - (u64::MAX % n);
        loop {
            let x = self.next_u64();
            if x < limit {
                return (x % n) as usize;
            }
        }
    }

    /// Bir dilimi yerinde Fisher-Yates ile karıştırır.
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.below(i + 1);
            slice.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SplitMix64;

    #[test]
    fn deterministic() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = SplitMix64::new(1);
        let mut b = SplitMix64::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn below_in_range() {
        let mut r = SplitMix64::new(7);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
    }

    #[test]
    fn shuffle_is_permutation() {
        let mut r = SplitMix64::new(99);
        let mut v: Vec<u32> = (0..16).collect();
        r.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            (0..16).collect::<Vec<_>>(),
            "tüm elemanlar korunmalı"
        );
    }
}
