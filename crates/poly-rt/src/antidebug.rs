//! User-mode anti-debug katmanı (Faz 2.2).
//!
//! **Dürüst kapsam:** Intel VT-x / AMD-V / EPT tabanlı bir mini-hypervisor
//! user-mode bir uygulamadan kurulamaz; bu Ring-0 (kernel sürücüsü) ya da
//! UEFI/bootloader bileşeni gerektirir. Bu modül, bir korumalı uygulamanın
//! kullanıcı modundan **gerçekten** yapabileceği tespitleri uygular:
//!
//! - **PEB.BeingDebugged** — `gs:[0x60]` üzerinden doğrudan PEB okuması.
//! - **PEB.NtGlobalFlag** — heap debug bayrakları (debugger varlığı ipucu).
//! - **DR0–DR3 donanım breakpoint'leri** — `GetThreadContext` ile (x64dbg'nin
//!   donanımsal breakpoint'lerini yakalar).
//! - **RDTSC timing** — single-step/trace altında zaman sapması.
//! - **Linux:** `/proc/self/status` TracerPid (ptrace) kontrolü.
//!
//! Tespit edilince çağıran taraf [`crate::SecureVm::poison`] ile VM belleğini
//! sahte kodla bozabilir.

/// Anti-debug tarama sonucu. Hangi göstergelerin tetiklendiğini ayrı ayrı tutar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DebugStatus {
    pub debugger_present: bool,
    pub nt_global_flag: bool,
    pub hardware_breakpoints: bool,
    pub timing_anomaly: bool,
}

impl DebugStatus {
    /// Herhangi bir gösterge tetiklendi mi?
    pub fn detected(&self) -> bool {
        self.debugger_present
            || self.nt_global_flag
            || self.hardware_breakpoints
            || self.timing_anomaly
    }
}

/// Varsayılan RDTSC eşiği. Normal sistemde 100 iterasyonluk döngü birkaç yüz
/// çevrim sürer; single-step debugger altında bu patlar. Eşik, yanlış pozitifi
/// önleyecek kadar yüksek seçilir.
pub const DEFAULT_RDTSC_THRESHOLD: u64 = 1_000_000;

/// Tüm göstergeleri tarar (varsayılan timing eşiğiyle).
pub fn check() -> DebugStatus {
    check_with_timing(DEFAULT_RDTSC_THRESHOLD)
}

/// Tüm göstergeleri, verilen RDTSC eşiğiyle tarar.
pub fn check_with_timing(rdtsc_threshold: u64) -> DebugStatus {
    DebugStatus {
        debugger_present: debugger_present(),
        nt_global_flag: nt_global_flag_set(),
        hardware_breakpoints: hardware_breakpoints(),
        timing_anomaly: timing_anomaly(rdtsc_threshold),
    }
}

// ---- PEB tabanlı kontroller (Windows x64) ----------------------------------

/// PEB tabanı (`gs:[0x60]`).
#[cfg(all(windows, target_arch = "x86_64"))]
#[inline]
fn peb_base() -> u64 {
    let peb: u64;
    // SAFETY: Windows x64'te TEB->ProcessEnvironmentBlock daima gs:[0x60]'tadır.
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly));
    }
    peb
}

/// PEB.BeingDebugged (offset +0x02).
#[cfg(all(windows, target_arch = "x86_64"))]
fn debugger_present() -> bool {
    let peb = peb_base();
    // SAFETY: PEB içinde geçerli, hizalı bir byte okuması.
    let flag = unsafe { core::ptr::read_volatile((peb + 0x02) as *const u8) };
    flag != 0
}

/// PEB.NtGlobalFlag (offset +0xBC). 0x70 maskesi heap debug bayraklarıdır.
#[cfg(all(windows, target_arch = "x86_64"))]
fn nt_global_flag_set() -> bool {
    const FLG_HEAP_DEBUG: u32 = 0x70; // ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS
    let peb = peb_base();
    // SAFETY: PEB içinde geçerli, hizalı bir u32 okuması.
    let v = unsafe { core::ptr::read_volatile((peb + 0xBC) as *const u32) };
    v & FLG_HEAP_DEBUG != 0
}

/// DR0–DR3 donanım breakpoint register'ları ayarlı mı?
#[cfg(all(windows, target_arch = "x86_64"))]
fn hardware_breakpoints() -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
    use windows_sys::Win32::System::Threading::GetCurrentThread;

    // CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64(0x100000) | 0x10
    const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

    // SAFETY: CONTEXT 16-bayt hizalı, zeroed güvenli; GetThreadContext sadece
    // ContextFlags ile istenen alanları doldurur.
    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    let ok = unsafe { GetThreadContext(GetCurrentThread(), &mut ctx) };
    if ok == 0 {
        return false;
    }
    ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0
}

// ---- Linux ptrace kontrolü -------------------------------------------------

#[cfg(target_os = "linux")]
fn debugger_present() -> bool {
    // /proc/self/status içinde TracerPid != 0 → bir izleyici (debugger) var.
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                return rest.trim().parse::<u32>().map(|p| p != 0).unwrap_or(false);
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn nt_global_flag_set() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn hardware_breakpoints() -> bool {
    false
}

// ---- Diğer platformlar için no-op fallback ---------------------------------

#[cfg(not(any(all(windows, target_arch = "x86_64"), target_os = "linux")))]
fn debugger_present() -> bool {
    false
}

#[cfg(not(any(all(windows, target_arch = "x86_64"), target_os = "linux")))]
fn nt_global_flag_set() -> bool {
    false
}

#[cfg(not(any(all(windows, target_arch = "x86_64"), target_os = "linux")))]
fn hardware_breakpoints() -> bool {
    false
}

// ---- RDTSC timing (mimari bağımsız x86) ------------------------------------

/// Küçük, öngörülebilir bir iş bloğunun çevrim sayısı eşiği aşıyorsa `true`
/// (single-step / trace altında tipik).
pub fn timing_anomaly(threshold_cycles: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: _rdtsc tüm x86_64'te mevcuttur.
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        let mut acc = 0u64;
        for i in 0..100u64 {
            acc = acc.wrapping_add(i);
        }
        core::hint::black_box(acc);
        let end = unsafe { core::arch::x86_64::_rdtsc() };
        end.wrapping_sub(start) > threshold_cycles
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = threshold_cycles;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_debugger_in_normal_run() {
        // Test debugger altında çalışmadığı sürece hiçbir gösterge tetiklenmemeli.
        let st = check();
        assert!(
            !st.detected(),
            "normal çalıştırmada tespit olmamalı: {st:?}"
        );
    }

    #[test]
    fn timing_huge_threshold_never_fires() {
        assert!(!timing_anomaly(u64::MAX));
    }
}
