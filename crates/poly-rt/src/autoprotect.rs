//! Otomatik tüm-modül şeffaf koruma (Faz 5+ otomasyon).
//!
//! Tek çağrıyla, yüklü bir modüldeki **tüm** korumalı fonksiyonlara detour kurar:
//! her fonksiyonun prologue'u `mov r11d, <id>; jmp ortak_dispatcher` ile yamalanır.
//! Ortak dispatcher, id'yi argümanla birlikte Rust tarafına geçirir; oradan
//! gömülü VM çalışır ve sonuç şeffafça çağırana döner.
//!
//! ## Dürüst sınırlar
//!   • Yalnızca `extern "C" fn(u64) -> u64` imzalı fonksiyonlar (id, RCX'i RDX'e
//!     taşıyıp dispatcher'a verir; tek tamsayı argüman + tamsayı dönüş).
//!   • Runtime (poly-rt) sürece **link**'lidir; foreign-process PIC enjeksiyonu değil.
//!   • Kurulum, programın kendi kodu tarafından çağrılır (packer entry'sine gömülü
//!     değil). Mekanizma gerçek; tam ürünleşme bu iki kısıttır.

#[cfg(all(windows, target_arch = "x86_64"))]
pub use imp::{protect_all, resolve_export};

#[cfg(all(windows, target_arch = "x86_64"))]
mod imp {
    use std::sync::OnceLock;

    use crate::ProtectedModule;

    static MODULE: OnceLock<ProtectedModule> = OnceLock::new();
    static NAMES: OnceLock<Vec<String>> = OnceLock::new();
    static COMMON_STUB: OnceLock<usize> = OnceLock::new();

    /// id ve argümanla çağrılan Rust dispatcher'ı; gömülü VM'i çalıştırır.
    extern "C" fn dispatch(id: u64, arg: u64) -> u64 {
        let names = NAMES.get().expect("isimler");
        let module = MODULE.get().expect("modül");
        match names.get(id as usize) {
            Some(name) => module.call(name, &[arg]).unwrap_or(0xDEAD_DEAD),
            None => 0xDEAD_DEAD,
        }
    }

    /// Ortak dispatcher stub'ı: `mov rdx,rcx; mov rcx,r11; movabs rax,dispatch; jmp rax`.
    /// (Argümanı RDX'e, id'yi RCX'e koyup `dispatch(id, arg)`'a atlar.)
    fn common_stub() -> usize {
        *COMMON_STUB.get_or_init(|| {
            use windows_sys::Win32::System::Memory::{
                VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            };
            let d = dispatch as extern "C" fn(u64, u64) -> u64 as usize as u64;
            let mut code = vec![0x48, 0x89, 0xCA, 0x4C, 0x89, 0xD9, 0x48, 0xB8];
            code.extend_from_slice(&d.to_le_bytes());
            code.extend_from_slice(&[0xFF, 0xE0]);
            unsafe {
                let buf = VirtualAlloc(
                    std::ptr::null(),
                    code.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                std::ptr::copy_nonoverlapping(code.as_ptr(), buf as *mut u8, code.len());
                buf as usize
            }
        })
    }

    /// Bir fonksiyonun prologue'unu `mov r11d, id; movabs rax, common; jmp rax`
    /// (18 byte) ile yamalar.
    unsafe fn install_detour(target: usize, id: u32, common: usize) {
        use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut p = [0u8; 18];
        p[0] = 0x41;
        p[1] = 0xBB; // mov r11d, imm32
        p[2..6].copy_from_slice(&id.to_le_bytes());
        p[6] = 0x48;
        p[7] = 0xB8; // movabs rax, imm64
        p[8..16].copy_from_slice(&(common as u64).to_le_bytes());
        p[16] = 0xFF;
        p[17] = 0xE0; // jmp rax

        let ptr = target as *mut u8;
        let mut old = 0u32;
        VirtualProtect(ptr as *mut _, 18, PAGE_EXECUTE_READWRITE, &mut old);
        std::ptr::copy_nonoverlapping(p.as_ptr(), ptr, 18);
        let mut tmp = 0u32;
        VirtualProtect(ptr as *mut _, 18, old, &mut tmp);
        FlushInstructionCache(GetCurrentProcess(), ptr as *const _, 18);
    }

    /// Yüklü modülün bir export'unun çalışma zamanı adresini çözer (GetProcAddress).
    pub fn resolve_export(module_handle: usize, name: &str) -> Option<usize> {
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
        let cname = std::ffi::CString::new(name).ok()?;
        // SAFETY: geçerli HMODULE + null-terminated ad.
        let p = unsafe { GetProcAddress(module_handle as _, cname.as_ptr() as *const u8) };
        p.map(|f| f as usize)
    }

    /// Modüldeki tüm korumalı fonksiyonlara otomatik detour kurar.
    ///
    /// `resolve(name) -> Option<adres>` her fonksiyonun çalışma zamanı adresini
    /// verir (genelde [`resolve_export`]). Kurulan detour sayısını döndürür.
    ///
    /// # Safety
    /// Çağıran, `resolve`'un döndürdüğü adreslerin yamalanabilir (en az 18 byte
    /// prologue'lu, `extern "C" fn(u64)->u64`) gerçek fonksiyonlar olduğunu
    /// garanti etmelidir.
    pub unsafe fn protect_all<F: Fn(&str) -> Option<usize>>(
        module: ProtectedModule,
        resolve: F,
    ) -> Result<usize, String> {
        let common = common_stub();
        let all_names: Vec<String> = module.names().cloned().collect();

        let mut installed: Vec<String> = Vec::new();
        for name in &all_names {
            if let Some(addr) = resolve(name) {
                let id = installed.len() as u32;
                install_detour(addr, id, common);
                installed.push(name.clone());
            }
        }

        if installed.is_empty() {
            return Err("çözülebilen korumalı fonksiyon yok".into());
        }
        let n = installed.len();
        MODULE
            .set(module)
            .map_err(|_| "modül zaten ayarlı".to_string())?;
        NAMES
            .set(installed)
            .map_err(|_| "isimler zaten ayarlı".to_string())?;
        Ok(n)
    }
}
