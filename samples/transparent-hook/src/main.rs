//! Şeffaf çağrı yönlendirme (detour hook) PoC — otomatik in-process stub'ın
//! çekirdeği.
//!
//! Fikir: korumalı bir fonksiyonun prologue'u çalışma anında `jmp dispatcher`
//! ile yamalanır. Bundan sonra fonksiyon **olağan şekilde çağrıldığında** kontrol
//! şeffafça gömülü VM'e gider, sonuç hesaplanır ve çağırana döner — çağıran
//! hiçbir şeyin değiştiğini fark etmez.
//!
//! Kanıt: aynı çağrı `real_secret(x)`
//!   • hook'tan ÖNCE  → orijinal (sentinel) değeri döner,
//!   • hook'tan SONRA → VM'in hesapladığı değeri döner.
//!
//! Dürüst sınırlar:
//!   • Runtime (poly-rt) sürece **link** edilmiştir; yabancı bir sürece enjekte
//!     edilen bağımsız PIC shellcode değildir.
//!   • Hook, programın kendi başlangıç kodu tarafından kurulur; packer tarafından
//!     entry point'e gömülmüş değildir.
//!   • Yalnızca Windows x64. Detour, fonksiyonun ilk 12 baytını ezer (gövdenin
//!     kalanı çalıştırılmaz).
//! Bunlar, tam ürünleşme için kalan son adımdır; mekanizmanın kendisi gerçektir.

use std::process::ExitCode;

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() -> ExitCode {
    use std::sync::OnceLock;

    use poly_rt::ProtectedModule;

    static MODULE: OnceLock<ProtectedModule> = OnceLock::new();
    static FUNC: OnceLock<String> = OnceLock::new();

    // Korumalı (gizlenmek istenen) orijinal fonksiyon. Hook sonrası gövdesi
    // çalıştırılmaz; gerçek mantık VM'dedir. Sentinel döndürür ki hook'un
    // çalıştığı net görülsün.
    #[no_mangle]
    #[inline(never)]
    extern "C" fn real_secret(x: u64) -> u64 {
        let mut a = std::hint::black_box(0x0BAD_C0DE_u64);
        a = a.wrapping_add(std::hint::black_box(x));
        a ^= std::hint::black_box(0x1111_2222);
        std::hint::black_box(a)
    }

    // VM dispatcher: çağrı buraya yönlenir. Argüman RCX'te (Win64) gelir.
    #[no_mangle]
    #[inline(never)]
    extern "C" fn vm_dispatch(x: u64) -> u64 {
        let m = MODULE.get().expect("modül");
        let f = FUNC.get().expect("fonksiyon");
        m.call(f, &[x]).unwrap_or(0xDEAD_DEAD)
    }

    /// Fonksiyonun ilk 12 baytını `movabs rax, dispatch; jmp rax` ile yamalar.
    unsafe fn install_detour(target: usize, dispatch: usize) {
        use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut patch = [0u8; 12];
        patch[0] = 0x48; // REX.W
        patch[1] = 0xB8; // mov rax, imm64
        patch[2..10].copy_from_slice(&(dispatch as u64).to_le_bytes());
        patch[10] = 0xFF; // jmp rax
        patch[11] = 0xE0;

        let p = target as *mut u8;
        let mut old = 0u32;
        VirtualProtect(p as *mut _, 12, PAGE_EXECUTE_READWRITE, &mut old);
        std::ptr::copy_nonoverlapping(patch.as_ptr(), p, 12);
        let mut tmp = 0u32;
        VirtualProtect(p as *mut _, 12, old, &mut tmp);
        FlushInstructionCache(GetCurrentProcess(), p as *const _, 12);
    }

    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1).cloned() else {
        eprintln!("kullanım: transparent-hook <packed.dll> [fonksiyon] [arg]");
        return ExitCode::FAILURE;
    };
    let func = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "table_lookup".into());
    let arg: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);

    let module = match ProtectedModule::from_file(&path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("modül yüklenemedi: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = MODULE.set(module);
    let _ = FUNC.set(func.clone());

    // Beklenen (VM'in doğrudan hesabı).
    let expected = MODULE.get().unwrap().call(&func, &[arg]).unwrap_or(0);

    // Hook'tan ÖNCE: orijinal gövde çalışır.
    let before = real_secret(std::hint::black_box(arg));

    // Detour'u kur.
    let target = real_secret as extern "C" fn(u64) -> u64 as usize;
    let dispatch = vm_dispatch as extern "C" fn(u64) -> u64 as usize;
    unsafe { install_detour(target, dispatch) };

    // Hook'tan SONRA: aynı çağrı şeffafça VM'e gider.
    let after = real_secret(std::hint::black_box(arg));

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  Şeffaf Detour Hook PoC");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Modül     : {path}");
    println!("║  Fonksiyon : {func}({arg})");
    println!("╠──────────────────────────────────────────────────────────");
    println!("║  real_secret ÖNCE (orijinal) : {before} ({before:#x})");
    println!("║  real_secret SONRA (VM'e yön.): {after} ({after:#x})");
    println!("║  VM doğrudan (beklenen)      : {expected} ({expected:#x})");
    println!("╠──────────────────────────────────────────────────────────");
    if after == expected && before != after {
        println!("║  SONUÇ: ✓ Çağrı şeffafça VM'e yönlendirildi");
    } else {
        println!("║  SONUÇ: ✗ yönlendirme başarısız");
    }
    println!("╚══════════════════════════════════════════════════════════");

    if after == expected && before != after {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() -> ExitCode {
    eprintln!("Bu PoC yalnızca Windows x64'te desteklenir.");
    ExitCode::FAILURE
}
