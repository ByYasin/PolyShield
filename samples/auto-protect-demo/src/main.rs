//! Tek çağrıyla tüm-modül otomatik şeffaf koruma demosu.
//!
//! Packed bir DLL yüklenir, `poly_rt::autoprotect::protect_all` ile **tüm**
//! korumalı fonksiyonlara otomatik detour kurulur; ardından export'lar olağan
//! şekilde (GetProcAddress + çağrı) çalıştırıldığında şeffafça gömülü VM'e gider.
//! Sonuçlar, korunmamış bir referans modülün VM hesabıyla karşılaştırılarak
//! doğrulanır.

use std::process::ExitCode;

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() -> ExitCode {
    use poly_rt::autoprotect::{protect_all, resolve_export};
    use poly_rt::ProtectedModule;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("kullanım: auto-protect-demo <packed.dll>");
        return ExitCode::FAILURE;
    };

    // DLL'i yükle.
    let cpath = std::ffi::CString::new(path.as_str()).unwrap();
    let hmod_handle = unsafe { LoadLibraryA(cpath.as_ptr() as *const u8) };
    if hmod_handle.is_null() {
        eprintln!("LoadLibrary başarısız");
        return ExitCode::FAILURE;
    }
    let hmod = hmod_handle as usize;

    // Referans (korunmamış) modül — beklenen değerleri hesaplamak için.
    let reference = match ProtectedModule::from_file(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("referans modül: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Korunacak modül (protect_all sahipliği alır).
    let module = ProtectedModule::from_file(path).expect("modül");

    // TEK ÇAĞRI: tüm korumalı fonksiyonlara otomatik detour.
    let n = match unsafe { protect_all(module, |name| resolve_export(hmod, name)) } {
        Ok(n) => n,
        Err(e) => {
            eprintln!("protect_all: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("╔══════════════════════════════════════════════════════════");
    println!("║  Otomatik Tüm-Modül Şeffaf Koruma");
    println!("╠══════════════════════════════════════════════════════════");
    println!("║  Modül: {path}");
    println!("║  {n} fonksiyon tek çağrıyla otomatik detour'landı");
    println!("╠──────────────────────────────────────────────────────────");

    // 1-argümanlı, tam sanallaştırılabilir korumalı fonksiyonları olağan şekilde
    // çağır → şeffafça VM. (check_license stack-cookie çağrısı içerdiğinden tam
    // yürütülemez; native-escape sınırına örnektir, bilinçli olarak dışarıda.)
    let cases: [(&str, u64); 2] = [("polyv_table_lookup", 2), ("polyo_secret_value", 0x1357)];

    let mut all_ok = true;
    for (name, arg) in cases {
        let cname = std::ffi::CString::new(name).unwrap();
        let proc = unsafe { GetProcAddress(hmod_handle, cname.as_ptr() as *const u8) };
        let Some(proc) = proc else {
            continue;
        };
        let f: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(proc) };
        let got = f(arg); // detour → dispatcher → VM
        let expected = reference.call(name, &[arg]).unwrap_or(u64::MAX);
        let ok = got == expected;
        all_ok &= ok;
        println!(
            "║  {} {}({:#x}) → {:#x} (beklenen {:#x})",
            if ok { "✓" } else { "✗" },
            name,
            arg,
            got,
            expected
        );
    }
    println!("╚══════════════════════════════════════════════════════════");

    if all_ok {
        println!("\n✓ Tüm çağrılar şeffafça VM'e yönlendirildi ve doğru sonuç verdi.");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() -> ExitCode {
    eprintln!("Bu demo yalnızca Windows x64'te desteklenir.");
    ExitCode::FAILURE
}
