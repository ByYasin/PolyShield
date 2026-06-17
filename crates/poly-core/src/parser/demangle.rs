//! Sembol adı çözme (demangling) yardımcıları.
//!
//! `demangle` feature'ı kapalıysa tüm fonksiyonlar `None` döndürür; bu sayede
//! çağıran kod feature durumundan bağımsız aynı şekilde yazılabilir.

/// Verilen ham sembol adını okunabilir hale getirmeyi dener.
///
/// - Rust adları (`_ZN...`, `_R...`) → `rustc-demangle`
/// - Itanium C++ adları (`_Z...`) → `cpp_demangle`
/// - MSVC adları (`?...`) ve diğerleri şimdilik çözülmez (`None`).
///
/// Çözülen ad ham adla aynıysa (yani zaten okunabilirse) `None` döndürülür,
/// böylece gereksiz tekrar saklanmaz.
#[cfg(feature = "demangle")]
pub fn demangle(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }

    // Önce Rust: `_R` (v0) veya `_ZN...E` (legacy) kalıpları.
    if name.starts_with("_R") || name.starts_with("_ZN") {
        if let Ok(sym) = rustc_demangle::try_demangle(name) {
            let out = format!("{sym:#}"); // `:#}` → trailing hash'i gizler
            return distinct(name, out);
        }
    }

    // Itanium C++ (clang/gcc): `_Z` ile başlar.
    if name.starts_with("_Z") {
        if let Ok(sym) = cpp_demangle::Symbol::new(name) {
            if let Ok(out) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
                return distinct(name, out);
            }
        }
    }

    None
}

#[cfg(not(feature = "demangle"))]
pub fn demangle(_name: &str) -> Option<String> {
    None
}

/// Çözülmüş ad ham addan farklıysa onu döndürür, aksi halde `None`.
#[cfg(feature = "demangle")]
fn distinct(original: &str, demangled: String) -> Option<String> {
    if demangled == original {
        None
    } else {
        Some(demangled)
    }
}

#[cfg(all(test, feature = "demangle"))]
mod tests {
    use super::demangle;

    #[test]
    fn demangles_itanium_cpp() {
        // _Z3fooi → foo(int)
        let out = demangle("_Z3fooi").expect("C++ adı çözülmeli");
        assert_eq!(out, "foo(int)");
    }

    #[test]
    fn demangles_rust_legacy() {
        // Legacy Rust mangling.
        let out =
            demangle("_ZN4core3fmt9Formatter3pad17h0123456789abcdefE").expect("Rust adı çözülmeli");
        assert!(out.contains("core::fmt::Formatter::pad"), "çıktı: {out}");
    }

    #[test]
    fn plain_c_name_returns_none() {
        // Mangle edilmemiş düz C adı çözülmemeli.
        assert_eq!(demangle("CreateFileW"), None);
    }

    #[test]
    fn empty_name_returns_none() {
        assert_eq!(demangle(""), None);
    }
}
