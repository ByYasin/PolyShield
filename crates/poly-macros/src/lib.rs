//! PolyShield inline koruma attribute'leri (Faz 4.2).
//!
//! ## Neden sadece "işaretleme"?
//! Bir proc-macro derleme **sırasında** çalışır; o anda fonksiyonun makine kodu
//! henüz üretilmemiştir. Bu yüzden makro fonksiyonu kendisi sanallaştıramaz.
//! Bunun yerine **post-build (derleme sonrası) otopilot** akışını mümkün kılar:
//!
//! 1. `#[poly_virtualize]` fonksiyonu `polyv_<ad>` olarak **export** eder ve
//!    `#[inline(never)]` ile ayrı, bulunabilir bir fonksiyon olarak korur.
//! 2. Derlenen binary'de bu export'lar görünür; adresleri `.pdata` ile
//!    eşleşerek fonksiyon sınırları (boyut) elde edilir.
//! 3. `poly-cli shield <binary>` bu `polyv_*` / `polyo_*` export'larını bulup
//!    zırhlar (CI'da otomatik).
//!
//! ```ignore
//! #[poly_virtualize]
//! fn check_license(key: u64) -> bool { key ^ 0xDEAD == 0x1337 }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Fonksiyonu tam sanallaştırma için işaretler: `polyv_<ad>` adıyla export eder.
#[proc_macro_attribute]
pub fn poly_virtualize(_attr: TokenStream, item: TokenStream) -> TokenStream {
    mark(item, "polyv_")
}

/// Fonksiyonu karartma (obfuscate) için işaretler: `polyo_<ad>` adıyla export eder.
#[proc_macro_attribute]
pub fn poly_obfuscate(_attr: TokenStream, item: TokenStream) -> TokenStream {
    mark(item, "polyo_")
}

fn mark(item: TokenStream, prefix: &str) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);
    let export_name = format!("{prefix}{}", func.sig.ident);

    // export_name + inline(never): fonksiyon dış sembol tablosunda ayrı ve
    // bulunabilir kalır; böylece post-build otopilot adresini/boyutunu çözebilir.
    quote! {
        #[export_name = #export_name]
        #[inline(never)]
        #func
    }
    .into()
}
