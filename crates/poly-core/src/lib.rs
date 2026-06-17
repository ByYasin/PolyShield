//! # poly-core
//!
//! PolyShield'in çekirdek motoru. Bu crate, derlenmiş binary'leri (PE/ELF)
//! ayrıştırıp fonksiyon sembol haritasını çıkaran altyapıyı sağlar (Faz 1).
//! İleride LLVM/bytecode dönüşümü ve koruma katmanları da buraya eklenecektir.
//!
//! ## Hızlı kullanım
//! ```no_run
//! let info = poly_core::parse_file("target.exe").unwrap();
//! println!("{} ({}), {} fonksiyon", info.format, info.arch, info.function_count());
//! for f in info.exported_functions() {
//!     println!("  {:#x}  {}", f.virtual_address, f.display_name());
//! }
//! ```

pub mod error;
pub mod parser;

// En sık kullanılan tipleri crate kökünden de erişilebilir kıl.
pub use error::{PolyError, Result};
pub use parser::model::{
    Arch, BinaryFormat, BinaryInfo, FunctionSymbol, SectionInfo, SymbolVisibility,
};
pub use parser::{parse_bytes, parse_file};
