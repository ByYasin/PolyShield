//! # poly-rt
//!
//! PolyShield çalışma zamanı (Faz 2): self-encrypting VM yürütme ve user-mode
//! anti-debug.
//!
//! - [`SecureVm`] — bytecode'u bellekte komut başına şifreli tutar; çalışırken
//!   her komutu deşifre edip donanım entropisiyle (RDRAND) yeniden şifreler.
//! - [`antidebug`] — PEB / donanım breakpoint / timing tabanlı debugger tespiti.
//! - [`HwRng`] — RDRAND destekli entropi (yazılım fallback'li).
//!
//! ```
//! use poly_rt::{SecureVm, HwRng};
//! use poly_vm::{VmProgram, VmState, isa::VReg};
//!
//! // add(ecx, edx): mov eax,ecx ; add eax,edx ; ret
//! let prog = VmProgram::from_x86(&[0x89, 0xC8, 0x01, 0xD0, 0xC3], 0x1000, None);
//! let mut vm = SecureVm::new(&prog.instrs, HwRng::seeded(42));
//!
//! let mut st = VmState::with_default_stack();
//! st.set_reg_full(VReg::RCX, 20);
//! st.set_reg_full(VReg::RDX, 22);
//! vm.run(&mut st, 10_000).unwrap();
//! assert_eq!(st.reg(VReg::RAX) & 0xFFFF_FFFF, 42);
//! ```

pub mod antidebug;
pub mod autoprotect;
pub mod hwrng;
pub mod loader;
pub mod secure_vm;
pub mod trampoline;

pub use antidebug::{check, DebugStatus};
pub use hwrng::HwRng;
pub use loader::ProtectedModule;
pub use secure_vm::SecureVm;
pub use trampoline::TrampolineHandler;
