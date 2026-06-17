//! # poly-vm
//!
//! PolyShield Custom Virtual CPU motoru (Faz 1.2).
//!
//! Boru hattı: **x86-64 makine kodu → VM IR (lift) → kompakt bytecode (encode)**.
//! Doğruluk, dahili bir register-tabanlı [`interp`] yorumlayıcısıyla doğrulanır.
//!
//! Önemli not: Derlenmiş bir binary'de LLVM IR bulunmaz; bu yüzden kaynak,
//! disassemble edilen makine kodudur (`iced-x86`). Eşlenemeyen komutlar
//! `VmOp::Native` ile ham haliyle korunur, böylece hiçbir davranış kaybolmaz.
//!
//! ```
//! use poly_vm::VmProgram;
//! // mov eax, ecx ; add eax, edx ; ret   (System V / Win64 arg reg'leri farklı)
//! let code = [0x89, 0xC8, 0x01, 0xD0, 0xC3];
//! let prog = VmProgram::from_x86(&code, 0x1000, Some("add".into()));
//! assert_eq!(prog.stats.native, 0);
//! ```

pub mod disasm;
pub mod encoder;
pub mod error;
pub mod interp;
pub mod isa;
pub mod lifter;
pub mod polymorph;
pub mod program;
pub mod rng;

pub use encoder::OpcodeMap;
pub use error::{Result, VmError};
pub use interp::{run, step, NativeHandler, RunOutcome, StepFlow, VmState};
pub use isa::{Cond, MemRef, OpSize, VReg, VmInstr, VmOp, VmOperand};
pub use lifter::{lift, LiftResult};
pub use polymorph::{armor, ArmorResult, ArmoredProgram, RegPerm};
pub use program::{VmProgram, VmStats};
pub use rng::SplitMix64;
