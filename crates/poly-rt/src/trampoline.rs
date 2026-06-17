//! Native-escape trampoline.
//!
//! Lift edilemeyen ham bir x86 komutunu **gerçek CPU'da** çalıştırır: VM register
//! ve flag durumunu bir bağlam yapısına yazar, çalışma anında üretilen bir stub
//! ile register'ları yükler → orijinal komutu icra eder → sonuçları geri yazar.
//!
//! ## Güvenli alt küme (dürüst sınır)
//! VM'in belleği gerçek süreç adres uzayından ayrık (flat Vec) olduğundan,
//! trampoline yalnızca **bellek erişimi olmayan, dallanma olmayan, yalnızca-GPR**
//! komutları güvenle çalıştırabilir (örn. `popcnt`, `lzcnt`, `tzcnt`, `andn`).
//! Bellek/kontrol-akışı/SSE escape'leri reddedilir (VM bunları yine de raporlar).
//! Bu, gerçek bir bağlam köprüsüdür; kapsamı mimari kısıttan gelir.

use poly_vm::error::{Result, VmError};
use poly_vm::{NativeHandler, VmState};

/// Native komutları gerçek CPU'da çalıştıran köprü.
pub struct TrampolineHandler;

impl Default for TrampolineHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TrampolineHandler {
    pub fn new() -> Self {
        TrampolineHandler
    }
}

impl NativeHandler for TrampolineHandler {
    fn handle(&mut self, bytes: &[u8], state: &mut VmState) -> Result<()> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            imp::run_native(bytes, state).map_err(VmError::Interp)
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            let _ = (bytes, state);
            Err(VmError::Interp(
                "native trampoline yalnızca Windows x64'te mevcut".into(),
            ))
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod imp {
    use iced_x86::code_asm::*;
    use iced_x86::{
        Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, OpKind, Register,
    };
    use poly_vm::VmState;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    /// Stub'ın okuyup yazdığı bağlam: 16 GPR + rflags.
    #[repr(C)]
    struct Ctx {
        regs: [u64; 16],
        rflags: u64,
    }

    const RSP_IDX: usize = 4;

    pub fn run_native(bytes: &[u8], state: &mut VmState) -> std::result::Result<(), String> {
        if bytes.is_empty() {
            return Err("boş native komut".into());
        }

        // 1) Komutu yeniden decode et ve güvenli alt kümede mi kontrol et.
        let mut decoder = Decoder::new(64, bytes, DecoderOptions::NONE);
        let instr = decoder.decode();
        if instr.is_invalid() {
            return Err("native komut decode edilemedi".into());
        }
        if instr.flow_control() != FlowControl::Next {
            return Err("kontrol-akışı escape'i trampoline edilemez".into());
        }
        for i in 0..instr.op_count() {
            if instr.op_kind(i) == OpKind::Memory {
                return Err("bellek erişimli escape trampoline edilemez".into());
            }
        }

        // Kullanılan register'lar: hepsi GPR olmalı, RSP kullanılmamalı.
        let mut info = InstructionInfoFactory::new();
        let used = info.info(&instr);
        let mut used_idx = [false; 16];
        for ur in used.used_registers() {
            let r = ur.register();
            if r == Register::None {
                continue;
            }
            if !r.is_gpr() {
                return Err("GPR olmayan (SSE/segment) escape trampoline edilemez".into());
            }
            let idx = gpr_index(r.full_register()).ok_or("bilinmeyen GPR")?;
            if idx == RSP_IDX {
                return Err("RSP kullanan escape trampoline edilemez".into());
            }
            used_idx[idx] = true;
        }

        // 2) Bağlam tutucu (holder): komutun kullanmadığı, RSP olmayan bir GPR.
        let holder_idx = (0..16)
            .find(|&i| i != RSP_IDX && !used_idx[i])
            .ok_or("boş holder register yok")?;

        // 3) Bağlamı VM durumundan doldur.
        let mut ctx = Ctx {
            regs: state.regs,
            rflags: compose_rflags(state),
        };

        // 4) Stub'ı üret ve çalıştır.
        let stub = assemble_stub(bytes, holder_idx)?;
        unsafe {
            let buf = VirtualAlloc(
                std::ptr::null(),
                stub.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if buf.is_null() {
                return Err("VirtualAlloc başarısız".into());
            }
            std::ptr::copy_nonoverlapping(stub.as_ptr(), buf as *mut u8, stub.len());
            let f: extern "C" fn(*mut Ctx) = std::mem::transmute(buf);
            f(&mut ctx);
            VirtualFree(buf, 0, MEM_RELEASE);
        }

        // 5) Sonuçları VM durumuna geri yaz.
        state.regs = ctx.regs;
        decompose_rflags(state, ctx.rflags);
        Ok(())
    }

    /// Bağlam köprüsü stub'ını code_asm ile üretir.
    fn assemble_stub(native: &[u8], holder_idx: usize) -> std::result::Result<Vec<u8>, String> {
        let regs = gpr_table();
        let holder = regs[holder_idx];
        let callee_saved = [rbx, rbp, rsi, rdi, r12, r13, r14, r15];

        let mut a = CodeAssembler::new(64).map_err(|e| e.to_string())?;
        let e = |r: Result<(), iced_x86::IcedError>| r.map_err(|x| x.to_string());

        // Callee-saved register'ları sakla.
        for r in callee_saved {
            e(a.push(r))?;
        }
        // holder = ctx (RCX = ilk Win64 argümanı).
        e(a.mov(holder, rcx))?;
        // flags-in
        e(a.push(qword_ptr(holder + 128i64)))?;
        e(a.popfq())?;
        // GPR'leri yükle (RSP ve holder hariç).
        for (i, &r) in regs.iter().enumerate() {
            if i == RSP_IDX || i == holder_idx {
                continue;
            }
            e(a.mov(r, qword_ptr(holder + (8 * i as i64))))?;
        }
        // Orijinal komut.
        a.db(native).map_err(|x| x.to_string())?;
        // flags'ı yakala, GPR'leri geri yaz.
        e(a.pushfq())?;
        for (i, &r) in regs.iter().enumerate() {
            if i == RSP_IDX || i == holder_idx {
                continue;
            }
            e(a.mov(qword_ptr(holder + (8 * i as i64)), r))?;
        }
        e(a.pop(qword_ptr(holder + 128i64)))?;
        // Callee-saved'ı geri yükle.
        for r in callee_saved.iter().rev() {
            e(a.pop(*r))?;
        }
        e(a.ret())?;

        a.assemble(0x1000).map_err(|x| x.to_string())
    }

    fn gpr_table() -> [AsmRegister64; 16] {
        [
            rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
        ]
    }

    fn gpr_index(r: Register) -> Option<usize> {
        Some(match r {
            Register::RAX => 0,
            Register::RCX => 1,
            Register::RDX => 2,
            Register::RBX => 3,
            Register::RSP => 4,
            Register::RBP => 5,
            Register::RSI => 6,
            Register::RDI => 7,
            Register::R8 => 8,
            Register::R9 => 9,
            Register::R10 => 10,
            Register::R11 => 11,
            Register::R12 => 12,
            Register::R13 => 13,
            Register::R14 => 14,
            Register::R15 => 15,
            _ => return None,
        })
    }

    // rflags bit konumları.
    const CF: u64 = 1 << 0;
    const PF: u64 = 1 << 2;
    const ZF: u64 = 1 << 6;
    const SF: u64 = 1 << 7;
    const OF: u64 = 1 << 11;

    fn compose_rflags(s: &VmState) -> u64 {
        let mut f = 1 << 1; // reserved bit daima 1
        if s.cf {
            f |= CF;
        }
        if s.pf {
            f |= PF;
        }
        if s.zf {
            f |= ZF;
        }
        if s.sf {
            f |= SF;
        }
        if s.of {
            f |= OF;
        }
        f
    }

    fn decompose_rflags(s: &mut VmState, f: u64) {
        s.cf = f & CF != 0;
        s.pf = f & PF != 0;
        s.zf = f & ZF != 0;
        s.sf = f & SF != 0;
        s.of = f & OF != 0;
    }
}
