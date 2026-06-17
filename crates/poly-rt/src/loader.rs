//! Korumalı modül yükleyici — yeniden kullanılabilir runtime API'si.
//!
//! Bir programa gömülebilen loader: `.pshld` içeren bir PE/ELF'i okur, gömülü VM
//! programlarını tohumdan kurtarır ve korumalı fonksiyonları Win64 ABI ile
//! [`SecureVm`] üzerinde çalıştırır. Böylece geliştirici, korumalı bir fonksiyonu
//! native çağırmak yerine `module.call("ad", &args)` ile çalıştırabilir.
//!
//! > Dürüst sınır: bu, çağrıyı şeffafça yönlendiren otomatik bir stub değildir;
//! > geliştirici dispatch'i açıkça yapar (protector SDK modeli).

use std::collections::HashMap;

use poly_core::SymbolVisibility;
use poly_vm::{ArmoredProgram, RegPerm, VReg, VmInstr, VmState};

use crate::{HwRng, SecureVm};

/// Win64 tamsayı argüman register'ları: RCX, RDX, R8, R9.
const ARG_REGS: [VReg; 4] = [VReg::RCX, VReg::RDX, VReg(8), VReg(9)];

struct ProtectedFn {
    instrs: Vec<VmInstr>,
    perm: RegPerm,
}

/// Yüklenmiş korumalı modül.
pub struct ProtectedModule {
    funcs: HashMap<String, ProtectedFn>,
    /// (sanal_adres, bytes) — RIP-relative okumalar için salt-okunur section'lar.
    image: Vec<(u64, Vec<u8>)>,
}

impl ProtectedModule {
    /// Diskteki bir packed dosyayı yükler.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("okunamadı: {e}"))?;
        Self::from_bytes(&bytes)
    }

    /// Bellekteki packed binary'i yükler.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let info = poly_core::parse_bytes(bytes, None).map_err(|e| format!("parse: {e}"))?;

        let section = info
            .sections
            .iter()
            .find(|s| s.name == ".pshld")
            .ok_or_else(|| "'.pshld' yok — dosya pack'lenmemiş".to_string())?;
        let start = section.file_offset as usize;
        let end = (start + section.raw_size as usize).min(bytes.len());
        let entries = poly_pack::decode(&bytes[start..end]).map_err(|e| format!("pshld: {e}"))?;

        let mut rva_name = HashMap::new();
        for f in &info.functions {
            if f.visibility == SymbolVisibility::Exported {
                rva_name.insert((f.virtual_address - info.image_base) as u32, f.name.clone());
            }
        }

        let mut funcs = HashMap::new();
        for e in &entries {
            let armored = ArmoredProgram {
                version: 1,
                seed: e.seed,
                instr_count: e.instr_count as usize,
                payload: e.payload.clone(),
            };
            let (instrs, perm) = armored.recover().map_err(|x| format!("recover: {x}"))?;
            let name = rva_name
                .get(&e.rva)
                .cloned()
                .unwrap_or_else(|| format!("sub_{:x}", e.rva));
            funcs.insert(name, ProtectedFn { instrs, perm });
        }

        let mut image = Vec::new();
        for s in &info.sections {
            let off = s.file_offset as usize;
            let rs = s.raw_size as usize;
            if rs == 0 {
                continue;
            }
            if let Some(data) = bytes.get(off..off.saturating_add(rs)) {
                image.push((s.virtual_address, data.to_vec()));
            }
        }

        Ok(ProtectedModule { funcs, image })
    }

    /// Korumalı fonksiyon adları.
    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.funcs.keys()
    }

    /// Verilen alt-dizeyle eşleşen tam fonksiyon adını döndürür.
    pub fn resolve_name(&self, needle: &str) -> Option<String> {
        self.funcs.keys().find(|k| k.contains(needle)).cloned()
    }

    /// Korumalı fonksiyonu Win64 ABI ile VM'de çalıştırır; dönüş değeri (RAX).
    pub fn call(&self, name: &str, args: &[u64]) -> Result<u64, String> {
        let f = self
            .funcs
            .iter()
            .find(|(k, _)| k.contains(name))
            .map(|(_, v)| v)
            .ok_or_else(|| format!("'{name}' korumalı fonksiyon bulunamadı"))?;

        let mut vm = SecureVm::new(&f.instrs, HwRng::auto());
        let mut st = VmState::with_default_stack();
        // Native-escape trampoline'i tak (güvenli alt küme; platform desteklemiyorsa
        // escape yine hata verir).
        st.set_native_handler(Box::new(crate::TrampolineHandler::new()));
        for (va, data) in &self.image {
            st.add_image_region(*va, data.clone());
        }
        for (i, &a) in args.iter().enumerate().take(4) {
            st.set_reg_full(f.perm.map(ARG_REGS[i]), a);
        }
        vm.run(&mut st, 1_000_000)
            .map_err(|e| format!("yürütme: {e}"))?;
        Ok(st.reg(f.perm.map(VReg::RAX)))
    }
}
