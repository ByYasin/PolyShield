//! PolyShield Custom Virtual CPU — komut seti mimarisi (ISA).
//!
//! Tasarım: **register tabanlı** bir sanal makine. 16 sanal genel amaçlı
//! register (`v0..v15`), x86-64 GPR'leriyle (RAX..R15) birebir eşlenir; bu,
//! makine kodunu lift etmeyi ve doğrulamayı basitleştirir. Ayrıca sanal bir
//! bayrak (flags) durumu ve sanal komut işaretçisi (vip) vardır.
//!
//! Bu modül yalnızca **veri tiplerini** tanımlar; lifting `lifter`, çalıştırma
//! `interp`, serileştirme `encoder` modüllerindedir.

use serde::{Deserialize, Serialize};

/// Sanal genel amaçlı register. İndeks, x86-64 ModRM sırasını izler:
/// 0=RAX 1=RCX 2=RDX 3=RBX 4=RSP 5=RBP 6=RSI 7=RDI 8..15=R8..R15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VReg(pub u8);

impl VReg {
    pub const RAX: VReg = VReg(0);
    pub const RCX: VReg = VReg(1);
    pub const RDX: VReg = VReg(2);
    pub const RBX: VReg = VReg(3);
    pub const RSP: VReg = VReg(4);
    pub const RBP: VReg = VReg(5);
    pub const RSI: VReg = VReg(6);
    pub const RDI: VReg = VReg(7);

    pub const COUNT: usize = 16;

    /// İndeksin geçerli (0..16) olup olmadığını kontrol eder.
    pub fn is_valid(self) -> bool {
        (self.0 as usize) < Self::COUNT
    }

    /// Okunabilir ad (`v0` yerine x86 muadili).
    pub fn name(self) -> &'static str {
        const NAMES: [&str; 16] = [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ];
        NAMES.get(self.0 as usize).copied().unwrap_or("v?")
    }
}

/// Operand boyutu (byte cinsinden). x86 8/16/32/64-bit erişimleri modeller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpSize {
    Byte,
    Word,
    Dword,
    Qword,
}

impl OpSize {
    /// Byte cinsinden boyut (1/2/4/8).
    pub fn bytes(self) -> u32 {
        match self {
            OpSize::Byte => 1,
            OpSize::Word => 2,
            OpSize::Dword => 4,
            OpSize::Qword => 8,
        }
    }

    /// Bit cinsinden boyut.
    pub fn bits(self) -> u32 {
        self.bytes() * 8
    }

    /// Bu boyuta karşılık gelen değer maskesi (örn. Dword → 0xFFFF_FFFF).
    pub fn mask(self) -> u64 {
        match self {
            OpSize::Qword => u64::MAX,
            other => (1u64 << other.bits()) - 1,
        }
    }

    /// En anlamlı bit (işaret biti) maskesi.
    pub fn sign_bit(self) -> u64 {
        1u64 << (self.bits() - 1)
    }

    /// Byte sayısından OpSize üretir (8'e yuvarlanır).
    pub fn from_bytes(n: u32) -> OpSize {
        match n {
            1 => OpSize::Byte,
            2 => OpSize::Word,
            4 => OpSize::Dword,
            _ => OpSize::Qword,
        }
    }

    /// Kompakt kodlama için 2-bitlik kod (0..3).
    pub fn code(self) -> u8 {
        match self {
            OpSize::Byte => 0,
            OpSize::Word => 1,
            OpSize::Dword => 2,
            OpSize::Qword => 3,
        }
    }

    pub fn from_code(code: u8) -> OpSize {
        match code & 0b11 {
            0 => OpSize::Byte,
            1 => OpSize::Word,
            2 => OpSize::Dword,
            _ => OpSize::Qword,
        }
    }
}

/// Koşullu dallanma / bayrak koşulları (x86 condition code'larıyla aynı küme).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cond {
    O,  // overflow
    No, // not overflow
    B,  // below (CF=1)
    Ae, // above or equal (CF=0)
    E,  // equal (ZF=1)
    Ne, // not equal (ZF=0)
    Be, // below or equal
    A,  // above
    S,  // sign
    Ns, // not sign
    P,  // parity
    Np, // not parity
    L,  // less (signed)
    Ge, // greater or equal (signed)
    Le, // less or equal (signed)
    G,  // greater (signed)
}

impl Cond {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Option<Cond> {
        use Cond::*;
        const ALL: [Cond; 16] = [O, No, B, Ae, E, Ne, Be, A, S, Ns, P, Np, L, Ge, Le, G];
        ALL.get(code as usize).copied()
    }

    pub fn mnemonic(self) -> &'static str {
        use Cond::*;
        match self {
            O => "o",
            No => "no",
            B => "b",
            Ae => "ae",
            E => "e",
            Ne => "ne",
            Be => "be",
            A => "a",
            S => "s",
            Ns => "ns",
            P => "p",
            Np => "np",
            L => "l",
            Ge => "ge",
            Le => "le",
            G => "g",
        }
    }
}

/// Bellek erişim operandı: `[base + index*scale + disp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemRef {
    pub base: Option<VReg>,
    pub index: Option<VReg>,
    pub scale: u8, // 1, 2, 4 veya 8
    pub disp: i64,
}

/// Bir VM komutunun operandı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmOperand {
    Reg(VReg),
    /// İşaretli olarak saklanan anlık değer (immediate).
    Imm(i64),
    Mem(MemRef),
    /// Dallanma hedefi: program içindeki komut indeksi (vip).
    /// Lift sırasında mutlak x86 adresi bu indekse çözülür.
    Label(u32),
}

/// VM işlem kodu (opcode). Kompakt bytecode'da her biri `OpcodeMap` üzerinden
/// (1.3'te rastgele) bir byte'a eşlenir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmOp {
    Mov,
    Lea,
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Imul,
    Neg,
    Not,
    Inc,
    Dec,
    Cmp,
    Test,
    Push,
    Pop,
    Jmp,
    Jcc,
    Call,
    Ret,
    Nop,
    /// Lift edilemeyen orijinal x86 komutu — ham byte'larıyla saklanır
    /// (gerçek virtualizer'lardaki "native escape" mekanizması).
    Native,
    /// VM'den çıkış (durdurma).
    VmExit,
    // --- genişletilmiş komut seti (Faz 5+) ---
    Rol,
    Ror,
    /// Zero-extend taşıma (movzx); `src_size` kaynağı belirler.
    Movzx,
    /// Sign-extend taşıma (movsx/movsxd/cdqe/cwde/cbw); `src_size` kaynağı belirler.
    Movsx,
    /// Koşullu taşıma (cmovcc); `cond` koşulu belirler.
    Cmov,
    /// Koşula göre byte ayarla (setcc); `cond` koşulu belirler.
    Setcc,
    /// Bit testi (CF = bit). Bts/Btr/Btc ayrıca biti değiştirir.
    Bt,
    Bts,
    Btr,
    Btc,
    /// İki operandı takas eder (xchg).
    Xchg,
    /// Byte sırasını ters çevirir (bswap).
    Bswap,
    /// İşaretsiz çarpma: RDX:RAX = RAX * src.
    Mul,
    /// İşaretli tek-operandlı çarpma: RDX:RAX = RAX * src.
    Imul1,
    /// İşaretsiz bölme: RAX = RDX:RAX / src, RDX = kalan.
    Div,
    /// İşaretli bölme: RAX = RDX:RAX / src, RDX = kalan.
    Idiv,
    /// RAX'in işaretini RDX'e yayar (cqo/cdq/cwd).
    Cqo,
    /// Çift-duyarlı sola kaydırma (shld dst, src, count).
    Shld,
    /// Çift-duyarlı sağa kaydırma (shrd dst, src, count).
    Shrd,
    /// Takas-ve-topla (xadd).
    Xadd,
    /// Karşılaştır-ve-takas (cmpxchg, örtük RAX).
    Cmpxchg,
}

impl VmOp {
    /// Tüm opcode'lar — `OpcodeMap` ve testler için sabit sıra (declaration order).
    pub const ALL: [VmOp; 47] = [
        VmOp::Mov,
        VmOp::Lea,
        VmOp::Add,
        VmOp::Sub,
        VmOp::And,
        VmOp::Or,
        VmOp::Xor,
        VmOp::Shl,
        VmOp::Shr,
        VmOp::Sar,
        VmOp::Imul,
        VmOp::Neg,
        VmOp::Not,
        VmOp::Inc,
        VmOp::Dec,
        VmOp::Cmp,
        VmOp::Test,
        VmOp::Push,
        VmOp::Pop,
        VmOp::Jmp,
        VmOp::Jcc,
        VmOp::Call,
        VmOp::Ret,
        VmOp::Nop,
        VmOp::Native,
        VmOp::VmExit,
        VmOp::Rol,
        VmOp::Ror,
        VmOp::Movzx,
        VmOp::Movsx,
        VmOp::Cmov,
        VmOp::Setcc,
        VmOp::Bt,
        VmOp::Bts,
        VmOp::Btr,
        VmOp::Btc,
        VmOp::Xchg,
        VmOp::Bswap,
        VmOp::Mul,
        VmOp::Imul1,
        VmOp::Div,
        VmOp::Idiv,
        VmOp::Cqo,
        VmOp::Shld,
        VmOp::Shrd,
        VmOp::Xadd,
        VmOp::Cmpxchg,
    ];

    /// Sıralı tablo indeksini döndürür (OpcodeMap için).
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn mnemonic(self) -> &'static str {
        use VmOp::*;
        match self {
            Mov => "mov",
            Lea => "lea",
            Add => "add",
            Sub => "sub",
            And => "and",
            Or => "or",
            Xor => "xor",
            Shl => "shl",
            Shr => "shr",
            Sar => "sar",
            Imul => "imul",
            Neg => "neg",
            Not => "not",
            Inc => "inc",
            Dec => "dec",
            Cmp => "cmp",
            Test => "test",
            Push => "push",
            Pop => "pop",
            Jmp => "jmp",
            Jcc => "j",
            Call => "call",
            Ret => "ret",
            Nop => "nop",
            Native => "native",
            VmExit => "vmexit",
            Rol => "rol",
            Ror => "ror",
            Movzx => "movzx",
            Movsx => "movsx",
            Cmov => "cmov",
            Setcc => "set",
            Bt => "bt",
            Bts => "bts",
            Btr => "btr",
            Btc => "btc",
            Xchg => "xchg",
            Bswap => "bswap",
            Mul => "mul",
            Imul1 => "imul",
            Div => "div",
            Idiv => "idiv",
            Cqo => "cqo",
            Shld => "shld",
            Shrd => "shrd",
            Xadd => "xadd",
            Cmpxchg => "cmpxchg",
        }
    }
}

/// Tek bir VM komutu (orta seviye IR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInstr {
    pub op: VmOp,
    pub size: OpSize,
    /// 0..2 operand. Sıralama: hedef (dst) önce, sonra kaynak (src).
    pub operands: Vec<VmOperand>,
    /// `Jcc`/`Cmov`/`Setcc` için koşul.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cond: Option<Cond>,
    /// `Movzx`/`Movsx` için kaynak operand boyutu (hedef boyutu `size`'dir).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub src_size: Option<OpSize>,
    /// `Native` için orijinal x86 byte'ları.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub native_bytes: Vec<u8>,
    /// Orijinal komutun x86 adresi (eşleme/hata ayıklama için, 0 = bilinmiyor).
    #[serde(default)]
    pub orig_addr: u64,
}

impl VmInstr {
    /// Operandsız bir komut oluşturur.
    pub fn new(op: VmOp, size: OpSize) -> Self {
        VmInstr {
            op,
            size,
            operands: Vec::new(),
            cond: None,
            src_size: None,
            native_bytes: Vec::new(),
            orig_addr: 0,
        }
    }

    pub fn with_operands(mut self, ops: impl IntoIterator<Item = VmOperand>) -> Self {
        self.operands = ops.into_iter().collect();
        self
    }

    pub fn with_cond(mut self, cond: Cond) -> Self {
        self.cond = Some(cond);
        self
    }

    pub fn with_src_size(mut self, src_size: OpSize) -> Self {
        self.src_size = Some(src_size);
        self
    }

    pub fn at(mut self, addr: u64) -> Self {
        self.orig_addr = addr;
        self
    }

    /// İlk (hedef) operand.
    pub fn dst(&self) -> Option<&VmOperand> {
        self.operands.first()
    }

    /// İkinci (kaynak) operand.
    pub fn src(&self) -> Option<&VmOperand> {
        self.operands.get(1)
    }
}
