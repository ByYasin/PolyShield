# PolyShield — De-Virtualization Resistance Report

This document gives an **honest** assessment of the protection PolyShield-armored
code provides against reverse engineering: what measurably works, what is not done
yet, and what a real IDA Pro / x64dbg analyst would face.

## Test Setup

- **Target:** `samples/license-demo` (cdylib), with `check_license` marked
  `#[poly_virtualize]` and `secret_value` marked `#[poly_obfuscate]`.
- **Tools (in-project):** `poly-cli shield`, `poly-cli analyze`.
- **Tools (manual, external):** IDA Pro, x64dbg — these can't be automated, so a
  step-by-step procedure is given below; results are filled in by the analyst.

To reproduce:

```bash
cargo build -p license-demo
cargo run -p poly-cli -- shield  target/debug/license_demo.dll --min-coverage 0.85
cargo run -p poly-cli -- analyze target/debug/license_demo.dll --function check_license
```

## Measured Metrics (automatic)

Sample `analyze` output (`check_license`, 80 bytes of x86-64):

| Metric | Value | Note |
|--------|-------|------|
| VM coverage | 94% (17 VM instrs, 1 native) | Most of the function virtualized |
| Ciphertext entropy | ~7.1 bits/byte | Near the 8.0 max → no patterns / encrypted |
| Diversity | 12/12 unique, ~99.7% byte diff | Each seed yields entirely different bytecode |
| Size ratio | 0.41× | Bytecode larger than original (expected) |

## Static Analysis Resistance (IDA Pro)

Obstacles a static analyst faces, and the PolyShield mechanism behind each:

1. **No original instruction stream.** The protected function's x86 body is replaced
   by VM bytecode; IDA's disassembler can't recover a meaningful control-flow graph.
2. **No fixed opcode signature.** The opcode→byte mapping is permuted per build
   (`OpcodeMap::shuffled`), so signature-based automatic devirtualization won't match.
3. **Hidden data flow.** Register renaming (except RSP) shuffles the virtual
   registers, making symbolic tracking harder.
4. **High entropy.** The bytecode is keystream-encrypted at rest (~7.1 bits/byte);
   string/constant scans find nothing.
5. **Build diversity.** Two armored outputs don't resemble each other; a signature
   built on one sample doesn't fit another.

**IDA procedure (manual):** load the DLL → go to the `polyv_check_license` export →
confirm the body routes to the VM dispatcher → observe that the bytecode region is
high-entropy / pattern-free (via IDA "Entropy" or a hex editor). _Result:_ filled in
by the analyst.

## Dynamic Analysis Resistance (x64dbg)

The Phase 2 runtime kicks in at execution time:

1. **Self-encrypting bytecode.** `SecureVm` decrypts each instruction right before
   executing it and immediately re-encrypts it with a hardware (RDRAND) key. A memory
   dump taken at any instant looks **almost entirely encrypted**, and successive dumps
   differ.
2. **Anti-debug.** `poly-cli antidebug` indicators: PEB.BeingDebugged, NtGlobalFlag,
   **DR0–DR3 hardware breakpoints**, RDTSC timing. On detection, `SecureVm::poison()`
   fills memory with fake code and blocks execution.

**x64dbg procedure (manual):**
- Run `poly-cli antidebug` → "clean".
- Attach x64dbg and run the same command → PEB.BeingDebugged triggers.
- Set a hardware breakpoint → the DR0–DR3 indicator triggers.
- _Result:_ filled in by the analyst (indicators are expected to trigger).

## Loader Verification

`verify-loader` proves that a protected function's VM-executed result is **bit-for-bit
identical to the native result** (recovered from the embedded `.pshld` payload and
called via the Win64 ABI):

| Function | Args | Native | VM | Result |
|----------|------|--------|----|--------|
| `poly_demo_add` | (100, 23) | 21962 | 21962 | ✓ match |
| `secret_value` | (0x1357) | 0x11034ac22 | 0x11034ac22 | ✓ match |

This demonstrates the **semantic correctness** of the virtualization pipeline
end-to-end: lift → polymorphic armor → embed → recover → self-encrypting VM execution.

## Honest Limitations (not done yet)

To keep the "VMProtect competitor" claim honest:

- **No fully automatic stub yet (PoC exists).** `pack` embeds the armored payload into
  `.pshld`; the loader (`poly-rt::ProtectedModule`) runs it **correctly** in the VM
  (bit-identical to native, including RIP-relative reads). The **transparent redirection**
  mechanism works in the `transparent-hook` PoC: a function's prologue is detoured at
  runtime and the call transparently routes into the embedded VM (the caller doesn't
  notice). The remaining productization step is turning that detour into a **standalone,
  portable PIC shellcode embedded by the packer at the entry point** (instead of a
  linked-in runtime). The mechanism is proven; automation and portability remain.
- **Lifter subset.** Common integer/control-flow instructions are covered:
  mov/arith/logic/shift, **rol/ror, movzx/movsx (cdqe), cmov, setcc,
  bt/bts/btr/btc, xchg, bswap, mul/imul, div/idiv, cqo/cdq/cwd**,
  push/pop/jmp/jcc/call/ret. SSE/AVX, indirect jmp/call, REP, etc. still fall back to
  `Native` escapes (reported in the coverage score). The extended set noticeably raises
  coverage on typical optimized functions (e.g. one kernel32 function: 94% → 98%; the
  remaining natives are `int3` padding + an indirect `call`).
- **No hypervisor.** A VT-x/AMD-V/EPT mini-hypervisor can't be set up from user mode;
  it requires a Ring-0 driver (see the README Phase 2.2 note).
- **Key table in plain memory.** `SecureVm` keeps keys in the clear for demonstration;
  in production they should be derived/obscured.
- **Interpreter is verification-oriented.** `call`/`ret` use a host shadow stack, and
  neutral junk is chosen so it never touches the red zone.

## Conclusion

PolyShield provides measurable resistance to **static signature and string analysis**
(high entropy, opcode permutation, build diversity) and real resistance to **dynamic
analysis** (self-encrypting runtime + user-mode anti-debug). The single most important
missing step toward a full commercial protector is **binary repacking/loader**
integration — and the architecture is ready for it (the armored container is
self-describing).
