# PolyShield — Architecture

This document summarizes PolyShield's end-to-end architecture, data flow, and
design decisions, so a new developer can grasp the codebase quickly.

## Overall flow

```
 .exe/.dll/.so
      │  poly-core: PE/ELF parse → function symbol map
      ▼
 FunctionSymbol{ addr, size, file_offset, ... }
      │  poly-vm::lifter: machine code → VM IR (VmInstr) via iced-x86
      ▼
 VmInstr[]  (un-liftable instructions kept as VmOp::Native)
      │  poly-vm::polymorph::armor(seed): opcode perm + register rename
      │                                  + junk + keystream encryption
      ▼
 ArmoredProgram{ seed, payload }   (self-describing)
      │  poly-pack: embed into PE/ELF as a .pshld section
      ▼
 shielded.exe/.dll/.so
      │  poly-rt::ProtectedModule: recover from .pshld using the seed
      ▼
 poly-rt::SecureVm: per-instruction encrypted, re-encrypted each cycle (RDRAND)
      │  poly-vm::interp::step: single source of truth (run + SecureVm share it)
      ▼
 result (bit-identical to native; proven by verify-loader)
```

## Crates

| Crate | Responsibility |
|-------|----------------|
| **poly-core** | PE/ELF parsing, function symbol mapping (goblin). Read-only. |
| **poly-vm** | Custom VM: ISA (`isa`), lifter (`lifter`), encoder/opcode-map (`encoder`), interpreter (`interp`), polymorphic engine (`polymorph`), PRNG (`rng`). |
| **poly-rt** | Runtime: self-encrypting executor (`secure_vm`), anti-debug (`antidebug`), hardware RNG (`hwrng`), loader (`loader`), native-escape trampoline (`trampoline`), auto-protection (`autoprotect`). |
| **poly-pack** | Repacker: `.pshld` container (`container`) + PE (`pe`) / ELF (`elf`) section insertion. |
| **poly-macros** | `#[poly_virtualize]` / `#[poly_obfuscate]` — export markers for post-build discovery. |
| **poly-cli** | CLI wrapping the whole flow (`inspect`, `virtualize`, `shield`, `pack`, `unpack`, `run-protected`, `verify-loader`, `analyze`, `secure-run`, `antidebug`, `embed`). |
| **poly-gui** | egui "cyber cockpit" UI. |

Dependency direction: `poly-core` ← `poly-vm` ← `poly-rt` → (`poly-core`, `poly-pack`);
`poly-cli`/`poly-gui` wrap everything. No layering violations.

## Key design decisions

- **Disassembly-lift, not LLVM IR.** A compiled binary has no IR; the source is
  machine code (`iced-x86`). Un-liftable instructions are preserved **without loss**
  as `VmOp::Native`.
- **Single source of truth.** `interp::step` is used by both `run` and `SecureVm`;
  instruction semantics live in one place.
- **Self-describing container.** `ArmoredProgram` carries only a seed + encrypted
  payload; all transforms (`OpcodeMap`, `RegPerm`, keystream) are re-derived from the
  seed. This keeps `.pshld` small and the loader standalone.
- **Determinism.** All randomness comes from `SplitMix64`; same seed → same output
  (required for decode). Runtime cipher mutation, on the other hand, uses `HwRng`
  (RDRAND) and is non-deterministic.
- **Verifiability.** Each layer is proven against native results or by unit tests
  (`verify-loader`, hand-assembled tests, real `libc.so` / `kernel32`).

## Honest limitations (summary)

See [`RESISTANCE.md`](RESISTANCE.md) for details:

- **Lifter subset:** common integer/control-flow + rol/ror/movzx/movsx/cmov/setcc/
  bt*/xchg/bswap/mul/div/shld/shrd/xadd/cmpxchg/cqo. SSE/AVX, indirect calls, REP excluded.
- **VM memory model** is decoupled from the real address space (flat); RIP-relative
  reads are resolved via module image regions, but the native trampoline can only run
  **memory-free, GPR-only** escapes.
- **No hypervisor** (VT-x/EPT needs Ring-0); anti-debug is user-mode.
- **Automatic stub** mechanism is proven (detour + dispatcher), but the runtime is
  linked in and limited to a 1-arg signature; a packer-embedded portable PIC shellcode
  is the final productization step.

## Test strategy

- **Unit:** ISA/encoder round-trip, PRNG, demangle, container, ELF/PE section insertion.
- **Hand-assembled integration:** for each lifted instruction, x86 bytes → lift →
  interpret → expected result (no external compiler needed).
- **Real binaries:** kernel32 (coverage), libc.so (ELF section), host binary (parse).
- **End-to-end:** `verify-loader` native == VM; `auto-protect-demo` transparent routing.
- **CI:** fmt + clippy (`-D warnings`) + test + shield coverage gate (`.github/workflows/ci.yml`).
