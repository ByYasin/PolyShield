# PolyShield

> A 100% native (Rust), web-free code virtualization / obfuscation tool.

PolyShield takes a compiled `.exe` / `.dll` (PE) or ELF binary, lists its
functions, and produces a hardened output where selected functions are
**virtualized** (lifted to a custom VM bytecode) and **polymorphically armored**.

## Crates

| Crate       | Role                                                            |
|-------------|----------------------------------------------------------------|
| `poly-core` | PE/ELF parsing + function symbol mapping                       |
| `poly-vm`   | Custom VM: x86-64 → IR lift, encode, interpret, polymorphism   |
| `poly-rt`   | Runtime: self-encrypting execution (RDRAND), anti-debug, loader |
| `poly-pack` | Repacker: embed armored payload into PE/ELF (`.pshld` section) |
| `poly-macros` | `#[poly_virtualize]` / `#[poly_obfuscate]` inline markers    |
| `poly-cli`  | Command-line interface                                          |
| `poly-gui`  | Desktop "cyber cockpit" UI (egui)                              |

Pipeline: `parse → lift → polymorphic armor → embed (PE/ELF) → loader → self-encrypting VM`.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for details.

## Quick Start

```bash
cargo build
cargo test

# Inspect a binary (summary + function list)
cargo run -p poly-cli -- inspect path/to/target.dll

# Virtualize a function (lift to VM bytecode)
cargo run -p poly-cli -- virtualize path/to/target.dll --addr 0x180001440 --disasm

# Polymorphic armor — each seed yields a different output
cargo run -p poly-cli -- virtualize path/to/target.dll --addr 0x180001440 --variants 5

# Desktop UI — drag a file onto the window
cargo run -p poly-gui
```

## Inline Protection

```rust
use poly_macros::poly_virtualize;

#[poly_virtualize]                 // exported as polyv_check_license
pub extern "C" fn check_license(key: u64) -> u64 { /* ... */ }
```

Build, then let the autopilot find and armor the marked symbols:

```bash
cargo build -p license-demo
cargo run -p poly-cli -- shield target/debug/license_demo.dll --min-coverage 0.85
```

## Repacking & Loader

```bash
# Embed armored payload as a new .pshld section (still a valid, loadable binary)
cargo run -p poly-cli -- pack target/debug/license_demo.dll -o shielded.dll

# Run an embedded function in the VM and check it matches the native call (Windows)
cargo run -p poly-cli -- verify-loader shielded.dll --function poly_demo_add --arg 100 --arg 23

# Auto-protect every function in one call; calls transparently route to the VM (Windows)
cargo run -p auto-protect-demo -- shielded.dll
```

## Status

All core phases work end-to-end and are verified against native results
(see `cargo test`, 60+ tests). Honest limitations are documented in
[`docs/RESISTANCE.md`](docs/RESISTANCE.md):

- **Lifter** covers a broad x86-64 integer subset; SSE/AVX, indirect calls and
  REP fall back to `Native` escapes (reported in the coverage score).
- **No hypervisor**: VT-x/EPT needs Ring-0; anti-debug is user-mode
  (PEB, DR0-DR7, RDTSC).
- **Transparent in-process redirection** is proven as a PoC (`transparent-hook`,
  `auto-protect-demo`). The remaining productization step is a packer-embedded,
  portable PIC shellcode with multi-signature ABI marshalling.

## License

MIT
