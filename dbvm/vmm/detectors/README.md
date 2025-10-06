# DBVM Usermode Detector CLI

Build a small CLI that detects Cheat Engine's DBVM from usermode.

Contents:
- `dbvm_detect.h`/`dbvm_detect.c`: detection library
- `dbvm_detect_cli.c`: CLI tool that prints detection summary

Build (CMake):

1) From repo root:

```
cmake -S . -B build
cmake --build build --config Release
```

2) Run the CLI:

```
build/Release/dbvm_detect_cli.exe
```

Output fields:
- `result`: NO_HYPERVISOR | DBVM_CONFIRMED | OTHER_HYPERVISOR | DBVM_SUSPECT | INDETERMINATE
- `dbvm_version`: when DBVM_CONFIRMED, 0xCE0000 | version low 24 bits
- `hv_present_bit`: CPUID.1:ECX[31]
- `vmcall_ud_cycles`: avg cycles for VMCALL/VMMCALL → injected #UD path
- `ud2_ud_cycles`: avg cycles for UD2 → #UD path
- `cpuid_0d_ecx_low16`: CPUID(0x0D,0).ECX low16
- `xcr0_low32`: XGETBV(0) low 32 bits
- `used_vmmcall`: 1 when AMD VMMCALL path used in positive handshake

Notes:
- The detector first attempts DBVM GetVersion handshake (VMCALL/VMMCALL) using default passwords.
- If that fails, it applies password-agnostic side-channels (timing deltas + CPUID/XGETBV invariants).
- On systems with Hyper‑V or other HVs, `hv_present_bit=1` and no DBVM signature → `OTHER_HYPERVISOR`.
- The timing test uses modest iteration count (64) to keep it fast. Increase in `dbvm_detect.c` if needed.

