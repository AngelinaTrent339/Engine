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
build/Release/dbvm_detect_cli.exe --pause
```

Options:
- `--pause`: wait for keypress before exit (useful when launching manually)
- `--json`: print JSON output instead of text
- `--policy` + `--policy-threshold=<pct>`: print a simple likelihood line based on timing ratio

Output fields:
- `result`: NO_HYPERVISOR | DBVM_CONFIRMED | OTHER_HYPERVISOR | DBVM_SUSPECT | INDETERMINATE
- `dbvm_version`: when DBVM_CONFIRMED, 0xCE0000 | version low 24 bits
- `hv_present_bit`: CPUID.1:ECX[31]
- `vmcall_ud_cycles`: avg cycles for VMCALL/VMMCALL → injected #UD path
- `ud2_ud_cycles`: avg cycles for UD2 → #UD path
- `cpuid_0d_ecx_low16`: CPUID(0x0D,0).ECX low16
- `xcr0_low32`: XGETBV(0) low 32 bits
- `used_vmmcall`: 1 when AMD VMMCALL path used in positive handshake

Timing and thresholds:
- The detector compares vmcall/vmmcall vs ud2 exception paths using percentiles (p50/p90/p99) with 256 samples each to reduce noise.
- Set `DBVM_SUSPECT_THRESHOLD_PCT` (default 40) to adjust how much slower vmcall must be versus ud2 at both p50 and p90.
- Set `DBVM_CONFIRM_RATIO_X100` (default 190) to escalate very strong timing signals to `DBVM_CONFIRMED` when the mean ratio exceeds this x100 value.

Notes:
- The detector first attempts DBVM GetVersion handshake (VMCALL/VMMCALL) using default passwords.
- If that fails, it applies password-agnostic side-channels (timing deltas + CPUID/XGETBV invariants).
- On systems with Hyper‑V or other HVs, `hv_present_bit=1` and no DBVM signature → `OTHER_HYPERVISOR`.
- The timing test uses modest iteration count (64) to keep it fast. Increase in `dbvm_detect.c` if needed.
