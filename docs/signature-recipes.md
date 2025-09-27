# Signature Recipes (IDA SigMaker) — Stable Anchors and Patterns

This guide provides step‑by‑step signatures you can produce with IDA SigMaker (or equivalent) to re‑identify the key functions and sites described in docs/ce-detection-map.md across builds. Prefer small, distinctive byte sequences with wildcards for RIP‑relative displacements and addresses.

General tips
- Build multiple short signatures for each target (e.g., 2–4 per function) using different unique features.
- Keep immediates that are very unlikely to change (e.g., `0x00BADD00D`, `0x40000006`, `cmp ax,25h`) and mask displacements.
- For large VM blocks, sign the SSE XOR stage with the two QWORD constants and a nearby `syscall` cluster.
- Save the resulting patterns with meaningful names (e.g., TLS_KILL_CPUID_CMP, TLS_KILL_NTTERM, VMCORE_QWORDS, IMPORT_RESOLVER_APISETS, EXIT_WRAPPER, WER_SCAFFOLD).


## TLS Kill Gate (TlsCallback_0)

Function: 0x7ff93430fab0; kill site at 0x7ff93430ff46–0x7ff93430ff52

Pattern A — CPUID hypervisor leaf (allow wildcards for stack offsets):
```
* mov eax, 06 00 00 40
* 31 C9                  ; xor ecx, ecx
* 0F A2                  ; cpuid
```

Pattern B — Fold + compare (encoding may vary; keep immediate 0x25):
```
* 66 0F 3A 16 ?? 04      ; pextrw ecx, xmm0, 4
* 31 C8                  ; xor eax, ecx (or 31 C1 depending on order)
* 66 3D 25 00            ; cmp ax, 25h
```

Pattern C — Kill tail (keep ExitStatus):
```
* 48 C7 C1 FF FF FF FF   ; mov rcx, -1
* BA 0D D0 AD 0B         ; mov edx, 0x0BADD00D
* FF 15 ?? ?? ?? ??       ; call qword ptr [rip+disp]  ; NtTerminateProcess
```


## Import Resolver (API‑set aware loader)

Function: 0x7ff9343a23e0

Pattern A — LoadLibraryExW with LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800):
```
* 48 8D 15 ?? ?? ?? ??    ; lea rdx, [apiset_wstr]
* 49 C7 C0 00 00 00 00    ; mov r8, 0
* 41 B9 00 08 00 00       ; mov r9d, 0x800
* FF 15 ?? ?? ?? ??        ; call LoadLibraryExW
```

Pattern B — Fallback on error 87 (INVALID_PARAMETER):
```
* FF 15 ?? ?? ?? ??        ; call GetLastError
* 83 F8 57                 ; cmp eax, 87
* 75 ??                    ; jnz ...
* FF 15 ?? ?? ?? ??        ; call LoadLibraryExW (flags = 0)
```

Pattern C — Terminal GetProcAddress:
```
* FF 15 ?? ?? ?? ??        ; call GetProcAddress
* 48 0F C9 ??              ; ror/xor dance followed by xchg into table
```


## VM Core (Export hashing + syscalls)

Function: 0x7ff934350cb0

Pattern A — QWORD constants + SSE XOR (anchor):
```
* 48 B8 39 48 00 0A 3F 8F AE C5   ; mov rax, 0xC5AE8F3F0A004839
* 48 B8 76 0D 65 C6 CA 4C 92 E5   ; mov rax, 0xE5924CCAC6650D76
... (store into locals) ...
* 0F 57 ??                         ; xorps
```

Pattern B — Syscall cluster (put multiple near each other):
```
* 0F 05   ; syscall
* ...
* 0F 05   ; syscall
```

Pattern C — Export hash inner loop (keep multiplier; bytes may vary by compiler):
```
* ... FNV-like mixing ...
* imul r?, r?, 0x0000000008000001CB
```


## Exit Wrapper (TerminateProcess → ExitProcess)

Function: 0x7ff93439CA40

Pattern:
```
* FF 15 ?? ?? ?? ??      ; call GetCurrentProcess
* 48 89 C1               ; mov rcx, rax
* 8B D3                  ; mov edx, ebx
* FF 15 ?? ?? ?? ??      ; call TerminateProcess
* 8B CB                  ; mov ecx, ebx
* FF 15 ?? ?? ?? ??      ; call ExitProcess
```


## Clean Crash Scaffold (UnhandledExceptionFilter route)

Function: 0x7ff93439AA20

Pattern:
```
* FF 15 ?? ?? ?? ??      ; call RtlCaptureContext
* FF 15 ?? ?? ?? ??      ; call RtlLookupFunctionEntry
* FF 15 ?? ?? ?? ??      ; call RtlVirtualUnwind
* FF 15 ?? ?? ?? ??      ; call SetUnhandledExceptionFilter
* FF 15 ?? ?? ?? ??      ; call UnhandledExceptionFilter
```


## Top‑of‑Usermode Literal

File offset: 0x37B6 (FF FF FF FF FF 7F 00 00). Not mapped in the analyzed IDB; either map the raw bytes as a segment or search at the file level.


## Workflow with SigMaker

1) Open target function in IDA (e.g., TLS callback). Select a short, unique instruction run around the distinctive immediates.
2) Run SigMaker → Create signature. Mask RIP‑relative offsets (wildcards).
3) Save your pattern with a meaningful name, and repeat with 2–3 complementary slices (increase resiliency).
4) Repeat for resolver, VM core (use the QWORD constants + one `syscall` nearby), exit wrapper, and crash scaffold.
5) Store these signatures in a central place and re‑use on new builds. If a signature breaks, try the alternate slice.


## Export‑Hash CSV (for quick matching)

Use tools/hash_exports.py to generate a name→hash table from system DLLs:

```
python tools/hash_exports.py user32.dll kernel32.dll ntdll.dll dwmapi.dll -o export-hashes.csv
```

Then, when you see folded-constant compares (e.g., 0x7EA84848) in the VM, compare against this CSV to resolve which export name is being matched.

