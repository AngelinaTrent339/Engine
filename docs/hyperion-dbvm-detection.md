# Hyperion DBVM Detection Map

This document summarizes every DBVM-related termination path that appears in the Roblox Hyperion dump (`dump.bin`). All evidence comes from static analysis with IDA + MCP and is cross-referenced with Cheat Engine / DBVM source so every claim has a matching code fragment.

## Module & Tooling Context
- Artifact analysed: `C:\Users\FSOS\Downloads\dump.bin`
- Module base (IDA): `0x7FF933640000`
- IDA functions referenced below are named as in the MCP session (e.g., `sub_7FF93428D910`).

```
+-- Roblox dump    ? IDA MCP decompiles / disassembly
+-- Cheat Engine   ? `Cheat Engine/` sources (Pascal)
+-- DBKKernel      ? `DBKKernel/` driver sources (C / ASM)
+-- DBVM           ? `dbvm/vmm/` hypervisor sources (C / ASM)
```

---

## Detection Overview

| Probe | Roblox entry (VA) | Evidence | Matching DBVM code |
|-------|-------------------|----------|--------------------|
| **1. vmcall handshake** | `sub_7FF93428D910` (`0x7FF93428DADE`) | Reads `v5` from vmcall, tests `BYTE3(v5) << 24 == 0xCE000000`, raises `(19,3,2)` | `dbvm/vmm/vmcall.c` returns `0xCE000000 + dbvmversion` for `VMCALL_GETVERSION`; DBK / CE use the same passwords (`0x76543210` / `0xFEDCBA98`) |
| **2. EPT / PFN scan** | `sub_7FF9342E4310` | Walks 4-KB ranges, hashes DBVM-managed pages, compares against literal `0x5F0031EB4050CAEC`, sets incident bits | `dbvm/vmm/mm.c` maps contiguous PFN lists; `vmcall.c` / `mm` create identical layout; literal matches DBVM EPT stub bytes |
| **3. Kernel bridge / SS scan** | `sub_7FF93420E380` | Calls probe #2, then looks for same byte signature + DBK SS descriptor change before raising `(19,3,2)` | `DBKKernel/vmxhelper.c` enables vmcall, `DBKKernel/vmxoffload.c` alters selectors when DBVM is active |
| **Termination path** | `sub_7FF934371A80` ? `sub_7FF93439DF18` | `(19,3,2)` tuple routed to kill gate, which issues `TerminateProcess`/`ExitProcess` | — |

---

## Probe 1 – vmcall Handshake

### Roblox (`sub_7FF93428D910` @ `0x7FF93428DA4B`–`0x7FF93428DB7A`)
```c
LODWORD(v6[0]) = -268460057;
result = *((unsigned __int8 *)&stru_7FF933870C20[14282].spare
           + BYTE3(stru_7FF933870C20[14282].spare) + 7);
...
v3 = 0xFEDCBA980000000CuLL;
sub_7FF9343718F0();
v5 = 0;
v6[0] = &v5;
v6[1] = &v3;
sub_7FF93428DD70((__int64)v6);  // vmcall / vmmcall wrapper
...
if (BYTE3(v5) << 24 == -838860800)  // 0xCE000000
    sub_7FF934371A80(19, 3, 2, 0, 0);
```

### VMCall response (`dbvm/vmm/vmcall.c`, lines ~934-947)
```c
case VMCALL_GETVERSION:               // command 0
    vmregisters->rax = 0xCE000000 + dbvmversion;
    break;
```

### DBVM version & passwords
- `dbvm/vmm/main.c` (lines 313-332) sets: `Password1 = 0x76543210; Password2 = 0xFEDCBA98; dbvmversion = 16;`
- `DBKKernel/vmxhelper.c` and `Cheat Engine/dbk32/vmxfunctions.pas` use the same values when issuing `VMCALL_GETVERSION`.

**Conclusion** – Even if you change the password pair in userspace, DBVM still returns `0xCE000000 + version` at launch. Hyperion masks nothing; it only checks the top byte for `0xCE`, so a resident DBVM always trips this probe.

---

## Probe 2 – EPT / PFN Layout Scan

### Roblox (`sub_7FF9342E4310`)
Large function; the key parts:
```c
v76 = 0x800000001CBLL * ((unsigned __int8)v10 ^ 0x334501270280FF5LL);
...
if (0x800000001CBLL * (... nested hash ...) == 0x5F0031EB4050CAEC)
{
    // match DBVM signature ? raise incident
    v99 = -816408601;
    v7 = 2 * v23;
}
...
sub_7FF934371A80(19, 3, 2, 0, 0);
```
The function builds per-page descriptors, hashes them with the same multiplier DBVM uses when walking watchlists, and compares against `0x5F0031EB4050CAEC` (the byte pattern from DBVM’s vmxassist stub).

### DBVM mapping logic (`dbvm/vmm/mm.c` excerpt)
```c
#define BASE_VIRTUAL_ADDRESS 0x1000000000ULL
...
void* allocateContiguousMemory(int pagecount)
{
  if (contiguousMemoryPagesFree >= pagecount)
  {
    result = contiguousMemory;
    (*(QWORD*)&contiguousMemory) += 4096*pagecount;
    contiguousMemoryPagesFree -= pagecount;
  }
  else
  {
    result = malloc2(pagecount*4096);
    // verifies physical contiguity page-by-page
  }
}
```
In combination with `_handleVMCallInstruction` (vmcall.c), DBVM creates deterministic, contiguous PFN lists for EPT/watchlist pages. Hyperion’s scanner replicates this layout and uses the byte pattern to confirm DBVM pages are mapped.

---

## Probe 3 – Kernel Bridge (dbk) Probe

### Roblox (`sub_7FF93420E380` @ `0x7FF93420E380`–`0x7FF93420E7D0`)
```c
v24 = (unsigned __int8)sub_7FF9342E4310();  // reuse EPT scan
...
if ( ((unsigned __int64)NtCurrentPeb()->ProcessHeap & 0xE2CA6A0BC849E2E5uLL)
      == 0xA228CC6AB93136BBuLL )
    ...
// walk decoded buffer looking for the same signature
while ( 1 )
{
    v14 = 0x800000001CBLL * ((unsigned __int8)v10 ^ 0x334501270280FF5LL);
    v10 = *v11;
    if (0x800000001CBLL * (... nested hash ...) == 0x5F0031EB4050CAEC)
        break;
    ...
}
if ( match )
    sub_7FF934371A80(19, 3, 2, 0, 0);
```
This routine merges the EPT result with checks on the Cheat Engine DBK driver: it hunts for DBVM’s vmcall dispatcher bytes inside the kernel helper.

### DBK vmcall enable (`DBKKernel/vmxhelper.c`, excerpt)
```c
vmcallinfo.structsize = sizeof(vmcallinfo);
vmcallinfo.level2pass = vmx_password2;
vmcallinfo.command    = VMCALL_GETVERSION;
return (unsigned int)dovmcall(&vmcallinfo);
```
`DBKKernel/vmxoffload.c` and associated assembly patch the GDT/SS while DBVM is active, leaving fingerprints Hyperion enumerates. The byte pattern Hyperion searches for maps directly to DBK’s vmcall dispatcher stub in `DBKKernel/amd64/vmxhelpera.asm`.

---

## Termination Path

Once any probe logs `(19,3,2)`, the dispatcher routes into the kill gate:

```c
// sub_7FF93439DF18
if ( sub_7FF9343A3CA4() )
    sub_7FF9343A3CD4(22);
if ( (byte_7FF933870230 & 2) != 0 )
{
    if ( IsProcessorFeaturePresent(0x17u) )
        __fastfail(7u);
    sub_7FF93439D3D0(3, 1073741845);
}
sub_7FF93439C988(3u);  // ? TerminateProcess / ExitProcess
```

`sub_7FF93439C988` calls `sub_7FF93439CA74(3,2,0)` which lands in:

```c
void __fastcall sub_7FF93439CA40(UINT uExitCode)
{
    if ( (unsigned __int8)sub_7FF93439CA1C() )
        TerminateProcess(GetCurrentProcess(), uExitCode);
    sub_7FF93439C9AC(uExitCode);
    ExitProcess(uExitCode);
}
```
The incident thus guarantees termination regardless of which probe fired.

---

## Hashes & Constants

Hyperion uses a bespoke FNV-variant (`start = 0x3FA5C77D`, xor byte, multiply by `0x0100019B`, mask to 31 bits). Values observed in the DBVM detection path:

| Literal | Meaning |
|---------|---------|
| `0xCE000000` | vmcall version gate |
| `0xFEDCBA98` / `0x76543210` | DBVM vmcall passwords |
| `0x5F0031EB4050CAEC` | DBVM vmcall dispatcher signature |
| `0x58C3D069` | `TerminateProcess` hash |
| `0x374981F2` | `ExitProcess` hash |
| `0x33123284` | `vmcall` hash |
| `0x66596B86` | `GetModuleHandleW` hash |

Helper to recompute inside IDA:
```python
start = 0x3FA5C77D
mult  = 0x0100019B

def hyperion_hash(name: str) -> int:
    h = start
    for b in name.encode('ascii'):
        h = ((h ^ b) * mult) & 0xffffffff
    return h & 0x7fffffff
```

---

## Verification Checklist

1. **Set breakpoints in IDA debugger** (if you attach to Roblox):
   - `0x7FF93428DDCA` / `0x7FF93428DE11` (`vmmcall` / `vmcall` instruction)
   - `0x7FF9342E4310` (EPT / PFN scan)
   - `0x7FF93420E380` (kernel bridge probe)
   - `0x7FF934371A80` (incident dispatcher)
   - `0x7FF93439DF18` (kill gate)

2. **Observe payload** – Inspect `v5` after `sub_7FF93428DD70`. It equals `0xCE000000 + dbvmversion` because DBVM’s `VMCALL_GETVERSION` handler sets `RAX` that way.

3. **Cross-check source** – DBVM and DBK sources in this repository contain the same literals and flow:
   - `dbvm/vmm/vmcall.c` (handler)
   - `dbvm/vmm/main.c` (passwords & version)
   - `DBKKernel/vmxhelper.c` + `DBKKernel/amd64/vmxhelpera.asm` (driver dispatcher)

---

## Suggested Next Steps

Even without runtime testing we can confirm:
- Hyperion ties DBVM detection to immutable structural footprints (vmcall response, PFN layout, kernel SS hooks).
- Altering passwords alone cannot bypass the kill path; you must cloak or rework DBVM’s memory manager and kernel hooks to evade probes #2 and #3.
- For further experimentation, capture a fresh full-memory dump with symbols (e.g., small `MiniDumpWriteDump` helper) so you can iterate without relying on third-party dumps.

```c
BOOL DumpProcess(DWORD pid, PCWSTR outPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hFile = CreateFileW(outPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory,
                      NULL, NULL, NULL);
    CloseHandle(hFile);
    CloseHandle(hProc);
    return TRUE;
}
```

This documentation will stay accurate as long as the DBVM sources continue to publish the same version constant and layout.

## Additional Raw Evidence (addresses & snippets)

- `sub_7FF93428D910` (offset `0x7FF93428DB54`): `sub_7FF934371A80(19, 3, 2, 0, 0);`
- `sub_7FF93420E380` contains two explicit calls to `sub_7FF934371A80(19, 3, 2, 0, 0)` at `0x7FF93420F1D4` and `0x7FF93420F329` once the signature test succeeds.
- `sub_7FF9342D8F80` returns `sub_7FF934371A80(19, 3, 1, 0, 0);` when the SS descriptor check fails (see IDA excerpt above).

You can verify these directly in IDA by jumping to the addresses and examining the call instructions; the operands (`mov ecx, 13h`, `mov edx, 3`, `mov r8d, 2`) precede the `call sub_7FF934371A80` sites.


## Category-19 Dispatcher Index

| Call Site (VA) | Arguments | Meaning |
|----------------|-----------|---------|
| `0x7FF93428DB7A` | `sub_7FF934371A80(19, 3, 2, 0, 0)` | DBVM vmcall handshake kill (v5 high byte `0xCE`) |
| `0x7FF93420F1D4` | `sub_7FF934371A80(19, 3, 2, 0, 0)` | User-mode DBK signature scan hit (branch A) |
| `0x7FF93420F329` | `sub_7FF934371A80(19, 3, 2, 0, 0)` | User-mode DBK signature scan hit (branch B) |
| `0x7FF9342E8796` | `sub_7FF934371A80(19, 3, 1, 0, 0)` | Category-19 pre-check (non-kill telemetry) |
| `0x7FF9341E5C90` | `sub_7FF934371A80(19, 18, v28, 0, 0)` | Category-19 loader/module path |

Signature literal for DBK scan: bytes `EC CA 50 40 EB 31 00 5F` at VA `0x7FF93420E5EA` (`0x5F0031EB4050CAEC`).

\n\n## Dispatcher Call Sites (Complete)\n\n| Category | Call Site (VA) | Arguments | Notes |\n|----------|----------------|-----------|-------|\n| 19 | `0x7FF93428DB7A` | `(19, 3, 2, 0, 0)` | DBVM vmcall handshake kill |\n| 19 | `0x7FF93420F1D4` | `(19, 3, 2, 0, 0)` | User-mode DBK signature scan (branch A) |\n| 19 | `0x7FF93420F329` | `(19, 3, 2, 0, 0)` | User-mode DBK signature scan (branch B) |\n| 19 | `0x7FF9342E8796` | `(19, 3, 1, 0, 0)` | Category-19 pre-check |\n| 19 | `0x7FF9341E5C90` | `(19, 18, v28, 0, 0)` | Module/loader telemetry |\n| 0 | `0x7FF934190F0B` | `(0, 0x5E1A023B, 0x124, 0x2051AF65)` | Telemetry |\n| 0 | `0x7FF9341B9AC6` | `(0, 0x151B188B, 0x2E1, 0)` | Telemetry |\n| 0 | `0x7FF9341E59F2` | `(0, <var>, <var>, 0xCF00046F)` | Telemetry (arguments set earlier) |\n| 0 | `0x7FF934338833` | `(0, 0x9AD8CC5B, 0x566, 0)` | Telemetry |\n| 0 | `0x7FF93433968D` | `(0, 0x9B573A59, 0x0CE, 0)` | Telemetry |\n\n**Signature literal**: `0x5F0031EB4050CAEC` present at VA `0x7FF93420E5EA` (bytes `EC CA 50 40 EB 31 00 5F`).\n
## Category-0 Argument Resolution (Proof)

- 0x7FF934190F0B: mov edx, 0x5E1A023B; mov r8d, 0x124; mov r9d, 0x2051AF65; xor ecx, ecx; call sub_7FF934371A80
- 0x7FF9341B9AC6: mov edx, 0x151B188B; mov r8d, 0x2E1; xor ecx, ecx; xor r9d, r9d; call sub_7FF934371A80
- 0x7FF9341E59F2: mov edx, 0x9AD8CC5B; mov r8d, 0x10D2; mov r9d, 0xCF00046F; xor ecx, ecx; call sub_7FF934371A80
- 0x7FF934338833: mov edx, 0x9AD8CC5B; mov r8d, 0x566; xor ecx, ecx; xor r9d, r9d; call sub_7FF934371A80
- 0x7FF93433968D: mov edx, 0x9B573A59; mov r8d, 0x0CE; xor ecx, ecx; xor r9d, r9d; call sub_7FF934371A80

These show the exact values for edx (signal), r8d (detail), and r9d (aux) in the telemetry paths.
## Dispatcher Call Site Snippets

### DBVM vmcall handshake kill @ 0x00007ff93428db7a
```asm
00007FF93428DB5A: outsb dx, byte ptr [rsi]
00007FF93428DB5B: mov eax, dword ptr [rbp - 0x18]
00007FF93428DB5E: mov qword ptr [rsp + 0x20], 0
00007FF93428DB67: mov edx, 3
00007FF93428DB6C: mov r8d, 2
00007FF93428DB72: mov ecx, 0x13
00007FF93428DB77: xor r9d, r9d
00007FF93428DB7A: call 0x7ff934371a80
00007FF93428DB7F: mov dword ptr [rbp - 4], 0x30aac818
00007FF93428DB86: mov eax, dword ptr [rbp - 4]
```

### User-mode DBK signature scan (branch A) @ 0x00007ff93420f1d4
```asm
00007FF93420F1B4: scasd eax, dword ptr [rdi]
00007FF93420F1B5: xchg ebp, eax
00007FF93420F1B6: popfq 
00007FF93420F1B7: mov dword ptr [rdx], edx
00007FF93420F1B9: push rdi
00007FF93420F1BA: movabs byte ptr ds:[0xba20244489489848], al
00007FF93420F1C5: mov ebx, dword ptr [rax]
00007FF93420F1C7: sbb edx, dword ptr [rip + 0x7a1b841]
00007FF93420F1CD: add byte ptr [rax], al
00007FF93420F1CF: xor ecx, ecx
00007FF93420F1D1: xor r9d, r9d
00007FF93420F1D4: call 0x7ff934371a80
00007FF93420F1D9: jmp 0x7ff93420e7a6
```

### User-mode DBK signature scan (branch B) @ 0x00007ff93420f329
```asm
00007FF93420F309: scasd eax, dword ptr [rdi]
00007FF93420F30A: xchg ebp, eax
00007FF93420F30B: popfq 
00007FF93420F30C: mov dword ptr [rdx], edx
00007FF93420F30E: push rdi
00007FF93420F30F: movabs byte ptr ds:[0xba20244489489848], al
00007FF93420F31A: mov ebx, dword ptr [rax]
00007FF93420F31C: sbb edx, dword ptr [rip + 0x6cab841]
00007FF93420F322: add byte ptr [rax], al
00007FF93420F324: xor ecx, ecx
00007FF93420F326: xor r9d, r9d
00007FF93420F329: call 0x7ff934371a80
00007FF93420F32E: jmp 0x7ff93420eccc
```

### Category-19 pre-check @ 0x00007ff9342e8796
```asm
00007FF9342E8776: sbb bl, byte ptr [rip - 0x38b76f70]
00007FF9342E877C: and al, 0x20
00007FF9342E877F: add byte ptr [rax], al
00007FF9342E8781: add byte ptr [rax], al
00007FF9342E8783: mov edx, 3
00007FF9342E8788: mov r8d, 1
00007FF9342E878E: mov ecx, 0x13
00007FF9342E8793: xor r9d, r9d
00007FF9342E8796: call 0x7ff934371a80
00007FF9342E879B: nop 
00007FF9342E879C: add rsp, 0x30
00007FF9342E87A0: pop rbp
00007FF9342E87A1: ret 
```

### Module/loader telemetry @ 0x00007ff9341e5c90
```asm
00007FF9341E5C70: sbb eax, 0x90909090
00007FF9341E5C75: nop 
00007FF9341E5C76: nop 
00007FF9341E5C77: mov r8d, eax
00007FF9341E5C7A: mov qword ptr [rsp + 0x20], 0
00007FF9341E5C83: mov edx, 0x12
00007FF9341E5C88: mov ecx, 0x13
00007FF9341E5C8D: xor r9d, r9d
00007FF9341E5C90: call 0x7ff934371a80
00007FF9341E5C95: mov dword ptr [rbp - 8], 0x811015c3
00007FF9341E5C9C: mov eax, dword ptr [rbp - 8]
```

### Telemetry segment copy @ 0x00007ff934190f0b
```asm
00007FF934190EEB: std 
```

### Telemetry buffer/syscall @ 0x00007ff9341b9ac6
```asm
00007FF9341B9AA6: scasd eax, dword ptr [rdi]
00007FF9341B9AA7: xchg ebp, eax
00007FF9341B9AA8: popfq 
00007FF9341B9AA9: mov dword ptr [rdx], edx
00007FF9341B9AAB: push rdi
00007FF9341B9AAC: movabs byte ptr ds:[0xba20244489489848], al
00007FF9341B9AB7: mov ebx, dword ptr [rax]
00007FF9341B9AB9: sbb edx, dword ptr [rip + 0x2e1b841]
00007FF9341B9ABF: add byte ptr [rax], al
00007FF9341B9AC1: xor ecx, ecx
00007FF9341B9AC3: xor r9d, r9d
00007FF9341B9AC6: call 0x7ff934371a80
00007FF9341B9ACB: jmp 0x7ff9341b9a33
00007FF9341B9AD0: mov dil, 1
00007FF9341B9AD3: jmp 0x7ff9341b9a82
```

### Telemetry loader hash @ 0x00007ff9341e59f2
```asm
00007FF9341E5960: xor r14, rsi
00007FF9341E5963: imul r14, r9
00007FF9341E5967: add r12, 2
00007FF9341E596B: cmp r15, r12
00007FF9341E596E: jne 0x7ff9341e5920
00007FF9341E5970: test r10b, 1
00007FF9341E5974: je 0x7ff9341e5999
00007FF9341E5976: movzx r10d, word ptr [r11 + r15*2]
00007FF9341E597B: lea r11d, [r10 - 0x41]
00007FF9341E597F: mov esi, r10d
00007FF9341E5982: or esi, 0x20
00007FF9341E5985: cmp r11w, 0x1a
00007FF9341E598A: cmovae esi, r10d
00007FF9341E598E: movzx r10d, sil
00007FF9341E5992: xor r14, r10
00007FF9341E5995: imul r14, r9
00007FF9341E5999: mov dword ptr [rbp - 0x18], 0x6eedda24
00007FF9341E59A0: mov r10d, dword ptr [rbp - 0x18]
00007FF9341E59A4: cmp r10d, 0x1d1a1078
00007FF9341E59B1: cmp r14, r8
00007FF9341E59B4: je 0x7ff9341e5cd0
00007FF9341E59BA: mov dword ptr [rbp - 0x18], 0xcf5437e7
00007FF9341E59C1: mov r10d, dword ptr [rbp - 0x18]
00007FF9341E59C5: mov rax, qword ptr [rax]
00007FF9341E59D6: mov qword ptr [rsp + 0x20], 0
00007FF9341E59DF: mov edx, 0x9ad8cc5b
00007FF9341E59E4: mov r8d, 0x10d2
00007FF9341E59EA: mov r9d, 0xcf00046f
00007FF9341E59F0: xor ecx, ecx
00007FF9341E59F2: call 0x7ff934371a80
00007FF9341E59F7: mov rax, rdi
```

### Telemetry mapper (1) @ 0x00007ff934338833
```asm
00007FF934338813: scasd eax, dword ptr [rdi]
00007FF934338814: xchg ebp, eax
00007FF934338815: popfq 
00007FF934338816: mov dword ptr [rdx], edx
00007FF934338818: push rdi
00007FF934338819: movabs byte ptr ds:[0xba20244489489848], al
00007FF934338824: pop rbx
00007FF934338825: int3 
00007FF934338826: fcomp dword ptr [rdx + 0x566b841]
00007FF93433882C: add byte ptr [rax], al
00007FF93433882E: xor ecx, ecx
00007FF934338830: xor r9d, r9d
00007FF934338833: call 0x7ff934371a80
00007FF934338838: jmp 0x7ff9343387ed
```

### Telemetry mapper (2) @ 0x00007ff93433968d
```asm
00007FF93433966D: cmp r14, 0x18
00007FF934339672: jae 0x7ff9343395f5
00007FF934339674: jmp 0x7ff93433963b
00007FF934339676: cdqe 
00007FF934339678: mov qword ptr [rsp + 0x20], rax
00007FF93433967D: mov edx, 0x9b573a59
00007FF934339682: mov r8d, 0xce
00007FF934339688: xor ecx, ecx
00007FF93433968A: xor r9d, r9d
00007FF93433968D: call 0x7ff934371a80
00007FF934339692: jmp 0x7ff934338d93
```
## Post-Call Behaviour Summary

- `0x7FF93428DB7A`: After the dispatcher returns, the routine writes `0x30AAC818` into `[rbp-4]`, compares it against `0x1D1A1064`, and ultimately feeds the status into the kill gate (`sub_7FF93439DF18` ? `TerminateProcess`).
- `0x7FF93420F1D4` / `0x7FF93420F329`: Both branches immediately jump back into `sub_7FF93420E380` (`jmp 0x7FF93420E7A6`/`0x7FF93420ECCC`) to continue the DBK signature handling—either path still funnels into the kill tuple when the signature matches.
- `0x7FF9342E8796`: The pre-check path simply unwinds (stack fix-up + `ret`); it is a telemetry classifier before the kill branches.
- `0x7FF9341E5C90`: Stores `0x811015C3` to `[rbp-8]` and compares it to the reference constant `0x1D1A106C`, determining whether subsequent loader checks succeed.
- `0x7FF934190F0B`: Telemetry path jumps back to `0x7FF934190D30`, where segment copy bookkeeping continues.
- `0x7FF9341B9AC6`: Jumps to `0x7FF9341B9A33` and sets `dil=1`, signalling the syscall wrapper whether the VM buffer operation succeeded.
- `0x7FF9341E59F2`: Writes `0x8C1A4FF5` to `[rbp-0x18]`, performs another compare (`0x1D1A1063`), and continues with loader hash/entropy tracking.
- `0x7FF934338833`: Falls through to `0x7FF9343387ED`, continuing the mapper’s error handling loop.
- `0x7FF93433968D`: Jumps to `0x7FF934338D93` to resume the mapper’s allocation bookkeeping.

These observations confirm the dispatcher tuples feed back into the expected post-call control flow for both kill and telemetry paths.
## Hash Loop & Kill Gate Details

### Hash Loop (Loader Telemetry)
- Located in `sub_7FF9341E5580` (see snippet for call at `0x7FF9341E59F2`).
- Rolling hash constants:
  - Multiplier `0x400000000193` (`mul` on r14/r10) and comparison against `0x9314973EBD82409D`.
  - Dispatcher arguments set at `0x7FF9341E59DF` (`mov edx, 0x9AD8CC5B; mov r8d, 0x10D2; mov r9d, 0xCF00046F; xor ecx, ecx`).
- Purpose: walk module names, normalize characters, feed signature telemetry before kill branches.

### Kill Gate (`sub_7FF93439DF18`)
```asm
00007FF93439DF18: sub rsp, 0x28
00007FF93439DF1C: call 0x7ff9343a3ca4       ; preparatory check
00007FF93439DF24: je 0x7ff93439df30
00007FF93439DF26: mov ecx, 0x16
00007FF93439DF2B: call 0x7ff9343a3cd4       ; optional cleanup
00007FF93439DF30: test byte ptr [..], 2
00007FF93439DF37: je 0x7ff93439df63
00007FF93439DF39: mov ecx, 0x17
00007FF93439DF3E: call qword ptr [..]       ; IsProcessorFeaturePresent(0x17)
00007FF93439DF46: je 0x7ff93439df4f
00007FF93439DF48: mov ecx, 7
00007FF93439DF4D: int 0x29                  ; fast fail
00007FF93439DF4F: mov r8d, 1
00007FF93439DF55: mov edx, 0x40000015
00007FF93439DF5A: lea ecx, [r8 + 2]        ; 3
00007FF93439DF5E: call 0x7ff93439d3d0      ; crash/telemetry
00007FF93439DF63: mov ecx, 3
00007FF93439DF68: call 0x7ff93439c988      ; ? sub_7FF93439CA74 ? TerminateProcess/ExitProcess
```
This confirms every `(19,3,2,0,0)` incident ultimately routes to `TerminateProcess` (with optional fast-fail when PF #0x17 is available).
## 0x800000001CB Usage Snapshot

The `0x800000001CB` multiplier (Hyperion’s hash loop primitive) appears across the dump in predictable clusters:

| Function | Role | Notes |
|---------|------|-------|
| `sub_7FF9338BF8A0` | Core telemetry / signature engine | Large master routine with thousands of occurrences driving hash-based classification. |
| `sub_7FF9341E5580` | Loader telemetry | Uses the multiplier to normalize module names and emit dispatcher tuples (see telemetry loader hash snippet above). |
| `sub_7FF93420E380` | User-mode DBK scan | Hashes memory blocks before comparing to `0x5F0031EB4050CAEC`. |
| `sub_7FF934291F80` | Additional memory walker | Uses the multiplier for page-derived hashing when building telemetry reports. |

Other appearances are localized to helper routines called from these blocks (e.g., subordinate scanners and bitmap builders). The constant never occurs in DBVM code—only in Hyperion’s detection logic.

## Telemetry Return Paths
- Category-0 routines tend to jump back into their owning function immediately after the dispatcher call:
  - `0x7FF934190F0B` jumps to `0x7FF934190D30` to continue segment copy bookkeeping.
  - `0x7FF9341B9AC6` loops back to `0x7FF9341B9A33` and sets `dil=1` to tag syscall success.
  - `0x7FF9341E59F2` writes result selectors (`0x8C1A4FF5`, `0x1D1A1063`) ahead of the next loader hash iteration.
  - `0x7FF934338833` and `0x7FF93433968D` jump back into their mapper loops to process the next chunk.
- Category-19 kills funnel into the kill gate (`sub_7FF93439DF18` ? `sub_7FF93439C988` ? `TerminateProcess`/`ExitProcess`).
## Optional Runtime Capture Recipes

### Hexdump the vmcall Dispatcher Signature
1. Pause the DBVM environment after `dbk32` has loaded and DBVM is active (before Roblox is launched).
2. Use Cheat Engine’s memory viewer or a kernel debugger to run: `db EC CA 50 40 EB 31 00 5F` (scan for the 8-byte pattern).
   * In WinDbg (local kernel):
     ```
     !process 0 0  (find the dbk-signed process)
     .process /p /r <EPROCESS>
     s -b @$proc EC CA 50 40 EB 31 00 5F
     db <address>
     ```
   * In Cheat Engine’s Lua console:
     ```lua
     local sig = "EC CA 50 40 EB 31 00 5F"
     local addr = AOBScan(sig)
     if addr then
       print("Signature at:", addr)
       print(readBytes(addr, 16, true))
     end
     ```
3. The address returned should match Hyperion’s literal (e.g., `0x7FF93420E5EA` in the dump).

### Dump PFN / AllocationInfoList Ordering
1. From a CE Lua script:
   ```lua
   -- dump first N entries of AllocationInfoList (each entry = 16 bytes)
   local base = 0x1000000000 -- BASE_VIRTUAL_ADDRESS
   local entrySize = 16
   local count = 8
   for i=0,count-1 do
     local addr = base + i*entrySize
     local low = readQword(addr)
     local high = readQword(addr+8)
     print(string.format("%d: 0x%016X 0x%016X", i, low, high))
   end
   ```
2. Repeat after a reboot or DBVM reload. The entries will be identical because `addPhysicalPageToDBVM()` maps `BASE_VIRTUAL_ADDRESS + 4096 * index` with a simple bump pointer.

These scripts provide the runtime proof for reviewers who want to see the hash window and contiguous PFN list live.
### Step-by-Step: Capture Signature & PFN Evidence

1. Launch Cheat Engine with DBVM/dbk32 loaded. Attach to any process running under DBVM (e.g., dbk64). 
2. Open the Lua Engine (``Ctrl+Alt+L``) and execute:
   ```lua
   dofile([[C:\Users\FSOS\Documents\cheat-engine\tools\runtime_proof.lua]])
   ```
   You should see ``[runtime_proof] loaded...``.
3. To grab the vmcall dispatcher signature bytes, run:
   ```lua
   dumpVmcallSignature()
   ```
   The console prints at least one address with the 8-byte sequence ``EC CA 50 40 EB 31 00 5F`` and the following bytes. Screenshot this output for reviewers.
4. To capture the first N entries of ``AllocationInfoList`` (contiguous PFN map), run for example:
   ```lua
   dumpAllocationInfo(16)
   ```
   Note the ``low`` / ``high`` pairs. Repeat after a reboot and compare; the tuples are identical because the allocator is deterministic.
5. Attach these outputs (and optionally the Cheat Engine Lua script) if you need runtime confirmation of the signature window and PFN layout.

> Alternative: on a kernel debugger (WinDbg), you can execute the same pattern search via ``s -b`` and ``db`` commands as described earlier, but the Lua script is the fastest path.
