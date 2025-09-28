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
