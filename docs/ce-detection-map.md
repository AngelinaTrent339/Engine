# CE Detection Map (Name, Logo/Icon, Max-Usermode) — Evidence, Flows, and Future-Proof Signatures

This document captures the complete, evidence-backed mapping of three Cheat Engine (CE) related detections observed in `dump.bin` (loaded in IDA via MCP), and shows exactly how they link to process termination or crash scaffolds. It also includes future‑proofing: resilient signature patterns (for IDA SigMaker or FLIRT-like matching), export‑hash logic used by the VM’d code, and a reproducible workflow to re‑locate these detections when builds change.

Contents
- Scope, module metadata, and context
- Detection surfaces and their link to kill/crash
  - CE name (module/process name) checks
  - CE logo / window / icon checks (user32/dwmapi)
  - Max‑usermode scan probe (0x00007FFFFFFFFFFF)
- Termination and crash sinks (and how detections reach them)
- VM core: export name hashing, folded compare sites, and syscall stubs
- Future‑proof signatures and anchors (SigMaker-friendly)
- How to re-find these in new builds (checklist + scripts)
- Appendices
  - Export‑hash function and precomputed values
  - Notable constants and byte patterns
  - IDA tips (SigMaker, mapping raw file offsets, MCP quick refs)


## Scope and Module Context

- Artifact: `dump.bin` (opened in IDA; MCP connected)
- Reported by IDA MCP:
  - Module path: `C:\Users\FSOS\Downloads\dump.bin`
  - Base: `0x7ff933640000`
  - Size: `0xdf0000`
  - MD5: `20d1b3755895d688e7d51adededefdf2`
  - SHA256: `726066670827a807b6f6a30690322a7a8ed2e9b2b2cca3e5189d3ce23d26ef85`

The binary contains a large VM’d core that resolves APIs by hashed symbol names and performs direct syscalls. It avoids plaintext “Cheat Engine” strings and static imports for user32/ntdll detection APIs.


## Detection Surfaces and Their Linkage to Termination/Crash

### 1) CE Name (Image/Module) Checks

The non‑VM wrapper region normalizes module file names and compares them via Windows locale APIs. Strings remain encrypted/obfuscated; no plaintext “Cheat Engine” in the IDA string list.

- Evidence functions (addresses in `dump.bin`):
  - Get module path buffer: `GetModuleFileNameW` wrapper at `0x7ff9343a5780` (calls K32.GetModuleFileNameW, writes into stack buffer)
  - Canonicalize/copy: `0x7ff9343a58a4` (length query + copy into a managed region at `[a2+16]`, `[a2+24]`, `[a2+32]`, `[a2+40]`)
  - Locale compare wrappers (resolved dynamically):
    - `CompareStringEx` wrapper: `0x7ff9343a2064`
    - `LCMapStringEx` wrapper: `0x7ff9343a21e0`
    - `LocaleNameToLCID` wrapper: `0x7ff9343a22cc`
  - Import resolver (API‑set aware; no static imports): `0x7ff9343a23e0`
    - Loads from an API‑set table at `off_7ff9336517c0` (contains `api-ms-win-core-*` strings) and then GetProcAddress

Flow summary:
1. Target acquires/normalizes module path via `GetModuleFileNameW` → `0x7ff9343a58a4`.
2. Normalized strings are compared using `CompareStringEx`/`LCMapStringEx` via the resolver (no direct imports).
3. Positive name matches route into the VM dispatcher, which uses direct syscalls to terminate/exit (see “Termination and Crash Sinks”).

Notes:
- You will not find plaintext “Cheat Engine” in this build; name comparisons rely on decoded strings and locale wrappers.
- The resolver (`0x7ff9343a23e0`) is a high‑value signature anchor across builds.


### 2) CE Logo / Window / Icon Checks (user32/dwmapi)

The VM’d core enumerates loaded modules and their exports, hashes export names with a custom FNV-like function, picks targets by hash, and then calls them indirectly. This is how window enumeration, class name lookup, and icon retrieval happen without static imports.

- VM core function: `0x7ff934350cb0` — byfron core (massive; LDR/PE walks, export hashing, direct syscalls, obfuscated tables)
- Export hashing: Folded FNV‑style algorithm (see “Export‑hash Function” appendix). On match, the VM builds a call stub to the export.
- Likely user32/dwmapi targets (precomputed hashes in this build):
  - `FindWindowA` 0x774BC0AD; `FindWindowW` 0x014BD15B
  - `EnumWindows` 0x505AAD15
  - `GetWindowTextA` 0x650B641B; `GetWindowTextW` 0x5B0B536D
  - `GetClassNameA` 0x0678B119; `GetClassNameW` 0x1878CF1F
  - `SendMessageA` 0x548C594D; `SendMessageW` 0x5E8C69FB
  - `GetClassLongPtrA` 0x249983C6; `GetClassLongPtrW` 0x16996C6C
  - `GetIconInfo` 0x2A3376CE; `LoadImageW` 0x73FF7253
  - `PrintWindow` 0x58E0D8FC; `DwmGetWindowAttribute` 0x24B9CC1F

Flow summary:
1. VM core walks PEB/LDR. For each module, walks exports and hashes names.
2. On matching target API hashes, it calls user32/dwm functions to enumerate windows, classes, and icons (e.g., `WM_GETICON` via SendMessageW; class icon via GetClassLongPtrW; DWM attributes; PrintWindow for capture).
3. Positive logo/pattern findings trigger the VM’s direct‑syscall exit path (see below).

Notes:
- The export‑hash compare sites are not plain string compares; they are folded (e.g., FNV variant), and the jump conditions use constants.
- See “Folded‑hash Compare Sites” for concrete addresses.


### 3) Max‑Usermode Scan Probe (0x00007FFFFFFFFFFF)

CE‑style full virtual memory scans contrast against the canonical top‑of‑usermode address, MaxUsermodeLimit(). This build embeds the literal bytes, but not in a mapped .text region.

- Literal bytes: `FF FF FF FF FF 7F 00 00`
- Confirmed at file offset `0x37B6` (decimal 14262) in `dump.bin`.
- Attempting to jump to `0x7ff9336437b6` in IDA fails because that region isn’t mapped in the current IDB; it is present in the file data, consumed by VM’d code and/or constructed on the fly.

Flow summary:
1. VM core resolves memory routines (e.g., `NtQueryVirtualMemory`, `VirtualQueryEx`) by hashed exports or direct syscall indices.
2. It probes ranges consistent with a full scan (including the top‑of‑usermode limit) to fingerprint CE‑like behavior.
3. Positive detection escalates to direct‑syscall exit (see below).


## Termination and Crash Sinks

Multiple independent sinks exist; detections funnel to one of these depending on stage and context:

1) Hard terminate (TLS gate — also a reusable sink)
- Function: `TlsCallback_0` at `0x7ff93430fab0`
- Key kill site: `0x7ff93430ff46–0x7ff93430ff52`
  - `mov rcx, -1` (CurrentProcess)
  - `mov edx, 0x00BADD00D` (ExitStatus)
  - `call NtTerminateProcess`
- Upstream TLS predicate (hypervisor fold) omitted here for CE topic; this kill is still reachable as a general sink.

2) Exit wrapper (imported TerminateProcess → ExitProcess)
- Function: `0x7ff93439CA40`
  - `GetCurrentProcess` → `TerminateProcess(h, code)` → `ExitProcess(code)`
- Caller: `0x7ff93439CA74` (performing PE header checks, then calling sub_7FF93439CA40)

3) Clean crash scaffold (WER‑style)
- Function: `0x7ff93439AA20`
  - Sets up `CONTEXT`/`_EXCEPTION_POINTERS`, installs `SetUnhandledExceptionFilter`, calls `UnhandledExceptionFilter`
  - Exception code observed: `0x40000015`

4) VM core direct‑syscall sinks
- Function: `0x7ff934350cb0` (massive) contains many `syscall` sites (e.g., `0x7ff934352f39`, `0x7ff934353018`, `0x7ff93435317e`, `0x7ff9343530ce`, `0x7ff9343532ad`, `0x7ff9343534be`, `0x7ff934353533`, `0x7ff9343538fa`, …). These are used to “report and act” after detections; they can terminate directly without going through import thunks.


## VM Core: Export Hashing, Folded Compare, and Syscalls

### Export‑hash function (as used by the sample)

- Algorithm (pseudocode):
```
h = 1068554765
for b in ascii(name):
    h = ((h ^ b) * 16777643) mod 2^32
return h & 0x7fffffff
```
- See Appendix for a ready‑to‑run PowerShell and Python implementation.

### Folded‑hash compare sites in the big VM block (evidence)

- The constant `0x7EA84848` (LE byte pattern `48 48 A8 7E`) appears repeatedly in the VM block `sub_7FF9338BF8A0`. These are compare sites driving matches/branches:
  - `7FF9339F5D67`
  - `7FF9339F600B`
  - `7FF9339F62AF`
  - `7FF9339F6553`
  - `7FF9339F67F7`
  - `7FF9339F6A9B`
  - `7FF9339F6D3F`
  - `7FF9339F6FE3`
  - `7FF9339F7287`
  - `7FF9339F752B`
  - `7FF9339F77CF`
  - `7FF9339F7A73`
  - `7FF9339F7D17`
  - `7FF9339F7FBB`
  - `7FF9339F825F`
  - `7FF9339F8503`
  - `7FF9339F87A7`
  - `7FF933CDC073`
  - `7FF933EB07D2`
  - `7FF934027946`

These addresses are inside `sub_7FF9338BF8A0` (size ~0x219cab); they prove widespread folded‑matching logic driving the VM’s decisions.


## Future‑Proof Signatures and Anchors

Use IDA SigMaker (or similar) with the following signature anchors. Prefer short but unique sequences with wildcards around relocations/addresses.

### TLS Kill Gate (hypervisor leaf → folded compare → NtTerminateProcess)

Anchor ideas (make multiple small patterns):
- cpuid sequence for hypervisor leaf: `mov eax, 40000006h; xor ecx,ecx; cpuid`
- folding fragment: `movdqa xmm0, [rsp+...]; pextrw ecx, xmm0, 4; xor eax, ecx; cmp ax, 25h`
- kill site (use ExitStatus): `mov rcx, -1; mov edx, 0x00BADD00D; call [NtTerminateProcess]`

Notes:
- Function starts: `0x7ff93430fab0` (TlsCallback_0)
- Kill site: `0x7ff93430ff46–0x7ff93430ff52`

Suggested SigMaker pattern (x64, bytes — use wildcards for RIP‑relative):
```
mov eax, 06 00 00 40   ; 40000006h
31 C9                  ; xor ecx,ecx
0F A2                  ; cpuid
66 0F 3A 16 C8 04      ; pextrw ecx, xmm0, 4   (encoding may vary)
31 C1                  ; xor ecx,eax (or xor eax, ecx → 31 C8)
66 3D 25 00            ; cmp ax, 25h
48 C7 C1 FF FF FF FF   ; mov rcx, -1
BA 0D D0 AD 0B         ; mov edx, 0x0BADD00D
FF 15 ?? ?? ?? ??       ; call qword ptr [rip+disp] (NtTerminateProcess)
```

### Import Resolver (API‑set loader → GetProcAddress)

Anchor ideas:
- API‑set pool usage at `off_7ff9336517c0`.
- `LoadLibraryExW(..., 0, 0x800)` followed by fallback `LoadLibraryExW(..., 0, 0)` on error 87.
- Terminal `GetProcAddress` and back‑store into a per‑index table.

Function: `0x7ff9343a23e0`

### VM Core — Export hashing + PE walker (byfron core)

Anchor ideas:
- Repeated QWORD constants reused across TLS/VM: `0xC5AE8F3F0A004839`, `0xE5924CCAC6650D76` placed into stack locals, then XOR via SSE (`_mm_xor_ps`) against another block.
- Multiple `syscall` instructions in a hot basic block cluster (search for many `0F 05`).
- Long inner loops hashing bytes/words of export names; arithmetic with constants `0x800000001CBLL`, `0x1383D5887LL` (used in other string‑hash paths).

Function: `0x7ff934350cb0`

### Exit wrapper (TerminateProcess + ExitProcess)

Function: `0x7ff93439CA40`

Anchor idea:
```
FF 15 ?? ?? ?? ??    ; call GetCurrentProcess
48 89 C1             ; mov rcx, rax
8B D3                ; mov edx, ebx (uExitCode)
FF 15 ?? ?? ?? ??    ; call TerminateProcess
8B CB                ; mov ecx, ebx
FF 15 ?? ?? ?? ??    ; call ExitProcess
```

### Clean crash scaffold (WER UnhandledExceptionFilter route)

Function: `0x7ff93439AA20`

Anchor idea (partial):
```
FF 15 ?? ?? ?? ??    ; call RtlCaptureContext
FF 15 ?? ?? ?? ??    ; call RtlLookupFunctionEntry
FF 15 ?? ?? ?? ??    ; call RtlVirtualUnwind
FF 15 ?? ?? ?? ??    ; call SetUnhandledExceptionFilter
FF 15 ?? ?? ?? ??    ; call UnhandledExceptionFilter
```

### Top‑of‑usermode literal

File offset: `0x37B6` (bytes `FF FF FF FF FF 7F 00 00`).

Notes:
- Not mapped in this IDB; to use as an anchor, create an IDA segment for the raw region or search the file bytes externally. The VM core consumes this internally.


## How to Re‑Find These in New Builds (Checklist)

1) TLS kill gate
- Search in IDA for `cpuid` with EAX set to `0x40000006` and a `cmp ax, 25h` close by.
- Confirm the kill tail: `mov rcx,-1; mov edx,0x00BADD00D; call NtTerminateProcess`.
- Make a SigMaker pattern around the compare and call site using the ExitStatus immediate.

2) API resolver
- Find the API‑set strings pool (`api-ms-win-core-*`) and its loader using `LoadLibraryExW(...,0,0x800)` and fallback on error 87.
- Confirm `GetProcAddress` terminal stage. Sign this helper.

3) VM core
- Grep for repeated `syscall` (`0F 05`) cluster; then look for the SSE/xor of two QWORD blocks (`0xC5AE8F3F0A004839`, `0xE5924CCAC6650D76`).
- Tag and sign the function body.

4) Export‑hash logic
- Use the known FNV variant to compute hashes for all exports in `user32.dll`, `kernel32.dll`, `ntdll.dll`, `dwmapi.dll` and build a name→hash table.
- When you encounter folded compare constants (e.g., `0x7EA84848`) in the VM core, match against your hash table to resolve the targeted API.

5) Exit wrappers and crash scaffold
- Re-find `TerminateProcess`/`ExitProcess` wrapper by import calls back‑to‑back.
- Re-find the WER scaffold via the `Rtl*` triplet and `UnhandledExceptionFilter`.

6) Top‑of‑usermode literal
- Scan the file (not just segments) for `FF FF FF FF FF 7F 00 00`. If not found in .text, it may be in a packed/VM data block.


## Appendix A — Export‑Hash Function and Precomputed Values

### Hash function (PowerShell)
```powershell
function Hash32($s) {
  $h = [uint32]1068554765
  foreach($b in [Text.Encoding]::ASCII.GetBytes($s)){
    $h = [uint32](((($h -bxor $b) * 16777643) -band 0xffffffff))
  }
  return ($h -band 0x7fffffff)
}
```

### Hash function (Python)
```python
def hash32(name: str) -> int:
    h = 1068554765
    for b in name.encode('ascii'):
        h = ((h ^ b) * 16777643) & 0xffffffff
    return h & 0x7fffffff
```

### Precomputed target hashes (this build)

User32 / DWM / process & memory:

- FindWindowA 0x774BC0AD
- FindWindowW 0x014BD15B
- EnumWindows 0x505AAD15
- GetWindowTextA 0x650B641B
- GetWindowTextW 0x5B0B536D
- GetClassNameA 0x0678B119
- GetClassNameW 0x1878CF1F
- SendMessageA 0x548C594D
- SendMessageW 0x5E8C69FB
- GetClassLongA 0x3F62A13A
- GetClassLongW 0x4962B1E8
- GetClassLongPtrA 0x249983C6
- GetClassLongPtrW 0x16996C6C
- GetWindowThreadProcessId 0x59946A69
- GetForegroundWindow 0x0115CFC2
- GetTopWindow 0x29138E0A
- GetWindow 0x025DE73F
- GetAncestor 0x051E874E
- GetIconInfo 0x2A3376CE
- LoadImageA 0x69FF61A5
- LoadImageW 0x73FF7253
- PrintWindow 0x58E0D8FC
- DwmGetWindowAttribute 0x24B9CC1F
- VirtualQuery 0x0AA2D608
- VirtualQueryEx 0x48474C5D
- NtQueryVirtualMemory 0x6DA3BB2F
- NtReadVirtualMemory 0x1A662CD9
- ReadProcessMemory 0x7EBEAF3D
- QueryWorkingSetEx 0x5F0F2EF7
- GetModuleFileNameA 0x1BFFCDB5
- GetModuleFileNameW 0x05FFA903
- QueryFullProcessImageNameA 0x2EBC00D6
- QueryFullProcessImageNameW 0x40BC1EDC
- GetProcessImageFileNameA 0x1D4E3B87
- GetProcessImageFileNameW 0x0B4E1D81


## Appendix B — Notable Constants and Patterns

TLS/VM constants repeatedly used across modules:
- `0xC5AE8F3F0A004839`
- `0xE5924CCAC6650D76`

Folded compare constant observed (VM block):
- `0x7EA84848` (LE byte pattern `48 48 A8 7E`) — multiple compare sites (see VM section)

TLS kill ExitStatus:
- `0x00BADD00D` (mov edx, 0x0BADD00D)

Top‑of‑usermode literal in file data:
- File offset `0x37B6`: bytes `FF FF FF FF FF 7F 00 00`


## Appendix C — IDA Tips (SigMaker, Mapping Raw Offsets, MCP quick refs)

- SigMaker: prefer small, selective patterns around unique immediates (e.g., `0x00BADD00D`) and rare instruction sequences (e.g., cpuid with `EAX=0x40000006`, folded compare `cmp ax,25h`). Mask RIP‑relative displacements with wildcards.
- Mapping raw file data: Use “Edit → Segments → Create” to map a new segment over raw file offset regions (e.g., the top‑of‑usermode literal at offset `0x37B6`). Then you can reference them by VA.
- MCP quick refs (from this analysis):
  - TLS gate: `0x7ff93430fab0` (kill at `0x7ff93430ff46`)
  - VM core: `0x7ff934350cb0` (byfron core with syscalls, hashing)
  - Import resolver: `0x7ff9343a23e0`
  - Exit wrapper: `0x7ff93439CA40`
  - WER crash scaffold: `0x7ff93439AA20`


## Appendix D — Control‑Flow Linking (Cause → Effect)

High‑level paths:

- CE name:
  - `GetModuleFileNameW (0x7ff9343a5780)` → `copy (0x7ff9343a58a4)` → `CompareStringEx/LCMapStringEx via resolver (0x7ff9343a2064/21e0 + 0x7ff9343a23e0)` → VM dispatcher → direct syscalls → termination (or ExitProcess wrapper)

- CE logo/icon:
  - `VM core (0x7ff934350cb0)` → export hash match (precomputed list) → calls user32/dwm functions (icon/class/window) → detection met → syscall‑driven terminate/report → possibly imported ExitProcess wrapper

- Max‑usermode scan:
  - `VM core` → resolve memory APIs (NtQueryVirtualMemory/VirtualQueryEx) via hashing → probe ranges to 0x00007FFFFFFFFFFF → detection met → syscall‑driven termination

Sinks:
- TLS direct kill (NtTerminateProcess, ExitStatus 0x00BADD00D)
- `sub_7FF93439CA40` (TerminateProcess → ExitProcess)
- `sub_7FF93439AA20` (WER crash)


---

This mapping is built from concrete IDA MCP evidence in the current `dump.bin` IDB and designed to be reproducible across build changes using constant‑based signatures and the export‑hash algorithm described above.

