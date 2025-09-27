# SigMaker Selections (Click-by-Click)

This file gives exact addresses and byte windows to select in IDA and run "SigMaker → Make Sig from selection". It reflects the current `dump.bin` IDB and avoids long ranges so signatures stay resilient.

How to use
- In IDA, press `G` to jump to the address.
- Select the indicated span (bytes). Right click → SigMaker → Make Sig from selection.
- In the preview, mask RIP‑relative displacements (call/jmp indirections) and keep unique immediates.
- Save signature with a meaningful name.


## TLS Kill Tail (NtTerminateProcess with 0x00BADD00D)

- Address: `0x7ff93430ff46`
- Length: 0x30 bytes (48)
- Purpose: catches the invariant kill tail across builds.

Extracted bytes (from MCP):
```
48 C7 C1 FF FF FF FF
BA 0D D0 AD 0B
FF 15 A8 D9 4B FF   ; mask RIP disp
65 48 8B 04 25 30 00 00 00
48 8B 80 F0 07 00 00
48 B9 DD 3A 71 8F 0B 6A CA E2
48 21 C1 48
```
Keep:
- `48 C7 C1 FF FF FF FF` (mov rcx,-1)
- `BA 0D D0 AD 0B` (ExitStatus 0x00BADD00D)
- `FF 15 ?? ?? ?? ??` (call [NtTerminateProcess]) with masked disp


## Import Resolver (API‑set aware loader)

- Address: `0x7ff9343a23e0`
- Length: ~0x40 bytes
- Purpose: re-find resolver that loads api‑sets and calls GetProcAddress.

Extracted head bytes:
```
48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57
41 54 41 55 41 56 41 57 48 83 EC 20 44 8B F9
4C 8D 35 ?? ?? ?? ??   ; lea r14, [apiset_pool]
...
```
Keep:
- prologue and the LEA to api‑set pool (mask disp)
- Look later in the function to select a second short range around `LoadLibraryExW(..., 0, 0x800)` and `GetProcAddress`.


## Exit Wrapper (TerminateProcess → ExitProcess)

- Address: `0x7ff93439ca40`
- Length: ~0x30 bytes
- Purpose: stable exit bridge used by non‑VM code.

Extracted bytes:
```
40 53 48 83 EC 20 8B D9
E8 ?? ?? ?? ??         ; call sub (pre‑check)
84 C0 74 11
FF 15 ?? ?? ?? ??      ; call GetCurrentProcess
48 8B C8 8B D3
FF 15 ?? ?? ?? ??      ; call TerminateProcess
8B CB
E8 ?? ?? ?? ??         ; call sub_7FF93439C9AC
8B CB
FF 15 ?? ?? ?? ??      ; call ExitProcess
```
Mask RIP displacements, keep the sequence of two import calls with RCX/RDX set.


## Clean Crash Scaffold (WER path)

- Address: `0x7ff93439aa20`
- Length: ~0x30–0x40 bytes
- Purpose: re-find crafted crash route via UnhandledExceptionFilter.

Extracted head bytes:
```
48 89 5C 24 08 55 48 8D AC 24 40 FB FF FF 48 81 EC C0 05 00 00 8B D9
B9 17 00 00 00
FF 15 ?? ?? ?? ??      ; IsProcessorFeaturePresent
85 C0 74 04 8B CB CD 29
B9 03 00 00 00
E8 ?? ?? ?? ??         ; sub_7FF93439AA18
33 D2 48 8D 4D F0 41 B8 D0 04 00 00
```
Follow-up slice later around the calls to `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `SetUnhandledExceptionFilter`, `UnhandledExceptionFilter`.


## VM Core (byfron) — QWORD Constant Anchor

- Function start: `0x7ff934350cb0`
- Selection: find the block where two QWORD immediates are loaded/stored:
  - `0xC5AE8F3F0A004839`
  - `0xE5924CCAC6650D76`
- In practice: search for these immediates in the function, then select ~0x20 bytes spanning the two `mov rax, imm64` sites and the subsequent SSE XOR (`xorps`/`pxor`). Mask nothing (immediates are the anchors).

Tip: If lookups are tedious, search for nearby `syscall` instruction clusters (`0F 05`) and sign two short slices.


## Top‑of‑Usermode Literal (file offset)

- File offset: `0x37B6`
- Not in a mapped segment. To use SigMaker on it:
  - Create a temporary IDA segment mapped over the file data around this offset and select the 8 bytes `FF FF FF FF FF 7F 00 00`.
  - Save as auxiliary signature (optional).


---

These selections can be re-used verbatim on very close builds; if a selection fails, take a second signature slice in the same function (e.g., just before/after the call site).

