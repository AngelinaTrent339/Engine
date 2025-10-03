Agent Notes: RobloxPlayerBeta_dump (BN + IDA)

Scope
- This guide documents all known early-startup detectors we’ve mapped in RobloxPlayerBeta_dump, with addresses in both VA and RVA (rebase) form, breakpoint playbooks, and patch‑ready handoffs. Use it for dynamic triage, correlation, and precise patching. It assumes Binary Ninja (BN) and IDA Pro are both available.

Image Base and Rebase
- PE image base (VA base): 0x7ffc541d0000
- Rebase formula: RVA = VA - 0x7ffc541d0000
- Examples (VA → RVA):
  - 0x7ffc5444d5e0 → 0x0027d5e0
  - 0x7ffc54f246a5 → 0x00d546a5
  - 0x7ffc54f73b10 → 0x00da3b10
  - 0x7ffc54f24540 → 0x00d54540
  - 0x7ffc54f243e7 → 0x00d543e7
  - 0x7ffc54f19dab → 0x00d49dab
  - 0x7ffc54f1cd3e → 0x00d4cd3e
  - 0x7ffc5444d870 → 0x0027d870
  - 0x7ffc5444d840 → 0x0027d840
  - 0x7ffc54fa0ac0 → 0x00dd0ac0
  - 0x7ffc54fa4478 → 0x00dd4478
  - 0x7ffc54f9ef30 → 0x00dcef30
  - 0x7ffc54faa06c → 0x00dda06c
  - 0x7ffc54f75b20 → 0x00da5b20
  - 0x7ffc54f75d61 → 0x00da5d61
  - 0x7ffc54f75e49 → 0x00da5e49
  - 0x7ffc54f75c4b → 0x00da5c4b
  - 0x7ffc54408180 → 0x00238180 (seed table buffer)
  - 0x7ffc54f24150 → 0x00d54150

Key Components (Early Startup)

1) Dispatcher (Byfron VM gateway)
- VA 0x7ffc5444d5e0 (RVA 0x0027d5e0)
- Behavior: Uses index (AX<<3), XORs two tables, decrements a guard word at 0x7ffc54404274, then either jmp r10 (direct) or via a jump table. All tiny stubs near 0x7ffc5444bc.. tailcall here.
- Watchdog: 0x7ffc54404274 decremented; underflow triggers int3.

2) Static DBVM probes (for completeness)
- vmcall: 0x7ffc54f19dab (RVA 0x00d49dab)
- vmcall: 0x7ffc54f1cd3e (RVA 0x00d4cd3e)
- vmcall + vmmcall: 0x7ffc54f243e7 (RVA 0x00d543e7)
- These are not the only startup paths that can cause exit; see the non‑vmcall path below.

3) Non‑vmcall startup detector (seeded table + indirect call)
- Seed/init and consumer live at 0x7ffc54f75b20 (RVA 0x00da5b20).
- Seed init (first‑time): 0x7ffc54f75d61..0x7ffc54f75e49 (RVA 0x00da5d61..0x00da5e49)
  - Uses RDTSC as entropy, emits bytes into 0x7ffc54408180 (RVA 0x00238180), sets a band of 0xFF per round, updates the index byte.
- Consumer reads 0x7ffc54408180 at:
  - 0x7ffc54f75b85, 0x7ffc54f75b9d, 0x7ffc54f75bb3, 0x7ffc54f75bc5, 0x7ffc54f75bd7, 0x7ffc54f75be8, 0x7ffc54f75bf9, 0x7ffc54f75c07 …
  - Then builds a function pointer and calls it at 0x7ffc54f75c4b (RVA 0x00da5c4b).
- This path does not use vmcall/vmmcall; it still leads to exit if the downstream check fails.

4) Anti‑debug traps used at startup (non‑DBVM)
- int1/ret shim: 0x7ffc5444d840 (RVA 0x0027d840)
- int 0x2d shim: 0x7ffc5444d870 (RVA 0x0027d870)
- Called from 0x7ffc54f24150 (RVA 0x00d54150) and others; useful to filter out when triaging.

5) Crash hub and abort
- UI/cleanup hub: 0x7ffc54f24540 (RVA 0x00d54540)
- Raise edge: 0x7ffc54f246a5 (RVA 0x00d546a5) → RaiseException wrapper: 0x7ffc54f73b10 (RVA 0x00da3b10)
- Alternate abort path (DllMain integrity path, not DBVM): 0x7ffc54fa20e0 → 0x7ffc54fa4ab8 → abort

Existing Local Changes (Observed)
- User‑level changes (not part of this repo):
  - GetVersion/CE0000 and vmcall “password” modifications were applied externally. These do not affect the non‑vmcall seed‑table path (item 3) and the process still exits on that detector.

Planned Patch Points (not applied here)
- Seed table freeze (stable startup):
  - NOP/replace 0x7ffc54f75d61..0x7ffc54f75e49 and write a known‑good schedule into 0x7ffc54408180, then set the index byte. This prevents data‑dependent divergence in the consumer.
- Short‑circuit dynamic call:
  - At 0x7ffc54f75c4b (call rax), replace call with code that writes a “success” result path (e.g., zeroing [rsp+28] and jumping to 0x7ffc54f75d4b) so the check cannot route to the crash hub.
- Backstop only (keep running even if tripped):
  - Patch 0x7ffc54f246a5 to skip 0x7ffc54f73b10; avoids RaiseException UI. Use as last resort.

Breakpoint Playbook (BN/WinDbg/x64dbg)
- Core crash edges:
  - bp 0x7ffc54f246a5 (RVA 0x00d546a5) — just before RaiseException
  - bp 0x7ffc54f73b10 (RVA 0x00da3b10) — RaiseException wrapper
- Dispatcher (route tracing):
  - bp 0x7ffc5444d5e0 (RVA 0x0027d5e0) — log AX and the computed r10 (jmp target) on each hit
- Seed table path (non‑vmcall):
  - bp 0x7ffc54f75d61 (RVA 0x00da5d61) — first‑time seed init
  - ba r1 0x7ffc54408180 (RVA 0x00238180) — watch reads; confirms consumer activity
  - bp 0x7ffc54f75c4b (RVA 0x00da5c4b) — call rax site; dump RAX, step in to see the exact callee
- Static DBVM stubs (for completeness):
  - bp 0x7ffc54f19dab (RVA 0x00d49dab)
  - bp 0x7ffc54f1cd3e (RVA 0x00d4cd3e)
  - bp 0x7ffc54f243e7 (RVA 0x00d543e7)
- Anti‑debug shims (noise filters):
  - bp 0x7ffc5444d840 (RVA 0x0027d840)
  - bp 0x7ffc5444d870 (RVA 0x0027d870)

Triage Workflow (finding more, no guessing)
1) When 0x7ffc54f246a5 hits, capture the caller and walk one frame up to the function that chose to exit.
2) Correlate with the last dispatcher hit (0x7ffc5444d5e0) — use logged AX and r10 to identify the “microcode” callee. Step into that callee.
3) If the non‑vmcall seed path is active, you’ll see repeated reads from 0x7ffc54408180 and the dynamic call at 0x7ffc54f75c4b. From there, follow return‑value usage to see the exact branch into the crash hub.
4) If you must scan, prefer dynamic execute‑time scans:
   - Find int1 / int 0x2d sites near the failing parent to filter noise.
   - Only as a sanity check, look for 0f 01 c1 / 0f 01 d9 in the current executable region; static matches are known: 0x7ffc54f19dab, 0x7ffc54f1cd3e, 0x7ffc54f243e7.

Rebase Cheat Sheet (copy/paste)
- Base = 0x7ffc541d0000
- Compute RVA quickly:
  - RVA(0x7ffc54f246a5) = 0x54f246a5 - 0x541d0000 = 0x00d546a5
  - RVA(0x7ffc54f73b10) = 0x54f73b10 - 0x541d0000 = 0x00da3b10
  - RVA(0x7ffc54f75b20) = 0x54f75b20 - 0x541d0000 = 0x00da5b20
  - RVA(0x7ffc54408180) = 0x54408180 - 0x541d0000 = 0x00238180

Notes and Cautions
- Guard counter at 0x7ffc54404274 (R/W) is decremented by the dispatcher; keep it >0 while stepping to avoid INT3.
- 0x7ffc54f24150 and 0x7ffc54f42b30 are generic anti‑debug entry points (int1/int2d); they are not DBVM‑specific.
- The non‑vmcall detector (seed table path) is sensitive to timing/state; RDTSC variance can influence its output. Freezing the seed schedule or short‑circuiting the dynamic call are clean, non‑vmcall mitigations.

Status
- No code changes have been applied in this repo. The “Existing Local Changes” section documents user‑side tweaks that were observed externally. The “Planned Patch Points” section lists precise sites suitable for surgical fixes.

Supplemental Details (All Findings)

DllMain / Once‑Only Integrity Path (not DBVM)
- _start: 0x7ffc54fa0ac0 (RVA 0x00dd0ac0) → 0x7ffc54fa0998 (RVA 0x00dd0998)
- DllMain helper: 0x7ffc54ee1b40 (RVA 0x00d11b40) → 0x7ffc54ef9870 (RVA 0x00d29870)
  - Performs cpuid and multiple KUSER_SHARED_DATA checks; not DBVM‑specific.
- Abort shim: 0x7ffc54fa20e0 (RVA 0x00dd20e0) → 0x7ffc54fa4ab8 (RVA 0x00dd4ab8) → abort

Crash/UI Hub Callflow (expanded)
- Hub: 0x7ffc54f24540 (RVA 0x00d54540)
  - Callees observed (subset): 0x7ffc54fa4c44 (RVA 0x00dd4c44), 0x7ffc54f9eef4 (RVA 0x00dceef4),
    0x7ffc54d59b50, 0x7ffc54fb20e0 (RVA 0x00df20e0), 0x7ffc54f9ef30 (RVA 0x00dcef30)
- Raise edge: 0x7ffc54f246a5 (RVA 0x00d546a5) → 0x7ffc54f73b10 (RVA 0x00da3b10)

Static vmcall/vmmcall Probes (branch detail)
- 0x7ffc54f19dab (RVA 0x00d49dab): failure branch at 0x7ffc54f19f2b (RVA 0x00d49f2b) → 0x7ffc54f1a022 (RVA 0x00d4a022)
- 0x7ffc54f1cd3e (RVA 0x00d4cd3e): minimal vmcall; returns to caller
- 0x7ffc54f243e7 (RVA 0x00d543e7): vmcall + vmmcall; stores result to [r8], then proceeds

Anti‑debug Shims (callers)
- 0x7ffc54f24150 (RVA 0x00d54150) → calls 0x7ffc54eb5c10 (RVA 0x00ce5c10), then 0x7ffc5444d840 (RVA 0x0027d840)
- 0x7ffc54f42b30 (RVA 0x00d72b30) → calls 0x7ffc5444d870 (RVA 0x0027d870)

Seed Table Path (buffer and flags)
- Buffer: 0x7ffc54408180 (RVA 0x00238180); index byte at same base; lanes at +7..+0xE (8 bytes per slot)
- Init flag: 0x7ffc54408544 (RVA 0x00238544) — used by 0x7ffc54f75b20 at first‑run
- Working pointers: 0x7ffc544088e8 / 0x7ffc544088f0 / 0x7ffc544088f8 (RVAs 0x002388e8 / 0x002388f0 / 0x002388f8)

Additional Helper/Wrapper Sites
- 0x7ffc54fa004c (RVA 0x00dd004c) → jmp 0x7ffc54fa4478 (RVA 0x00dd4478)
- 0x7ffc54faa06c (RVA 0x00dda06c): HeapFree/_errno wrappers
- 0x7ffc54fa10f4 (RVA 0x00dd10f4): RaiseException formatting trampoline

Concrete Patch Sketches (byte‑level, to be applied externally)
- Branch‑flip (vmcall stub): 0x7ffc54f19f2b (RVA 0x00d49f2b)
  - Original: conditional jmp to 0x7ffc54f1a022 on failure
  - Option: invert to always skip failure (e.g., JNE→JE) or NOP the conditional range, keeping fall‑through
- Short‑circuit dynamic call (seed path): 0x7ffc54f75c4b (RVA 0x00da5c4b)
  - Replace call rax with a stub that sets a benign result (e.g., mov dword [rsp+0x28],0; jmp 0x7ffc54f75d4b)
- Seed freeze: 0x7ffc54f75d61..0x7ffc54f75e49 (RVA 0x00da5d61..0x00da5e49)
  - Replace the RDTSC loop with a small memcpy of a known‑good 8‑byte lane set and index; then fall through to success epilogue

Find‑More Guide (stack‑based)
- On hit of 0x7ffc54f246a5, capture return address into 0x7ffc54f24540, then step one frame up to identify the exact parent that chose to exit.
- Cross‑check the last dispatcher hit at 0x7ffc5444d5e0 (log AX, r10). The r10 callee is the “microcode” function to inspect.
- For the non‑vmcall path, 0x7ffc54f75b20 reads 0x7ffc54408180; confirm with read watchpoints (ba r1).

