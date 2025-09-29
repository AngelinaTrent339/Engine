# DBVM Internals Reference

This document maps core DBVM subsystems for quick navigation and future work: VM‑exit dispatch (Intel/AMD), the VMCALL ABI, and the EPT/NPT watch and cloak paths. Paths below reference source files in this repo so you can jump into code quickly.

## Repository Layout (DBVM)

- `dbvm/vmm/` — Hypervisor proper (Intel VMX + AMD SVM/NP, EPT/NP, VM‑exit handlers, VMCALLs, cloaking, watches, MM, APIC, etc.). See `dbvm/vmm/mkx` for build/link steps.
- `dbvm/vmloader/` — Real‑mode/PM loader that places VMM into memory and jumps into it.
- `dbvm/bootsector/` — Bootstrap that loads `vmloader`.
- `dbvm/common/` — Shared C/ASM helpers used by `vmm` and ancillary tools.
- `dbvm/docs/` — Docs (this file).


## VM‑Exit Dispatch Map

DBVM has separate Intel (VMX) and AMD (SVM) event loops. Intel routes via VMCS `vm_exit_reason`; AMD routes via VMCB `EXITCODE`.

### Intel (VMX) Map

- Dispatch switch: `dbvm/vmm/vmeventhandler.c:4119`
- Selected exit reasons → handlers:
  - 0 `vm_exit_interrupt` → `handleInterrupt` (`dbvm/vmm/vmeventhandler.c`)
  - 1 `vm_exit_externalinterupt` → `handleInterrupt` (HLT window logic)
  - 2 Triple fault → diagnostic halt
  - 3 INIT → `handleINIT`
  - 4 SIPI → `handleSIPI`
  - 7 Interrupt window → single‑step or log
  - 9 Task switch → `handleTaskswitch` (`dbvm/vmm/vmeventhandler.c:4308`)
  - 10 CPUID → `handleCPUID` (`dbvm/vmm/vmeventhandler.c:4255`, `dbvm/vmm/vmeventhandler.c:1923`)
  - 12 HLT → `handleHLT`
  - 14 INVLPG → `handleINVLPG` (`dbvm/vmm/vmeventhandler.c:4292`)
  - 16 RDTSC → `handle_rdtsc` (`dbvm/vmm/vmeventhandler.c:4313`)
  - 18 VMCALL → `handleVMCall` (`dbvm/vmm/vmeventhandler.c:4333`)
  - 19..27 VMX instructions (+ `0xCE00/0xCE01` failures) → `handleIntelVMXInstruction` (`dbvm/vmm/vmeventhandler.c:4333`)
  - 28 CR access → `handleCRaccess`
  - 29 DR access → log
  - 30 IO → `handleIOAccess` (`dbvm/vmm/vmeventhandler.c:4377`, `dbvm/vmm/vmeventhandler.c:1403`)
  - 31 RDMSR → `handleRDMSR` (`dbvm/vmm/vmeventhandler.c:4386`, `dbvm/vmm/vmeventhandler.c:1795`)
  - 32 WRMSR → `handleWRMSR` (`dbvm/vmm/vmeventhandler.c:4395`, `dbvm/vmm/vmeventhandler.c:1634`)
  - 33 Invalid guest state → `handleInvalidEntryState`
  - 44 APIC access → log
  - 48 EPT violation → `handleEPTViolation` then `ept_invalidate` (`dbvm/vmm/vmeventhandler.c:4499`)
  - 49 EPT misconfig → `handleEPTMisconfig` (`dbvm/vmm/vmeventhandler.c:4514`)
  - 50 INVEPT → handled via `handleIntelVMXInstruction` (nested VMX emu)
  - 51 RDTSCP → `handle_rdtsc` (+ set rcx TSC_AUX)
  - 53 INVVPID → `handleIntelVMXInstruction`
  - 54 WBINVD → log
  - 55 XSETBV → `handleXSETBV`

Notes:
- The Intel path optionally reinjects pending interrupts using `vm_idtvector_information`/`vm_entry_interruptioninfo` bookkeeping on exits like EPT violations.
- Nested VMX is emulated when the guest executes VMX instructions (`dbvm/vmm/vmxemu.c`).

### AMD (SVM) Map

- Dispatch switch: `dbvm/vmm/vmeventhandler_amd.c`
- Key exit codes handled:
  - `VMEXIT_NPF` (Nested Page Fault) → `handleNestedPagingFault` (`dbvm/vmm/nphandler.c`)
  - `VMEXIT_RDTSC`, `VMEXIT_RDTSCP` → `handle_rdtsc`
  - `VMEXIT_CPUID` → CPUID handling path
  - `VMEXIT_VMRUN`/`VMEXIT_VMLOAD`/`VMEXIT_VMSAVE` → virtualization helpers
  - `VMEXIT_CLGI`/`VMEXIT_STGI` → GIF virtualization
  - `VMEXIT_INVLPGA` → invalidate page in guest address space
  - `VMEXIT_MSR` → RDMSR/WRMSR handling
  - `VMEXIT_SWINT`/`VMEXIT_INTR` → interrupt logic
  - Exceptions `VMEXIT_EXCP*` (UD, BP, PF, etc.) → exception‑specific flows, with single‑step assistance (e.g., syscall UD probe)
  - `VMEXIT_HLT`, `VMEXIT_INIT`, `VMEXIT_SHUTDOWN`, `VMEXIT_INVALID` → explicit handlers/diagnostics

AMD code is verbose; search tokens `case VMEXIT_...` in `dbvm/vmm/vmeventhandler_amd.c` to jump to each case.


## VMCALL ABI (Summary)

Entry validation (`dbvm/vmm/vmcall.c`):
- Registers: `RDX == Password1`, `RCX == Password3`. Defaults set in `dbvm/vmm/main.c`.
- Mapped struct starts with:
  - `VMCALL_BASIC { DWORD size; DWORD password2; DWORD command; }` (`dbvm/vmm/vmcallstructs.h`)
  - `password2` must match; `size` has a 16KB cap.

Core command IDs (`dbvm/vmm/vmcall.h`):
- Version
  - `0 VMCALL_GETVERSION` → returns 0 (stealth)
  - `255 VMCALL_GETVERSION_PRIVATE` → `0xce000000 + dbvmversion`
- Physical memory I/O
  - `3 VMCALL_READ_PHYSICAL_MEMORY` → `VMCALL_READPHYSICALMEMORY { sourcePA, bytesToRead, destinationVA, nopagefault }`
  - `4 VMCALL_WRITE_PHYSICAL_MEMORY` → `VMCALL_WRITEPHYSICALMEMORY { destinationPA, bytesToWrite, sourceVA, nopagefault }`
- MSR
  - `26 VMCALL_READMSR` (returns value in `RAX`)
  - `27 VMCALL_WRITEMSR`
- Ultimap (Intel)
  - `28 VMCALL_ULTIMAP`, `29 _DISABLE`, `34 _PAUSE`, `35 _RESUME`, `36 _DEBUGINFO`
- Pagefault controls
  - `31 VMCALL_DISABLE_DATAPAGEFAULTS`, `32 _ENABLE`, `33 _GETLASTSKIPPEDPAGEFAULT`
- Context switch
  - `30 VMCALL_SWITCH_TO_KERNELMODE` (change CS:RIP to kernel mode stub)
- EPT/NP Watch & Trace
  - `41 VMCALL_WATCH_WRITES`, `42 VMCALL_WATCH_READS`, `60 VMCALL_WATCH_EXECUTES`
  - `43 VMCALL_WATCH_RETRIEVELOG`, `44 VMCALL_WATCH_DELETE`, `68 VMCALL_WATCH_GETSTATUS`
  - Params via `VMCALL_WATCH_PARAM { PhysicalAddress, Size, Options, MaxEntryCount, ID, OptionalField1, OptionalField2 }` and `VMCALL_WATCH_RETRIEVELOG_PARAM`
- Cloaking
  - `45 VMCALL_CLOAK_ACTIVATE`, `46 _DEACTIVATE`
  - `47 VMCALL_CLOAK_READORIGINAL`, `48 _WRITEORIGINAL`
  - `49 VMCALL_CLOAK_CHANGEREGONBP`, `50 _REMOVECHANGEREGONBP`
  - Trace on breakpoint: `69 _TRACEONBP`, `71 _READLOG`, `72 _GETSTATUS`, `73 _STOPTRACE`, `70 _REMOVE`
  - Structs: `VMCALL_CLOAK_ACTIVATE_PARAM`, `VMCALL_CLOAK_READ/WRITE_PARAM`, `CHANGEREGONBPINFO`, `VMCALL_CLOAK_TRACEONBP_PARAM`
- EPT maintenance and hiding
  - `51 VMCALL_EPT_RESET` (clears all watches/cloaks/BP)
  - `79 VMCALL_HIDEDBVMPHYSICALADDRESSES`, `80 *_ALL`
- Timing
  - `61 VMCALL_SETTSCADJUST` (sets speedhack), `62 VMCALL_SETSPEEDHACK`

Return conventions:
- Most commands set `RAX` to status/value (Intel) and mirror to `vmcb->RAX` on AMD where needed.
- Helpers advance guest RIP: Intel adds `vm_exit_instructionlength`; AMD uses `nRIP` or `+3` fallback.


## EPT/NPT Watch Path (Execute/Read/Write)

Activation: `ept_watch_activate(PhysicalAddress, Size, Type, Options, MaxEntryCount, outID, Opt1, Opt2)` (`dbvm/vmm/epthandler.c`)
- Validates `MaxEntryCount` unless interrupt/DBVMBP mode is used.
- Allocates a `PageEventListDescriptor` log buffer sized by entry type (`basic`, `extended`, with optional `stack` snapshot) and count.
- For each CPU:
  - Map EPT/NPT PTE for the target page into `c->eptWatchList[ID]` (per‑CPU pointer to the entry) under `EPTPML4CS`.
  - Mutate permissions based on `Type`:
    - Intel: Writes → `WA=0`; Reads+Writes → `RA=0,WA=0` and if possible `XA=1` (execute‑only optimization); Executes → `XA=0`.
    - AMD: Update PTE fields (`RW`, `P`, `EXB`) to block the targeted access type.
  - Set `c->eptUpdated=1` and leave CS.
- `ept_invalidate()` to flush mappings.

On EPT Violation / NP Fault: `handleEPTViolation`/`handleNestedPagingFault`
- First dispatch to `ept_handleWatchEvent(...)`; if a configured watch matches, DBVM will:
  - Capture state into the watch’s log (`recordState`), including GPRs, segment state, and optionally XSAVE/stack per options.
  - For DBVMBP (breakpoint loop) options, it swaps the page byte to a trap and records `BrokenThreadEntry` for later resume.
  - Adjust per‑CPU PTE back to allow a single instruction (or to continue loop in DBVMBP) and arrange single‑step as needed.

Log retrieval/deactivation:
- `ept_watch_retrievelog(ID, dstVA, &resultSize, &offset, &errorcode)` moves the buffered entries into guest memory in chunks (repeat until complete). Advances RIP on completion and clears `CopyInProgress`.
- `ept_watch_deactivate(ID)` restores permissions and removes the watch; coexists safely with in‑flight violations.


## EPT/NPT Cloak Path (Dual‑view Page)

Activation: `ept_cloak_activate(physicalAddress, mode)` (`dbvm/vmm/epthandler.c`)
- Ensures `CloakedPagesList` → `CloakedPagesMap` migration when the list grows.
- If not already cloaked:
  - Allocate `CloakedPageData` and 4KB `Data` copy of the physical page; map original as `Executable`.
  - For each CPU (under `EPTPML4CS`):
    - Map the PTE and keep a pointer to it in `cloakdata->eptentry[cpunr]` (Intel) or `npentry` (AMD).
    - Intel: set EPT PTE to execute‑only (if supported) or execute but block reads/writes (`RA=0,WA=0`, `XA=1/0`).
    - AMD: set NPT PTE to point at `PhysicalAddressData`, readable but `EXB=1` (no execute).
    - Mark `eptUpdated=1`.
  - Insert into the cloaked pages map/list and `ept_invalidate()`.

On Execute/R/W access to the cloaked page: `ept_handleCloakEvent(...)`
- Intel:
  - Inspect `EPT_VIOLATION_INFO` and (optionally) detect MEGAJMP patterns to decide which PFN to expose (executable vs data).
  - Temporarily set the PTE to RWX (or adequate allow) and single‑step; track last write offset.
- AMD:
  - Swap NPT PTE to `PhysicalAddressExecutable` and clear `EXB` to allow execution.
  - If `mode==0`, single‑step then revert; if `mode==1`, mark all other pages non‑executable until next NPF (`NPMode1CloakSetState`).

After step: `ept_handleCloakEventAfterStep(...)`
- Intel: restore EPT PTE to execute‑only (or execute with R/W blocked).
- AMD: restore NPT PTE back to the data PFN with `EXB=1`.
- Invalidate EPT/NP (`ept_invalidate()`).

Utilities:
- Read/Write original page buffers from guest: `ept_cloak_readOriginal`, `ept_cloak_writeOriginal` (advance RIP afterwards).
- `ept_cloak_deactivate` fully restores the page and frees resources.


## EPT/NP Invalidation

- Intel: INVEPT single/all‑context using current `EPTPML4` in `ept_invalidate()`; optional INVVPID calls elsewhere for VPID maintenance.
- AMD: Clear VMCB clean bit and set `TLB_CONTROL=1` to invalidate.


## Passwords and Stealth Defaults

- Default passwords are initialized in `dbvm/vmm/main.c` (e.g., `Password1=0x76543210`, `Password2=0xfedcba98`, `Password3=0x90909090`).
- Public `VMCALL_GETVERSION` returns 0, masking DBVM presence. Use `VMCALL_GETVERSION_PRIVATE` for trusted detection.


## Quick File Jump List

- Intel VM‑exit switch: `dbvm/vmm/vmeventhandler.c`
- AMD VM‑exit switch: `dbvm/vmm/vmeventhandler_amd.c`
- EPT map/handlers: `dbvm/vmm/epthandler.c`, structs in `dbvm/vmm/eptstructs.h`
- NP map/handlers (AMD): `dbvm/vmm/nphandler.c`
- VMCALL IDs: `dbvm/vmm/vmcall.h`; param structs: `dbvm/vmm/vmcallstructs.h`; dispatcher: `dbvm/vmm/vmcall.c`
- VMX setup: `dbvm/vmm/vmxsetup.c`; nested VMX emu: `dbvm/vmm/vmxemu.c`
- Per‑CPU state: `dbvm/vmm/vmmhelper.h`

