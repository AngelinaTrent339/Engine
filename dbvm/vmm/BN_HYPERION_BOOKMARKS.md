Hyperion/Byfron Early-Startup Bookmarks (Binary Ninja)

Base: 0x7ffc541d0000

- Byfron_Dispatcher: 0x7ffc5444d5e0 (RVA 0x0027d5e0)
  - Guard: Dispatcher_GuardCounter 0x7ffc54404274

- Hyperion_SeedPath: 0x7ffc54f75b20 (RVA 0x00da5b20)
  - Dynamic call site: 0x7ffc54f75c4b (short-circuit target)
  - RDTSC loop start: 0x7ffc54f75d61
  - SeedTable_Buffer: 0x7ffc54408180
  - SeedTable_InitFlag: 0x7ffc54408544
  - Work A/B/C: 0x7ffc544088e8 / 0x7ffc544088f0 / 0x7ffc544088f8

- Crash/UI hub: 0x7ffc54f24540 (RVA 0x00d54540)
  - Raise edge: 0x7ffc54f246a5
  - RaiseException wrapper: 0x7ffc54f73b10

- Hyperion_Deleter2_StartDetection: 0x7ffc54efa2e0 (RVA 0x00d2a2e0)
- Hyperion_Deleter2_EndDetection:   0x7ffc54f478e0 (RVA 0x00d778e0)
- Hyperion_AllocateProtectedMemory: 0x7ffc54ee1c10 (RVA 0x00d11c10)
- Hyperion_FreeProtectedMemory:     0x7ffc54d5d760 (RVA 0x00b8d760)
- Hyperion_CpuID:                    0x7ffc5444bc40 (RVA 0x0027bc40)
- Hyperion_IceBPCaller:              0x7ffc54f24150 (RVA 0x00d54150)
- AntiDebug_Int1Ret:                 0x7ffc5444d840 (RVA 0x0027d840)
- AntiDebug_Int2D:                   0x7ffc5444d870 (RVA 0x0027d870)

Verification notes
- Dispatcher disassembly shows AX<<3 indexing, XOR of two tables, guard decrement, and jmp r10/jumptable.
- SeedPath disassembly shows RDTSC seeding, repeated reads from SeedTable_Buffer, and dynamic call at 0x7ffc54f75c4b.
- Xrefs confirm SeedTable_Buffer is consumed at the listed offsets and Byfron_Dispatcher references the guard counter.
- Deleter2 start/end call into functions observed under Crash/UI hub.

Use these as quick-jump anchors and validate runtime via:
- bp 0x7ffc5444d5e0; log AX/r10 then step into the callee
- ba r1 0x7ffc54408180; bp 0x7ffc54f75c4b to observe indirect call
- bp 0x7ffc54f246a5 / 0x7ffc54f73b10 for crash edges
