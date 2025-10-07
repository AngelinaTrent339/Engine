% DBVM Password‑Free Detection (Usermode)

This document describes a robust, password‑free method to detect Cheat Engine’s DBVM from usermode. It consolidates signals that are reliable in practice and details how to measure VM*CALL vs UD2 timings in a stable way.

## Goals
- No passwords or handshakes needed for detection.
- Strong confirm signals that are not timing‑dependent.
- Stable timing methodology for supporting evidence.
- Clear decision ladder with representative logs (DBVM off/on).

## Primary, Password‑Free Signals
- PF‑first on VM*CALL (REMOVED — fixed in DBVM)
  - DBVM has been updated so that a ring‑3 VMCALL/VMMCALL with invalid credentials never touches guest memory and always injects #UD first. Any attempt to rely on “page‑fault‑first” semantics no longer applies.
  - Current behavior (post‑fix):
    - DBVM loaded: first exception is ILLEGAL_INSTRUCTION (0xC000001D), identical to bare‑metal.
    - No DBVM: first exception is ILLEGAL_INSTRUCTION (0xC000001D).
  - Policy impact: Detectors must not use PF‑first as a confirm signal anymore.

- Descriptor‑table fingerprint (CONFIRMS when present)
  - Some DBVM builds patch guest descriptor tables to avoid SIDT/SGDT detection: IDTR limit = 8*256 (2048), GDTR limit = 88.
  - If idtr_limit == 2048 && gdtr_limit == 88 → DBVM_CONFIRMED, reason “IDTR=2048 & GDTR=88 (DBVM patch)”.
  - If your system shows normal Windows values (IDTR ≈ 0x0FFF, GDTR ≈ 0x007F), this signal is simply absent.

- RIP‑advance anomaly on #UD (CONFIRMS when present)
  - On some builds, a failing VM*CALL/VMMCALL advances RIP ≥ 3 bytes when injecting #UD.
  - If detected → DBVM_CONFIRMED with reason.

## Stable Timing Side‑Channel (Password‑Free)
The side‑channel compares the cost of the injected‑#UD path for VM*CALL/VMMCALL vs UD2. Policy is now pairwise‑only.

Implementation details that reduce variance:
- Affinity: Pin the measuring thread to a single CPU.
- Priority: Set thread priority to TIME_CRITICAL and disable priority boost during the window.
- Serialization: Wrap RDTSC with LFENCE before and after to reduce out‑of‑order skew.
- Sample count: 512 iterations/path by default (override with DBVM_MEASURE_ITERS, allowed 64–4096).
- Outlier control: Sort accepted samples and compute a 5% trimmed summary (trim 5% each tail) for mean/min/max and p50/p90/p99. This kills ISR/DPC spikes that previously exploded p90/p99.
- Preemption gating (QueryThreadCycleTime): For each iteration, compute thread_cycles vs rdtsc_cycles; drop the sample when `thread_cycles * 100 < rdtsc_cycles * qtc_min_share` (default 40%). Continue until N accepted samples are collected (retry attempts up to N×4).
- Warm‑up & lock: 32 warm‑up iterations per path before timing; code stubs are `VirtualLock`’d to remove demand page faults.
- AMD path selection: We measure both VMCALL and VMMCALL; the slower path is reported as vmcall_*.

Pairwise‑only thresholds (timing policy):
- Interleave per‑iteration and compute delta = vmcall_dt − ud2_dt.
- Decision: `delta_p50 >= 1800` cycles AND `delta_p90 >= 2300` cycles (tune per host). Env overrides: `DBVM_DELTA_P50_MIN`, `DBVM_DELTA_P90_MIN`.
  - On bare metal (no DBVM), deltas are near zero (e.g., p50≈36, p90≈108 in your logs) → will not trigger.
  - With DBVM loaded, deltas are thousands of cycles → triggers cleanly.

## Decision Ladder (Password‑Free)
1) Descriptor fingerprint present?
   - Yes → DBVM_CONFIRMED (reason: IDTR=2048 & GDTR=88).
2) RIP‑advance on #UD?
   - Yes → DBVM_CONFIRMED.
3) Timing side‑channel (pairwise only) meets delta thresholds?
   - Yes → DBVM_SUSPECT.
4) If CPUID hypervisor bit set but no DBVM signature → OTHER_HYPERVISOR.
5) Else → NO_HYPERVISOR.

## Representative Logs
The outputs below come from the detector’s CLI with the password‑free policy described above.

### No DBVM Loaded
```
result=NO_HYPERVISOR
reason=No DBVM indicators detected
hv_present_bit=0
vmcall_ud_cycles=4812
ud2_ud_cycles=4739
vmcall_ud_min=4788 vmcall_ud_max=4860
vmcall_p50=4824 vmcall_p90=4860 vmcall_p99=5004
ud2_ud_min=4680 ud2_ud_max=5076
ud2_p50=4716 ud2_p90=4788 ud2_p99=7920
fault_semantics_vmcall_exc=0x00000000
fault_semantics_vmmcall_exc=0x00000000
cpuid_0d_ecx_low16=0x0988
xcr0_low32=0x00000007
used_vmmcall=0
idtr_limit=0x0FFF
gdtr_limit=0x007F
idtr_base=0xFFFFF80000001000
gdtr_base=0xFFFFF8534B590000
vmcall_rip_advance=0
vmmcall_rip_advance=0
pref_vmcall_rip_advance=0
pref_vmmcall_rip_advance=0
vmcall_first_exc=0xC000001D vmcall_first_eflags=0x00010306
ud2_first_exc=0xC000001D ud2_first_eflags=0x00010246
rf_delta_signal=0
tf_exc_count=4
tf_exc_0_code=0xC000001D tf_exc_0_eflags=0x00010306
tf_exc_1_code=0xC000001D tf_exc_1_eflags=0x00010306
tf_exc_2_code=0xC000001D tf_exc_2_eflags=0x00010306
tf_exc_3_code=0xC000001D tf_exc_3_eflags=0x00010306
signals=TF- TFpref- SVM+ DESC-
cpu_vendor=AuthenticAMD
cpuid_80000001_ecx=0x75C237FF
cpuid_8000000a_eax=0x00000001
cpuid_8000000a_ebx=0x00008000
cpuid_8000000a_ecx=0x00000000
cpuid_8000000a_edx=0x101BBCFF
syscall_mean=515
syscall_min=504
syscall_max=684
vm_ud_vmcall_cycles=4812
vm_ud_vmmcall_cycles=4776
```

### DBVM Loaded (PF‑First Confirm)
```
result=DBVM_CONFIRMED
reason=VM*CALL first exception ACCESS_VIOLATION
dbvm_version=0x000000
hv_present_bit=0
vmcall_ud_cycles=7756
ud2_ud_cycles=5127
vmcall_ud_min=7704 vmcall_ud_max=7884
vmcall_p50=7740 vmcall_p90=7812 vmcall_p99=7956
ud2_ud_min=4788 ud2_ud_max=8208
ud2_p50=4860 ud2_p90=7560 ud2_p99=9216
fault_semantics_vmcall_exc=0x00000000
fault_semantics_vmmcall_exc=0x00000000
cpuid_0d_ecx_low16=0x0988
xcr0_low32=0x00000007
used_vmmcall=0
idtr_limit=0x0FFF
gdtr_limit=0x007F
idtr_base=0xFFFFF80000001000
gdtr_base=0xFFFFF8534B590000
vmcall_rip_advance=0
vmmcall_rip_advance=0
pref_vmcall_rip_advance=0
pref_vmmcall_rip_advance=0
vmcall_first_exc=0xC000001D vmcall_first_eflags=0x00010302
ud2_first_exc=0xC000001D ud2_first_eflags=0x00010246
rf_delta_signal=0
tf_exc_count=4
tf_exc_0_code=0xC0000005 tf_exc_0_eflags=0x00010306
tf_exc_1_code=0xC0000005 tf_exc_1_eflags=0x00010306
tf_exc_2_code=0xC0000005 tf_exc_2_eflags=0x00010306
tf_exc_3_code=0xC0000005 tf_exc_3_eflags=0x00010306
signals=TF- TFpref- SVM- DESC-
cpu_vendor=AuthenticAMD
cpuid_80000001_ecx=0x75C237FF
cpuid_8000000a_eax=0x00000001
cpuid_8000000a_ebx=0x00008000
cpuid_8000000a_ecx=0x00000000
cpuid_8000000a_edx=0x101BBCFF
syscall_mean=560
syscall_min=540
syscall_max=1260
vm_ud_vmcall_cycles=4967
vm_ud_vmmcall_cycles=7756
```

```
result=DBVM_CONFIRMED
reason=VM*CALL first exception ACCESS_VIOLATION
dbvm_version=0x000000
hv_present_bit=0
vmcall_ud_cycles=7784
ud2_ud_cycles=4863
vmcall_ud_min=7740 vmcall_ud_max=7884
vmcall_p50=7776 vmcall_p90=7848 vmcall_p99=8064
ud2_ud_min=4824 ud2_ud_max=4932
ud2_p50=4860 ud2_p90=4896 ud2_p99=5040
fault_semantics_vmcall_exc=0x00000000
fault_semantics_vmmcall_exc=0x00000000
cpuid_0d_ecx_low16=0x0988
xcr0_low32=0x00000007
used_vmmcall=0
idtr_limit=0x0FFF
gdtr_limit=0x007F
idtr_base=0xFFFFF80000001000
gdtr_base=0xFFFFF8534B590000
vmcall_rip_advance=0
vmmcall_rip_advance=0
pref_vmcall_rip_advance=0
pref_vmmcall_rip_advance=0
vmcall_first_exc=0xC000001D vmcall_first_eflags=0x00010302
ud2_first_exc=0xC000001D ud2_first_eflags=0x00010246
rf_delta_signal=0
tf_exc_count=4
tf_exc_0_code=0xC0000005 tf_exc_0_eflags=0x00010302
tf_exc_1_code=0xC0000005 tf_exc_1_eflags=0x00010302
tf_exc_2_code=0xC0000005 tf_exc_2_eflags=0x00010302
tf_exc_3_code=0xC0000005 tf_exc_3_eflags=0x00010302
signals=TF- TFpref- SVM- DESC-
cpu_vendor=AuthenticAMD
cpuid_80000001_ecx=0x75C237FF
cpuid_8000000a_eax=0x00000001
cpuid_8000000a_ebx=0x00008000
cpuid_8000000a_ecx=0x00000000
cpuid_8000000a_edx=0x101BBCFF
syscall_mean=560
syscall_min=540
syscall_max=1260
vm_ud_vmcall_cycles=4984
vm_ud_vmmcall_cycles=7784
```

## Usage & Tunables
- Default (password‑free):
  - `build/Release/dbvm_detect_cli.exe`
- Increase sample size:
  - `set DBVM_MEASURE_ITERS=1024`
- Disable PF‑first confirm (not recommended for your case):
  - `set DBVM_DISABLE_PF_CONFIRM=1`

## Notes
- PF‑first confirm is independent of timing and passwords and is the most reliable primary signal on your hardware.
- Timing is now measured with serialization, CPU pinning, priority control, and trimmed summaries to keep percentiles stable between runs.
- Descriptor and RIP‑advance confirms are opportunistic; if absent, timing+PF‑first still suffice.
