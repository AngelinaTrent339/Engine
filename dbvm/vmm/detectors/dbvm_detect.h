// Minimal, self-contained usermode DBVM detection API (Windows x64)
// Primary: DBVM-specific hypercall handshake (GetVersion)
// Secondary: Password-agnostic side-channels (vmcall vs ud2 latency + CPUID/XGETBV invariants)

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  DBVM_DETECT_NO_HV = 0,             // No hypervisor detected
  DBVM_DETECT_DBVM_CONFIRMED = 1,    // DBVM confirmed (GetVersion or signature)
  DBVM_DETECT_OTHER_HV = 2,          // Some HV present, not DBVM
  DBVM_DETECT_SUSPECT_DBVM = 3,      // Password-agnostic signals point to DBVM
  DBVM_DETECT_INDETERMINATE = 4      // Could not decide
} dbvm_detect_result_t;

typedef struct {
  dbvm_detect_result_t result;
  uint32_t dbvm_version;  // valid when result == DBVM_DETECT_DBVM_CONFIRMED
  uint32_t hv_vendor_leaf_present; // CPUID hypervisor-present bit
  char     reason[192];           // textual reason for final decision (expanded)
  char     cpu_vendor[13];        // CPUID vendor string
  uint64_t vmcall_ud_cycles;       // avg cycles max(vmcall,vmmcall)->#UD path
  uint64_t ud2_ud_cycles;          // avg cycles ud2->#UD path
  uint32_t cpuid_0d_ecx_low16;     // leaf 0x0D, subleaf 0, ECX low16
  uint32_t xcr0_low32;             // XGETBV(0) low 32
  // AMD-only extended CPUID captures
  uint32_t cpuid_80000001_ecx;     // SVM bit is ECX[2]
  uint32_t cpuid_8000000a_eax;
  uint32_t cpuid_8000000a_ebx;
  uint32_t cpuid_8000000a_ecx;
  uint32_t cpuid_8000000a_edx;
  uint8_t  used_vmmcall;           // 1 if AMD VMMCALL path used
  // Debug: individual measurements
  uint64_t vm_ud_vmcall_cycles;    // raw vmcall #UD avg cycles
  uint64_t vm_ud_vmmcall_cycles;   // raw vmmcall #UD avg cycles
  // Descriptor table snapshots
  uint16_t idtr_limit;             // SIDT limit (expect ~0x0FFF on Win x64)
  uint16_t gdtr_limit;             // SGDT limit (OS-dependent, but never 0x0058)
  uint64_t idtr_base;
  uint64_t gdtr_base;
  uint64_t vmcall_rip_advance;     // bytes RIP advanced after #UD (intel path)
  uint64_t vmmcall_rip_advance;    // bytes RIP advanced after #UD (amd path)
  // Prefixed variants (e.g., 66/F3/REX.W + VM*CALL) RIP advance after #UD
  uint64_t pref_vmcall_rip_advance;
  uint64_t pref_vmmcall_rip_advance;
  // First-exception snapshots for semantic diffs
  uint32_t vmcall_first_exc;       // first exception code seen around VM*CALL probe
  uint32_t vmcall_first_eflags;    // EFLAGS at that exception
  uint32_t ud2_first_exc;          // first exception code for UD2 probe
  uint32_t ud2_first_eflags;       // EFLAGS at that exception
  uint8_t  rf_delta_signal;        // 1 when RF bit differs VM*CALL vs UD2 on #UD-first
  // Password-free signals (for policy and debugging)
  uint8_t  sig_tf_plain;      // TF-first on plain VM*CALL (multi-try, cross-core)
  uint8_t  sig_tf_prefixed;   // TF-first on any prefixed VM*CALL (66/F3/F2/67/48), cross-core
  uint8_t  sig_svm_suite;     // TF-first/sequence hit on any two SVM opcodes (0F 01 D8..DF)
  uint8_t  sig_desc;          // SGDT/SIDT guest-style majority
  // TF/#DB vs #UD sequencing
  uint32_t tf_exc_count;           // number of exceptions captured (max 4)
  uint32_t tf_exc_codes[4];        // ordered exception codes
  uint32_t tf_exc_eflags[4];       // snapshot of EFLAGS for each exception (RF/TF bits)
  uint8_t  tf_path_used_vmmcall;   // 1 if AMD VMMCALL path probed
  // Timing distributions (basic)
  uint64_t vmcall_ud_min;
  uint64_t vmcall_ud_max;
  uint64_t ud2_ud_min;
  uint64_t ud2_ud_max;
  // Timing percentiles
  uint64_t vmcall_p50, vmcall_p90, vmcall_p99;
  uint64_t ud2_p50,    ud2_p90,    ud2_p99;
  // Syscall timing (via ntdll)
  uint64_t syscall_mean;
  uint64_t syscall_min;
  uint64_t syscall_max;
  uint64_t syscall2_mean; // NtQuerySystemTime
  uint64_t syscall2_min;
  uint64_t syscall2_max;
  // Fault-semantics probe: exception codes when calling VM instruction with NOACCESS vmcall struct pointer
  uint32_t vmcall_fault_exc;   // e.g., 0xC0000005 on DBVM, 0xC000001D/0xC0000096 otherwise
  uint32_t vmmcall_fault_exc;  // same as above (AMD only meaningful)
} dbvm_detect_info_t;

// Runs detection. Fills info with measurements and decision.
// Returns info->result for convenience.
dbvm_detect_result_t dbvm_detect_run(dbvm_detect_info_t* info);

#ifdef __cplusplus
}
#endif
