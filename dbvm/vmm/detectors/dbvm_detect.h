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
  uint64_t vmcall_ud_cycles;       // avg cycles max(vmcall,vmmcall)->#UD path
  uint64_t ud2_ud_cycles;          // avg cycles ud2->#UD path
  uint32_t cpuid_0d_ecx_low16;     // leaf 0x0D, subleaf 0, ECX low16
  uint32_t xcr0_low32;             // XGETBV(0) low 32
  uint8_t  used_vmmcall;           // 1 if AMD VMMCALL path used
  // Debug: individual measurements
  uint64_t vm_ud_vmcall_cycles;    // raw vmcall #UD avg cycles
  uint64_t vm_ud_vmmcall_cycles;   // raw vmmcall #UD avg cycles
  // Descriptor table snapshots
  uint16_t idtr_limit;             // SIDT limit (expect ~0x0FFF on Win x64)
  uint16_t gdtr_limit;             // SGDT limit (OS-dependent, but never 0x0058)
} dbvm_detect_info_t;

// Runs detection. Fills info with measurements and decision.
// Returns info->result for convenience.
dbvm_detect_result_t dbvm_detect_run(dbvm_detect_info_t* info);

#ifdef __cplusplus
}
#endif
