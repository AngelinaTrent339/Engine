#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

#include "dbvm_detect.h"

static const char* result_to_str(dbvm_detect_result_t r)
{
  switch (r) {
    case DBVM_DETECT_NO_HV: return "NO_HYPERVISOR";
    case DBVM_DETECT_DBVM_CONFIRMED: return "DBVM_CONFIRMED";
    case DBVM_DETECT_OTHER_HV: return "OTHER_HYPERVISOR";
    case DBVM_DETECT_SUSPECT_DBVM: return "DBVM_SUSPECT";
    case DBVM_DETECT_INDETERMINATE: return "INDETERMINATE";
    default: return "UNKNOWN";
  }
}

int main(int argc, char** argv)
{
  (void)argc; (void)argv;
  dbvm_detect_info_t info;
  dbvm_detect_result_t r = dbvm_detect_run(&info);

  printf("result=%s\n", result_to_str(r));
  if (r == DBVM_DETECT_DBVM_CONFIRMED)
    printf("dbvm_version=0x%06X\n", info.dbvm_version);
  printf("hv_present_bit=%u\n", info.hv_vendor_leaf_present);
  printf("vmcall_ud_cycles=%llu\n", (unsigned long long)info.vmcall_ud_cycles);
  printf("ud2_ud_cycles=%llu\n", (unsigned long long)info.ud2_ud_cycles);
  printf("cpuid_0d_ecx_low16=0x%04X\n", (unsigned)info.cpuid_0d_ecx_low16);
  printf("xcr0_low32=0x%08X\n", (unsigned)info.xcr0_low32);
  printf("used_vmmcall=%u\n", info.used_vmmcall);

  return (r == DBVM_DETECT_DBVM_CONFIRMED) ? 0 : 1;
}

