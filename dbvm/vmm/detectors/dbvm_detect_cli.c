#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <string.h>
#include <conio.h>

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

static void print_text(const dbvm_detect_info_t* info, dbvm_detect_result_t r)
{
  printf("result=%s\n", result_to_str(r));
  if (r == DBVM_DETECT_DBVM_CONFIRMED)
    printf("dbvm_version=0x%06X\n", info->dbvm_version);
  printf("hv_present_bit=%u\n", info->hv_vendor_leaf_present);
  printf("vmcall_ud_cycles=%llu\n", (unsigned long long)info->vmcall_ud_cycles);
  printf("ud2_ud_cycles=%llu\n", (unsigned long long)info->ud2_ud_cycles);
  printf("cpuid_0d_ecx_low16=0x%04X\n", (unsigned)info->cpuid_0d_ecx_low16);
  printf("xcr0_low32=0x%08X\n", (unsigned)info->xcr0_low32);
  printf("used_vmmcall=%u\n", info->used_vmmcall);
}

static void print_json(const dbvm_detect_info_t* info, dbvm_detect_result_t r)
{
  printf("{\n");
  printf("  \"result\": \"%s\",\n", result_to_str(r));
  printf("  \"dbvm_version\": %u,\n", info->dbvm_version);
  printf("  \"hv_present_bit\": %u,\n", info->hv_vendor_leaf_present);
  printf("  \"vmcall_ud_cycles\": %llu,\n", (unsigned long long)info->vmcall_ud_cycles);
  printf("  \"ud2_ud_cycles\": %llu,\n", (unsigned long long)info->ud2_ud_cycles);
  printf("  \"cpuid_0d_ecx_low16\": %u,\n", (unsigned)info->cpuid_0d_ecx_low16);
  printf("  \"xcr0_low32\": %u,\n", (unsigned)info->xcr0_low32);
  printf("  \"used_vmmcall\": %u\n", info->used_vmmcall);
  printf("}\n");
}

int main(int argc, char** argv)
{
  int pause_after = 0;
  int json = 0;
  for (int i=1;i<argc;i++) {
    if (_stricmp(argv[i], "--pause")==0) pause_after=1;
    else if (_stricmp(argv[i], "--json")==0) json=1;
  }

  dbvm_detect_info_t info;
  dbvm_detect_result_t r = dbvm_detect_run(&info);

  if (json) print_json(&info, r);
  else      print_text(&info, r);
  fflush(stdout);

  // If launched without a console (double-click), show a message box so the window doesn't just disappear
  HWND cw = GetConsoleWindow();
  if (!cw && !json) {
    char buf[512];
    if (r == DBVM_DETECT_DBVM_CONFIRMED)
      snprintf(buf, sizeof(buf),
        "result=%s\ndbvm_version=0x%06X\nhv_present_bit=%u\nvmcall_ud_cycles=%llu\nud2_ud_cycles=%llu\ncpuid_0d_ecx_low16=0x%04X\nxcr0_low32=0x%08X\nused_vmmcall=%u",
        result_to_str(r), (unsigned)info.dbvm_version, info.hv_vendor_leaf_present,
        (unsigned long long)info.vmcall_ud_cycles, (unsigned long long)info.ud2_ud_cycles,
        (unsigned)info.cpuid_0d_ecx_low16, (unsigned)info.xcr0_low32, info.used_vmmcall);
    else
      snprintf(buf, sizeof(buf),
        "result=%s\nhv_present_bit=%u\nvmcall_ud_cycles=%llu\nud2_ud_cycles=%llu\ncpuid_0d_ecx_low16=0x%04X\nxcr0_low32=0x%08X\nused_vmmcall=%u",
        result_to_str(r), info.hv_vendor_leaf_present,
        (unsigned long long)info.vmcall_ud_cycles, (unsigned long long)info.ud2_ud_cycles,
        (unsigned)info.cpuid_0d_ecx_low16, (unsigned)info.xcr0_low32, info.used_vmmcall);
    MessageBoxA(NULL, buf, "DBVM Detector", MB_OK|MB_ICONINFORMATION);
  }

  if (pause_after && GetConsoleWindow()!=NULL) {
    printf("\nPress any key to exit...\n");
    _getch();
  }

  return (r == DBVM_DETECT_DBVM_CONFIRMED) ? 0 : 1;
}
