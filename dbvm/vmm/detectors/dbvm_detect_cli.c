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
  if (info->reason[0])
    printf("reason=%s\n", info->reason);
  if (r == DBVM_DETECT_DBVM_CONFIRMED)
    printf("dbvm_version=0x%06X\n", info->dbvm_version);
  printf("hv_present_bit=%u\n", info->hv_vendor_leaf_present);
  printf("vmcall_ud_cycles=%llu\n", (unsigned long long)info->vmcall_ud_cycles);
  printf("ud2_ud_cycles=%llu\n", (unsigned long long)info->ud2_ud_cycles);
  printf("vmcall_ud_min=%llu vmcall_ud_max=%llu\n", (unsigned long long)info->vmcall_ud_min, (unsigned long long)info->vmcall_ud_max);
  printf("ud2_ud_min=%llu ud2_ud_max=%llu\n", (unsigned long long)info->ud2_ud_min, (unsigned long long)info->ud2_ud_max);
  printf("cpuid_0d_ecx_low16=0x%04X\n", (unsigned)info->cpuid_0d_ecx_low16);
  printf("xcr0_low32=0x%08X\n", (unsigned)info->xcr0_low32);
  printf("used_vmmcall=%u\n", info->used_vmmcall);
  printf("idtr_limit=0x%04X\n", info->idtr_limit);
  printf("gdtr_limit=0x%04X\n", info->gdtr_limit);
  printf("idtr_base=0x%016llX\n", (unsigned long long)info->idtr_base);
  printf("gdtr_base=0x%016llX\n", (unsigned long long)info->gdtr_base);
  printf("vmcall_rip_advance=%llu\n", (unsigned long long)info->vmcall_rip_advance);
  printf("vmmcall_rip_advance=%llu\n", (unsigned long long)info->vmmcall_rip_advance);
  if (info->tf_exc_count) {
    printf("tf_exc_count=%u\n", info->tf_exc_count);
    for (uint32_t i=0;i<info->tf_exc_count;i++) {
      printf("tf_exc_%u_code=0x%08X tf_exc_%u_eflags=0x%08X\n", i, info->tf_exc_codes[i], i, info->tf_exc_eflags[i]);
    }
  }
  printf("cpu_vendor=%s\n", info->cpu_vendor);
  printf("cpuid_80000001_ecx=0x%08X\n", info->cpuid_80000001_ecx);
  printf("cpuid_8000000a_eax=0x%08X\n", info->cpuid_8000000a_eax);
  printf("cpuid_8000000a_ebx=0x%08X\n", info->cpuid_8000000a_ebx);
  printf("cpuid_8000000a_ecx=0x%08X\n", info->cpuid_8000000a_ecx);
  printf("cpuid_8000000a_edx=0x%08X\n", info->cpuid_8000000a_edx);
  printf("syscall_mean=%llu\n", (unsigned long long)info->syscall_mean);
  printf("syscall_min=%llu\n", (unsigned long long)info->syscall_min);
  printf("syscall_max=%llu\n", (unsigned long long)info->syscall_max);
}

static void print_json(const dbvm_detect_info_t* info, dbvm_detect_result_t r)
{
  printf("{\n");
  printf("  \"result\": \"%s\",\n", result_to_str(r));
  printf("  \"reason\": \"%s\",\n", info->reason);
  printf("  \"dbvm_version\": %u,\n", info->dbvm_version);
  printf("  \"hv_present_bit\": %u,\n", info->hv_vendor_leaf_present);
  printf("  \"vmcall_ud_cycles\": %llu,\n", (unsigned long long)info->vmcall_ud_cycles);
  printf("  \"ud2_ud_cycles\": %llu,\n", (unsigned long long)info->ud2_ud_cycles);
  printf("  \"vmcall_ud_min\": %llu, \"vmcall_ud_max\": %llu,\n", (unsigned long long)info->vmcall_ud_min, (unsigned long long)info->vmcall_ud_max);
  printf("  \"ud2_ud_min\": %llu, \"ud2_ud_max\": %llu,\n", (unsigned long long)info->ud2_ud_min, (unsigned long long)info->ud2_ud_max);
  printf("  \"cpuid_0d_ecx_low16\": %u,\n", (unsigned)info->cpuid_0d_ecx_low16);
  printf("  \"xcr0_low32\": %u,\n", (unsigned)info->xcr0_low32);
  printf("  \"used_vmmcall\": %u,\n", info->used_vmmcall);
  printf("  \"idtr_limit\": %u,\n", (unsigned)info->idtr_limit);
  printf("  \"gdtr_limit\": %u,\n", (unsigned)info->gdtr_limit);
  printf("  \"idtr_base\": %llu,\n", (unsigned long long)info->idtr_base);
  printf("  \"gdtr_base\": %llu,\n", (unsigned long long)info->gdtr_base);
  printf("  \"vmcall_rip_advance\": %llu,\n", (unsigned long long)info->vmcall_rip_advance);
  printf("  \"vmmcall_rip_advance\": %llu,\n", (unsigned long long)info->vmmcall_rip_advance);
  printf("  \"tf_exc\": [");
  for (uint32_t i=0;i<info->tf_exc_count;i++) {
    printf("{\"code\":%u,\"eflags\":%u}%s", info->tf_exc_codes[i], info->tf_exc_eflags[i], (i+1<info->tf_exc_count)?",":"");
  }
  printf("]\n");
  printf(",  \"cpu_vendor\": \"%s\",\n", info->cpu_vendor);
  printf("  \"cpuid_80000001_ecx\": %u,\n", info->cpuid_80000001_ecx);
  printf("  \"cpuid_8000000a\": { \"eax\":%u, \"ebx\":%u, \"ecx\":%u, \"edx\":%u },\n",
         info->cpuid_8000000a_eax, info->cpuid_8000000a_ebx, info->cpuid_8000000a_ecx, info->cpuid_8000000a_edx);
  printf("  \"syscall\": { \"mean\":%llu, \"min\":%llu, \"max\":%llu }\n",
         (unsigned long long)info->syscall_mean, (unsigned long long)info->syscall_min, (unsigned long long)info->syscall_max);
  printf("}\n");
}

int main(int argc, char** argv)
{
  int pause_after = 0;
  int json = 0;
  int policy_mode = 0;
  int policy_threshold = 60; // percent over UD2 mean
  int no_vm = 0;
  for (int i=1;i<argc;i++) {
    if (_stricmp(argv[i], "--pause")==0) pause_after=1;
    else if (_stricmp(argv[i], "--json")==0) json=1;
    else if (_stricmp(argv[i], "--policy")==0) policy_mode=1;
    else if (_strnicmp(argv[i], "--policy-threshold=", 20)==0) {
      int v = atoi(argv[i]+20);
      if (v>=10 && v<=300) policy_threshold=v;
    }
    else if (_stricmp(argv[i], "--no-vm")==0) no_vm=1;
  }

  if (no_vm) SetEnvironmentVariableA("DBVM_NO_VM", "1");

  dbvm_detect_info_t info;
  dbvm_detect_result_t r = dbvm_detect_run(&info);

  if (json) print_json(&info, r);
  else      print_text(&info, r);
  if (policy_mode && !json) {
    int likely = 0;
    double ud2 = (double) (info.ud2_ud_cycles ? info.ud2_ud_cycles : 1);
    double vmc = (double) info.vmcall_ud_cycles;
    double ratio = vmc / ud2;
    if (info.hv_vendor_leaf_present==0 && vmc >= (ud2 * (1.0 + (policy_threshold/100.0))))
      likely = 1;
    const char* arch = ( _stricmp(info.cpu_vendor, "AuthenticAMD")==0 ? "AMD" : (_stricmp(info.cpu_vendor, "GenuineIntel")==0?"INTEL":"OTHER") );
    printf("policy=%s ratio=%.2f threshold=%d%%\n", likely?"LIKELY_DBVM":"NO_DBVM", ratio, policy_threshold);
    printf("policy_arch=%s\n", arch);
  }
  // Debug raw channels
  if (!json) {
    printf("vm_ud_vmcall_cycles=%llu\n", (unsigned long long)info.vm_ud_vmcall_cycles);
    printf("vm_ud_vmmcall_cycles=%llu\n", (unsigned long long)info.vm_ud_vmmcall_cycles);
  }
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
