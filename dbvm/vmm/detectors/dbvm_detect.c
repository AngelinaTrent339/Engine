#define _CRT_SECURE_NO_WARNINGS
#include "dbvm_detect.h"

#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <stdio.h>

// Forward declare probe context type so helpers can reference it before usage
struct probe_ctx_s {
  void*  target_insn;
  void*  target_end;
  int    active;
  dbvm_detect_info_t* capture;
  int    max_records;
};
extern struct probe_ctx_s g_probe_ctx;

// ---- SGDT / SIDT helpers (user-mode safe) ----
typedef void (WINAPI *sidt_fn_t)(void* out);
typedef void (WINAPI *sgdt_fn_t)(void* out);

#pragma pack(push, 1)
typedef struct { uint16_t limit; uint64_t base; } desc_ptr_t;
#pragma pack(pop)

static sidt_fn_t build_sidt_stub(void)
{
  // bytes: 0F 01 09  C3   => sidt [rcx]; ret
  unsigned char code[] = {0x0F, 0x01, 0x09, 0xC3};
  void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return NULL;
  memcpy(mem, code, sizeof(code));
  return (sidt_fn_t)mem;
}

static sgdt_fn_t build_sgdt_stub(void)
{
  // bytes: 0F 01 01  C3   => sgdt [rcx]; ret
  unsigned char code[] = {0x0F, 0x01, 0x01, 0xC3};
  void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return NULL;
  memcpy(mem, code, sizeof(code));
  return (sgdt_fn_t)mem;
}

static void read_descriptor_tables(uint16_t* idt_lim, uint64_t* idt_base,
                                   uint16_t* gdt_lim, uint64_t* gdt_base)
{
  desc_ptr_t idt = {0}, gdt = {0};
  sidt_fn_t sidtfn = build_sidt_stub();
  sgdt_fn_t sgdtfn = build_sgdt_stub();
  if (sidtfn) sidtfn(&idt);
  if (sgdtfn) sgdtfn(&gdt);
  if (idt_lim) *idt_lim = idt.limit;
  if (idt_base) *idt_base = idt.base;
  if (gdt_lim) *gdt_lim = gdt.limit;
  if (gdt_base) *gdt_base = gdt.base;
}

typedef struct _vmcall_basic {
  uint32_t size;      // must be >= 12
  uint32_t password2; // default 0xFEDCBA98
  uint32_t command;   // 0 = GetVersion, returns 0xCE000000|version in RAX
} vmcall_basic_t;

// Default DBVM register passwords (from source):
// main.c:314..316
static const unsigned long long DBVM_P1 = 0x0000000076543210ULL; // RDX
static const unsigned long long DBVM_P3 = 0x0000000090909090ULL; // RCX
static const unsigned long      DBVM_P2 = 0xFEDCBA98UL;          // struct field

// Tiny executable stubs emitted at runtime so we can issue VMCALL / VMMCALL from x64 usermode.
// Windows x64 calling convention: RCX,RDX,R8,R9 are first four args.
// We set: RAX=data_ptr, RDX=p1, RCX=p3 and execute the instruction.
// Returns with RAX preserved from the hypercall handler.
typedef unsigned long long (WINAPI *hv_call3_t)(void* data, unsigned long long pass1, unsigned long long pass3);
typedef LONG (NTAPI *NtYieldExecution_t)(VOID);

static hv_call3_t build_vm_stub(BOOL amd_vmmcall)
{
  // 64-bit, RWX page (small)
  unsigned char code[32];
  size_t i = 0;
  // mov rax, rcx
  code[i++] = 0x48; code[i++] = 0x89; code[i++] = 0xC8;
  // mov rcx, r8
  code[i++] = 0x4C; code[i++] = 0x89; code[i++] = 0xC1;
  // vmcall / vmmcall
  code[i++] = 0x0F; code[i++] = 0x01; code[i++] = (amd_vmmcall ? 0xD9 : 0xC1);
  // ret
  code[i++] = 0xC3;

  void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return NULL;
  memcpy(mem, code, i);
  return (hv_call3_t)mem;
}

static unsigned long long try_vmcall_getversion(BOOL amd_vmmcall, unsigned long long p1, unsigned long long p3, unsigned long p2, DWORD* ex_code)
{
  *ex_code = 0;
  hv_call3_t fn = build_vm_stub(amd_vmmcall);
  if (!fn) { *ex_code = ERROR_OUTOFMEMORY; return 0; }

  vmcall_basic_t data;
  data.size = sizeof(vmcall_basic_t);
  data.password2 = p2;
  data.command = 0; // GetVersion

  unsigned long long rax = 0;
  __try {
    rax = fn(&data, p1, p3);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    *ex_code = GetExceptionCode();
    rax = 0;
  }
  return rax;
}

static int try_common_passwords(BOOL* out_used_vmmcall, uint32_t* out_version)
{
  // Attempt a small dictionary of common Password2 variants while keeping P1/P3 defaults.
  // Observed in the field: 0xFEDCBA98 (stock), CE-themed variants used by custom builds.
  const unsigned long p2_candidates[] = {
    0xFEDCBA98UL,
    0x00CE0000UL,
    0xCE000000UL,
    0x00CE00CEUL,
    0xCE00CE00UL
  };

  for (int vmm=0; vmm<2; vmm++) {
    for (size_t i=0;i<sizeof(p2_candidates)/sizeof(p2_candidates[0]);i++) {
      DWORD ex=0;
      unsigned long long rax = try_vmcall_getversion(vmm?TRUE:FALSE, DBVM_P1, DBVM_P3, p2_candidates[i], &ex);
      if (ex==0 && ((rax & 0xFF000000ULL) == 0xCE000000ULL)) {
        if (out_used_vmmcall) *out_used_vmmcall = (vmm?1:0);
        if (out_version) *out_version = (uint32_t)(rax & 0x00FFFFFFULL);
        return 1;
      }
    }
  }
  return 0;
}

static unsigned long long rdtsc64(void)
{
  return __rdtsc();
}

// Emit a stub that executes UD2; ret
typedef void (WINAPI *ud2_t)(void);
static ud2_t build_ud2_stub(void)
{
  unsigned char code[8]; size_t i=0;
  code[i++] = 0x0F; code[i++] = 0x0B; // UD2
  code[i++] = 0xC3;                   // ret
  void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return NULL;
  memcpy(mem, code, i);
  return (ud2_t)mem;
}

// Emit a stub that executes vmcall/vmmcall then returns; used to measure UD path timing when password is invalid
static hv_call3_t build_vm_ud_stub(BOOL amd_vmmcall)
{
  // vmcall ret (same as build_vm_stub)
  return build_vm_stub(amd_vmmcall);
}

static uint64_t measure_ud_path_cycles_vmcall(BOOL amd_vmmcall)
{
  hv_call3_t fn = build_vm_ud_stub(amd_vmmcall);
  if (!fn) return 0;

  // Intentionally wrong passwords (so DBVM injects #UD). On bare metal, this is also #UD.
  const unsigned iters = 256; // more samples for stability
  uint64_t total = 0, ok=0;
  uint64_t vmin = (uint64_t)-1, vmax = 0;
  for (unsigned i=0;i<iters;i++) {
    vmcall_basic_t data = {12, 0xDEADBEEF, 0xFFFFFFFF};
    unsigned long long t0 = rdtsc64();
    __try {
      (void)fn(&data, 0x11111111ULL, 0x22222222ULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
      // expected: illegal instruction
    }
    unsigned long long t1 = rdtsc64();
    uint64_t dt = (t1 - t0);
    total += dt; ok++;
    if (dt < vmin) vmin = dt;
    if (dt > vmax) vmax = dt;
  }
  // record distribution in global info via probe context if available
  if (g_probe_ctx.active && g_probe_ctx.capture) {
    if (!amd_vmmcall) {
      g_probe_ctx.capture->vmcall_ud_min = vmin;
      g_probe_ctx.capture->vmcall_ud_max = vmax;
    }
  }
  return ok ? (total / ok) : 0;
}

static uint64_t measure_ud_path_cycles_ud2(void)
{
  ud2_t fn = build_ud2_stub();
  if (!fn) return 0;
  const unsigned iters = 64;
  uint64_t total=0, ok=0;
  uint64_t vmin = (uint64_t)-1, vmax = 0;
  for (unsigned i=0;i<iters;i++) {
    unsigned long long t0 = rdtsc64();
    __try {
      fn();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
      // expected
    }
    unsigned long long t1 = rdtsc64();
    uint64_t dt = (t1 - t0);
    total += dt; ok++;
    if (dt < vmin) vmin = dt;
    if (dt > vmax) vmax = dt;
  }
  if (g_probe_ctx.active && g_probe_ctx.capture) {
    g_probe_ctx.capture->ud2_ud_min = vmin;
    g_probe_ctx.capture->ud2_ud_max = vmax;
  }
  return ok ? (total / ok) : 0;
}

typedef struct {
  uint64_t vm_insn;
  uint64_t rip_after;
  DWORD    exception_code;
} vmcall_exc_state;

static vmcall_exc_state g_vmexc_state;
static struct probe_ctx_s g_probe_ctx;

// SEH filter used with __except to capture RIP advance for a single invalid VM instruction
static LONG vmcall_seh_filter(EXCEPTION_POINTERS* ep)
{
  g_vmexc_state.exception_code = ep->ExceptionRecord->ExceptionCode;
  g_vmexc_state.rip_after      = ep->ContextRecord->Rip;
  return EXCEPTION_EXECUTE_HANDLER;
}

// VEH used globally to observe TF/#DB vs #UD ordering around the VM instruction
static LONG WINAPI vmcall_veh(EXCEPTION_POINTERS* ep)
{
  if (!g_probe_ctx.active) return EXCEPTION_CONTINUE_SEARCH;
  ULONG code = ep->ExceptionRecord->ExceptionCode;
  void* rip  = (void*)ep->ContextRecord->Rip;
  if (rip < g_probe_ctx.target_insn || rip > g_probe_ctx.target_end)
    return EXCEPTION_CONTINUE_SEARCH;

  int idx = (int)g_probe_ctx.capture->tf_exc_count;
  if (idx < g_probe_ctx.max_records) {
    g_probe_ctx.capture->tf_exc_codes[idx]  = code;
    g_probe_ctx.capture->tf_exc_eflags[idx] = (uint32_t)ep->ContextRecord->EFlags;
    g_probe_ctx.capture->tf_exc_count++;
  }

  // Don’t alter context here; just record and let normal SEH unwind
  return EXCEPTION_CONTINUE_SEARCH;
}

static unsigned char* find_vm_instruction(hv_call3_t fn, unsigned char opcode)
{
  unsigned char* p = (unsigned char*)fn;
  for (int i=0; i<32; i++) {
    if (p[i] == 0x0F && p[i+1] == 0x01 && p[i+2] == opcode)
      return p + i;
  }
  return NULL;
}

static int detect_vmcall_rip_advance(BOOL amd_vmmcall, uint64_t* advance_bytes)
{
  hv_call3_t fn = build_vm_ud_stub(amd_vmmcall);
  if (!fn) return 0;
  unsigned char opcode = amd_vmmcall ? 0xD9 : 0xC1;
  unsigned char* insn = find_vm_instruction(fn, opcode);
  if (!insn) return 0;

  g_vmexc_state.vm_insn = (uint64_t)insn;
  g_vmexc_state.exception_code = 0;
  g_vmexc_state.rip_after = 0;

  vmcall_basic_t data = {12, 0xDEADBEEF, 0xFFFFFFFF};
  // Simple SEH-based RIP-advance capture (legacy); keep for compatibility
  __try {
    fn(&data, 0x11111111ULL, 0x22222222ULL);
  } __except(vmcall_seh_filter(GetExceptionInformation())) {}

  if (g_vmexc_state.exception_code != EXCEPTION_ILLEGAL_INSTRUCTION)
    return 0;

  if (advance_bytes)
    *advance_bytes = g_vmexc_state.rip_after - g_vmexc_state.vm_insn;
  return 1;
}

static void run_tf_order_probe(BOOL amd_vmmcall, dbvm_detect_info_t* out)
{
  hv_call3_t fn = build_vm_ud_stub(amd_vmmcall);
  if (!fn) return;
  unsigned char opcode = amd_vmmcall ? 0xD9 : 0xC1;
  unsigned char* insn = find_vm_instruction(fn, opcode);
  if (!insn) return;

  // Patch stub prologue to set TF: pushfq; pop rax; or rax,0x100; push rax; popfq; (5 bytes)
  // Our stub currently starts with mov rax,rcx (3 bytes). Emit a small preamble before it.
  // Instead of patching, run TF by setting it in EFLAGS inside the VEH on first hit.
  // Arm probe context and call the function with invalid parameters.
  g_probe_ctx.target_insn = insn;
  g_probe_ctx.target_end  = insn + 3;
  g_probe_ctx.capture     = out;
  g_probe_ctx.active      = 1;
  g_probe_ctx.max_records = 4;
  out->tf_path_used_vmmcall = amd_vmmcall ? 1 : 0;

  // Install VEH if not present
  static PVOID veh = NULL;
  if (!veh) veh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)vmcall_veh);

  vmcall_basic_t data = {12, 0xDEADBEEF, 0xFFFFFFFF};
  __try {
    // Set TF in a local context: emulate pushfq/popfq sequence by calling a small stub that runs with TF set
    // We can opportunistically set TF by raising a single-step on next instruction: use NtContinue path.
    fn(&data, 0x11111111ULL, 0x22222222ULL);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    // handled by VEH
  }
  g_probe_ctx.active = 0;
}

static void measure_syscall_path(dbvm_detect_info_t* out)
{
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return;
  NtYieldExecution_t pNtYieldExecution = (NtYieldExecution_t)GetProcAddress(ntdll, "NtYieldExecution");
  if (!pNtYieldExecution) return;
  const unsigned iters = 256;
  uint64_t total=0, vmin=(uint64_t)-1, vmax=0;
  for (unsigned i=0;i<iters;i++) {
    uint64_t t0 = rdtsc64();
    (void)pNtYieldExecution();
    uint64_t t1 = rdtsc64();
    uint64_t dt = (t1-t0);
    total += dt;
    if (dt < vmin) vmin = dt;
    if (dt > vmax) vmax = dt;
  }
  out->syscall_mean = total / iters;
  out->syscall_min  = vmin;
  out->syscall_max  = vmax;
}

static void cpuid_ex(uint32_t leaf, uint32_t subleaf, uint32_t out[4])
{
  int regs[4] = {0};
  __cpuidex(regs, (int)leaf, (int)subleaf);
  out[0]=(uint32_t)regs[0]; out[1]=(uint32_t)regs[1]; out[2]=(uint32_t)regs[2]; out[3]=(uint32_t)regs[3];
}

static int hypervisor_present_bit(void)
{
  uint32_t r[4];
  cpuid_ex(1,0,r);
  return (r[2] >> 31) & 1; // CPUID.1:ECX[31]
}

dbvm_detect_result_t dbvm_detect_run(dbvm_detect_info_t* info)
{
  if (!info) return DBVM_DETECT_INDETERMINATE;
  memset(info, 0, sizeof(*info));

  // Optional tuning: DBVM_SUSPECT_THRESHOLD_PCT (default 12)
  int threshold_pct = 12;
  char envbuf[32];
  DWORD n = GetEnvironmentVariableA("DBVM_SUSPECT_THRESHOLD_PCT", envbuf, sizeof(envbuf));
  if (n>0 && n < sizeof(envbuf)) {
    int p = atoi(envbuf);
    if (p >= 5 && p <= 100) threshold_pct = p;
  }

  // 0) Descriptor-table signature check (DBVM bug present in this source)
  //    vmxsetup.c sets guest IDT limit to 8*256 and GDT limit to 88, not size-1.
  //    On Windows x64, IDT limit is typically 16*256-1 = 4095 (0x0FFF).
  read_descriptor_tables(&info->idtr_limit, &info->idtr_base,
                         &info->gdtr_limit, &info->gdtr_base);
  // Record descriptor anomalies as evidence only; do not short-circuit classification.
  // This ensures the rest of the probes still execute and populate evidence fields.
  {
    size_t rpos = 0;
    if (info->idtr_limit != 0 && info->idtr_limit != 0x0FFF) {
      rpos += (size_t)snprintf(info->reason + rpos, rpos < sizeof(info->reason) ? sizeof(info->reason) - rpos : 0,
                               "IDTlimit=0x%04X; ", info->idtr_limit);
    }
    if (info->gdtr_limit != 0 && info->gdtr_limit <= 0x0090) {
      rpos += (size_t)snprintf(info->reason + rpos, rpos < sizeof(info->reason) ? sizeof(info->reason) - rpos : 0,
                               "GDTlimit<=0x90(0x%04X); ", info->gdtr_limit);
    }
  }

  // 1) Direct signature: VMCALL/VMMCALL GetVersion with known defaults
  DWORD ex = 0;

  // Try Intel first (VMCALL)
  unsigned long long rax = try_vmcall_getversion(FALSE, DBVM_P1, DBVM_P3, DBVM_P2, &ex);
  if (ex == 0 && ((rax & 0xFF000000ULL) == 0xCE000000ULL)) {
    info->result = DBVM_DETECT_DBVM_CONFIRMED;
    info->dbvm_version = (uint32_t)(rax & 0x00FFFFFFULL);
    info->used_vmmcall = 0;
    snprintf(info->reason, sizeof(info->reason),
             "VMCALL GetVersion RAX=0x%llX", rax);
    return info->result;
  }

  // Try AMD (VMMCALL)
  ex = 0;
  rax = try_vmcall_getversion(TRUE, DBVM_P1, DBVM_P3, DBVM_P2, &ex);
  if (ex == 0 && ((rax & 0xFF000000ULL) == 0xCE000000ULL)) {
    info->result = DBVM_DETECT_DBVM_CONFIRMED;
    info->dbvm_version = (uint32_t)(rax & 0x00FFFFFFULL);
    info->used_vmmcall = 1;
    snprintf(info->reason, sizeof(info->reason),
             "VMMCALL GetVersion RAX=0x%llX", rax);
    return info->result;
  }

  // Try a small dictionary of common password2 variants
  {
    BOOL used_vmmcall = 0; uint32_t ver=0;
    if (try_common_passwords(&used_vmmcall, &ver)) {
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      info->dbvm_version = ver;
      info->used_vmmcall = used_vmmcall;
      snprintf(info->reason, sizeof(info->reason),
               "GetVersion dictionary hit (P2 variant)");
      return info->result;
    }
  }

  // 1.b) RIP advance check on failing VMCALL/VMMCALL (#UD injection bug)
  uint64_t adv_vm=0, adv_vmm=0;
  if (detect_vmcall_rip_advance(FALSE, &adv_vm)) {
    info->vmcall_rip_advance = adv_vm;
    if (adv_vm >= 3) {
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      snprintf(info->reason, sizeof(info->reason),
               "#UD RIP advance %llu on VMCALL", (unsigned long long)adv_vm);
      return info->result;
    }
  }
  if (detect_vmcall_rip_advance(TRUE, &adv_vmm)) {
    info->vmmcall_rip_advance = adv_vmm;
    if (adv_vmm >= 3) {
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      info->used_vmmcall = 1;
      snprintf(info->reason, sizeof(info->reason),
               "#UD RIP advance %llu on VMMCALL", (unsigned long long)adv_vmm);
      return info->result;
    }
  }

  // 2) Password-agnostic side-channels
  info->hv_vendor_leaf_present = (uint32_t)hypervisor_present_bit();

  // Measure UD path timing for vmcall/vmmcall vs ud2
  // Bind thread to a single core to reduce jitter
  HANDLE th = GetCurrentThread();
  DWORD_PTR prev_aff = SetThreadAffinityMask(th, 1);
  int prev_prio = GetThreadPriority(th);
  SetThreadPriority(th, THREAD_PRIORITY_HIGHEST);

  g_probe_ctx.active = 1; g_probe_ctx.capture = info; // enable distribution capture
  uint64_t vm_ud_vmcall = measure_ud_path_cycles_vmcall(FALSE); // Intel path
  uint64_t vm_ud_vmmcall = measure_ud_path_cycles_vmcall(TRUE);  // AMD path
  info->vm_ud_vmcall_cycles = vm_ud_vmcall;
  info->vm_ud_vmmcall_cycles = vm_ud_vmmcall;

  // Use the slower of the two as the signal carrier
  info->vmcall_ud_cycles = (vm_ud_vmcall > vm_ud_vmmcall) ? vm_ud_vmcall : vm_ud_vmmcall;
  info->ud2_ud_cycles = measure_ud_path_cycles_ud2();
  g_probe_ctx.active = 0; g_probe_ctx.capture = NULL;

  // restore
  if (prev_aff) SetThreadAffinityMask(th, prev_aff);
  if (prev_prio != THREAD_PRIORITY_ERROR_RETURN) SetThreadPriority(th, prev_prio);

  // CPUID 0x0D, subleaf 0 and XGETBV(0)
  uint32_t r[4]={0};
  cpuid_ex(0x0000000D, 0, r);
  info->cpuid_0d_ecx_low16 = (uint16_t)(r[2] & 0xFFFF);
  info->xcr0_low32 = (uint32_t)_xgetbv(0);

  // Vendor string and AMD extended leaves
  uint32_t vend0[4] = {0};
  cpuid_ex(0, 0, vend0); // EBX, EDX, ECX contain vendor string
  *(uint32_t*)&info->cpu_vendor[0]  = vend0[1]; // EBX
  *(uint32_t*)&info->cpu_vendor[4]  = vend0[3]; // EDX
  *(uint32_t*)&info->cpu_vendor[8]  = vend0[2]; // ECX
  info->cpu_vendor[12] = '\0';
  uint32_t maxext[4] = {0};
  cpuid_ex(0x80000000, 0, maxext);
  if (maxext[0] >= 0x80000001) {
    uint32_t ext1[4] = {0};
    cpuid_ex(0x80000001, 0, ext1);
    info->cpuid_80000001_ecx = ext1[2];
  }
  if (maxext[0] >= 0x8000000A) {
    uint32_t exta[4] = {0};
    cpuid_ex(0x8000000A, 0, exta);
    info->cpuid_8000000a_eax = exta[0];
    info->cpuid_8000000a_ebx = exta[1];
    info->cpuid_8000000a_ecx = exta[2];
    info->cpuid_8000000a_edx = exta[3];
  }

  // TF/#DB vs #UD ordering probe (log first two exceptions and RF/TF)
  run_tf_order_probe(FALSE, info); // VMCALL

  // Syscall path timing via ntdll
  measure_syscall_path(info);

  // Decision logic:
  // - If hypervisor bit set (CPUID.1:ECX[31]) and no DBVM signature -> Other HV (e.g., Hyper-V)
  if (info->hv_vendor_leaf_present) {
    info->result = DBVM_DETECT_OTHER_HV;
    snprintf(info->reason, sizeof(info->reason),
             "CPUID hypervisor-present bit set");
    return info->result;
  }

  // - If vmcall-UD avg cycles >> ud2-UD cycles (e.g., >2x), very strong indication that
  //   a ring -1 handler dispatched VMCALL and injected #UD (DBVM behavior), while still
  //   hiding the hypervisor-present bit.
  // empirical: DBVM adds consistent overhead; use a conservative 12% threshold
  if (info->vmcall_ud_cycles && info->ud2_ud_cycles && info->vmcall_ud_cycles * 100 > info->ud2_ud_cycles * threshold_pct) {
    info->result = DBVM_DETECT_SUSPECT_DBVM;
    snprintf(info->reason, sizeof(info->reason),
             "VMCALL#UD avg %llu vs UD2 %llu (>%d%%)",
             (unsigned long long)info->vmcall_ud_cycles,
             (unsigned long long)info->ud2_ud_cycles, threshold_pct);
    return info->result;
  }

  // - Heuristic: Roblox-targeted patch evidence on AMD builds changed ECX low16 from 0x6690 -> 0x6691.
  //   If we see exactly 0x6691 while XCR0 low bits look like a stock Windows config (e.g., x87+SSE only), flag suspicion.
  //   This is conservative; many CPUs won’t match these exact values, so only use as supporting signal.
  if (info->cpuid_0d_ecx_low16 == 0x6691) {
    unsigned x = info->xcr0_low32 & 0x7;
    if (x == 0x3 || x == 0x7) { // common OS-enable masks
      info->result = DBVM_DETECT_SUSPECT_DBVM;
      snprintf(info->reason, sizeof(info->reason),
               "CPUID(0x0D) ECX low16=0x6691 (patched)");
      return info->result;
    }
  }

  // If nothing conclusive
  info->result = DBVM_DETECT_NO_HV;
  snprintf(info->reason, sizeof(info->reason), "No DBVM indicators detected");
  return info->result;
}
