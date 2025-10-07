#define _CRT_SECURE_NO_WARNINGS
#include "dbvm_detect.h"

#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <stdio.h>
#include <emmintrin.h>

// Forward declare probe context type so helpers can reference it before usage
struct probe_ctx_s {
  void*  target_insn;
  void*  target_end;
  int    active;
  dbvm_detect_info_t* capture;
  int    max_records;
  uint64_t* rip_out; // when non-NULL, store RIP advance into this field on #UD
};
extern struct probe_ctx_s g_probe_ctx;

// Forward decls used before their definitions
static void cpuid_ex(uint32_t leaf, uint32_t subleaf, uint32_t out[4]);
static LONG WINAPI vmcall_veh(EXCEPTION_POINTERS* ep);

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

// UD2 probe with VEH capture of first exception (without TF prefixing)
typedef void (WINAPI *stub3_t)(void* a, unsigned long long b, unsigned long long c);
static stub3_t build_ud2_capture_stub(unsigned char** out_insn)
{
  unsigned char code[16]; size_t i=0;
  // UD2
  if (out_insn) *out_insn = &((unsigned char*)0)[i];
  code[i++]=0x0F; code[i++]=0x0B;
  // ret
  code[i++]=0xC3;
  void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return NULL;
  memcpy(mem, code, i);
  if (out_insn) *out_insn = ((unsigned char*)mem);
  return (stub3_t)mem;
}

static void capture_ud2_first_exc(dbvm_detect_info_t* out)
{
  out->tf_exc_count = 0;
  unsigned char* insn = NULL;
  stub3_t fn = build_ud2_capture_stub(&insn);
  if (!fn || !insn) return;
  g_probe_ctx.target_insn = insn;
  g_probe_ctx.target_end  = insn + 2;
  g_probe_ctx.capture     = out;
  g_probe_ctx.active      = 1;
  g_probe_ctx.max_records = 4;
  static PVOID veh = NULL; if (!veh) veh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)vmcall_veh);
  __try { fn(NULL, 0, 0); } __except(EXCEPTION_EXECUTE_HANDLER) {}
  g_probe_ctx.active = 0;
  if (out->tf_exc_count>=1) {
    out->ud2_first_exc = out->tf_exc_codes[0];
    out->ud2_first_eflags = out->tf_exc_eflags[0];
  }
}

static int sgdt_sidt_gueststyle_confirm(void)
{
  // Sample multiple times to avoid transient noise
  int idt_guest_like = 0;
  int gdt_guest_like = 0;
  for (int i=0;i<8;i++) {
    uint16_t idl=0, gdl=0; uint64_t ib=0, gb=0;
    read_descriptor_tables(&idl, &ib, &gdl, &gb);
    if (idl != 0 && idl != 0x0FFF && idl <= 0x0900) idt_guest_like++;
    if (gdl != 0 && gdl <= 0x0090) gdt_guest_like++;
    Sleep(0);
  }
  // Confirm only if both limits look guest-style in a majority of samples
  return (idt_guest_like >= 5 && gdt_guest_like >= 5);
}

// Helper: pick up to two distinct CPU affinity bits for cross-core repeats
static int pick_two_affinity_masks(DWORD_PTR* m1, DWORD_PTR* m2)
{
  DWORD_PTR procMask=0, sysMask=0;
  if (!GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask)) {
    *m1 = 1; *m2 = 0; return 1;
  }
  // pick first two bits in procMask
  DWORD_PTR first=0, second=0;
  for (DWORD i=0;i<sizeof(DWORD_PTR)*8;i++) {
    DWORD_PTR bit = ((DWORD_PTR)1)<<i;
    if (procMask & bit) { if (!first) first=bit; else { second=bit; break; } }
  }
  *m1 = first ? first : 1;
  *m2 = second; // may be 0 if single-core affinity
  return second ? 2 : 1;
}

// Generic: build a one-instruction TF probe (prefix(optional) + 0F 01 xx) and record if SINGLE_STEP arrives first
// probe_one_insn_tf_first is declared later after VEH/types are defined

// Cross-core wrapper: run lambda-like probe twice with different affinity masks
typedef int (*probe_fn_t)(void* ctx);
static int run_cross_core_consistent(probe_fn_t fn, void* ctx)
{
  DWORD_PTR m1=0,m2=0; int n = pick_two_affinity_masks(&m1,&m2);
  HANDLE th = GetCurrentThread();
  DWORD_PTR old = SetThreadAffinityMask(th, m1);
  int a = fn(ctx);
  int b = 0;
  if (n==2) {
    SetThreadAffinityMask(th, m2);
    b = fn(ctx);
  } else {
    b = a;
  }
  if (old) SetThreadAffinityMask(th, old);
  return (a && b) ? 1 : 0;
}

typedef struct _vmcall_basic {
  uint32_t size;      // must be >= 12
  uint32_t password2; // default 0xFEDCBA98
  uint32_t command;   // 0 = GetVersion, returns 0xCE000000|version in RAX
} vmcall_basic_t;

// Default DBVM register passwords (from source):
// main.c:314..316
static const unsigned long long DBVM_P1 = 0x0000000072543210ULL; // RDX
static const unsigned long long DBVM_P3 = 0x0000000030909090ULL; // RCX
static const unsigned long      DBVM_P2 = 0xFEDCBA48UL;          // struct field

// Tiny executable stubs emitted at runtime so we can issue VMCALL / VMMCALL from x64 usermode.
// Windows x64 calling convention: RCX,RDX,R8,R9 are first four args.
// We set: RAX=data_ptr, RDX=p1, RCX=p3 and execute the instruction.
// Returns with RAX preserved from the hypercall handler.
typedef unsigned long long (WINAPI *hv_call3_t)(void* data, unsigned long long pass1, unsigned long long pass3);
#if defined(_MSC_VER)
__declspec(guard(nocf)) static unsigned long long call_stub_nocf(hv_call3_t fp, void* data, unsigned long long p1, unsigned long long p3)
{
  return fp(data, p1, p3);
}
#else
static unsigned long long call_stub_nocf(hv_call3_t fp, void* data, unsigned long long p1, unsigned long long p3)
{
  return fp(data, p1, p3);
}
#endif
typedef LONG (NTAPI *NtYieldExecution_t)(VOID);
typedef LONG (NTAPI *NtQuerySystemTime_t)(PLARGE_INTEGER);

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

// Build a stub with optional prefixes before the VM instruction. Returns function and start of insn.
// Prefixed-stub variants disabled for now (reserved for future hardening)

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
    rax = call_stub_nocf(fn, &data, p1, p3);
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
  _mm_lfence();
  unsigned long long t = __rdtsc();
  _mm_lfence();
  return t;
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

// PROBE: Fault semantics when the vmcall struct pointer is NOACCESS
// On bare metal: executing VMCALL/VMMCALL in ring3 raises ILLEGAL/PRIV INSTRUCTION before dereferencing the pointer
// On DBVM: the hypervisor maps the guest pointer first; if NOACCESS, it injects a page fault (ACCESS_VIOLATION)
static DWORD probe_vmcall_fault_semantics(BOOL amd_vmmcall)
{
  hv_call3_t fn = build_vm_ud_stub(amd_vmmcall);
  if (!fn) return ERROR_OUTOFMEMORY;

  // Reserve 2 pages so we can make the first one NOACCESS
  SYSTEM_INFO si; GetSystemInfo(&si); SIZE_T pagesz = si.dwPageSize ? si.dwPageSize : 4096;
  SIZE_T allocsz = pagesz * 2;
  void* mem = VirtualAlloc(NULL, allocsz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
  if (!mem) return ERROR_OUTOFMEMORY;
  DWORD oldProt=0; VirtualProtect(mem, pagesz, PAGE_NOACCESS, &oldProt);
  // Pass a pointer in the NOACCESS page
  void* noacc_ptr = mem;

  vmcall_basic_t* data = (vmcall_basic_t*)noacc_ptr; // intentionally unreadable
  DWORD exc = 0;
  __try {
    // Use override if provided, else defaults
    unsigned long long p1 = DBVM_P1, p3 = DBVM_P3;
    char b1[32], b3[32];
    DWORD n1 = GetEnvironmentVariableA("DBVM_P1_OVERRIDE", b1, sizeof(b1));
    DWORD n3 = GetEnvironmentVariableA("DBVM_P3_OVERRIDE", b3, sizeof(b3));
    if (n1>0) p1 = _strtoui64(b1, NULL, 0);
    if (n3>0) p3 = _strtoui64(b3, NULL, 0);
    (void)fn((void*)data, p1, p3);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    exc = GetExceptionCode();
  }
  // Cleanup
  VirtualFree(mem, 0, MEM_RELEASE);
  return exc;
}

typedef struct timing_stats_s {
  uint64_t mean;
  uint64_t vmin;
  uint64_t vmax;
  uint64_t p50;
  uint64_t p90;
  uint64_t p99;
} timing_stats_t;

// Forward declarations for measurement helpers
static void measure_ud_path_cycles_vmcall(BOOL amd_vmmcall, timing_stats_t* out);
static void measure_ud_path_cycles_ud2(timing_stats_t* out);
static void measure_syscall_path(dbvm_detect_info_t* out);
static void measure_pairwise_delta(BOOL amd_vmmcall, timing_stats_t* out);

static void run_measurements(dbvm_detect_info_t* info, int no_vm)
{
  // Measure UD path timing for vmcall/vmmcall vs ud2 and syscall timing
  HANDLE th = GetCurrentThread();
  DWORD_PTR prev_aff = SetThreadAffinityMask(th, 1);
  int prev_prio = GetThreadPriority(th);
  SetThreadPriority(th, THREAD_PRIORITY_TIME_CRITICAL);
  SetThreadPriorityBoost(th, TRUE);

  g_probe_ctx.active = 0; g_probe_ctx.capture = NULL;
  timing_stats_t vm_vmcall_stats = {0}, vm_vmmcall_stats = {0}, ud2_stats = {0};
  uint64_t vm_ud_vmcall = 0, vm_ud_vmmcall = 0;
  if (!no_vm) {
    measure_ud_path_cycles_vmcall(FALSE, &vm_vmcall_stats);
    measure_ud_path_cycles_vmcall(TRUE,  &vm_vmmcall_stats);
    vm_ud_vmcall = vm_vmcall_stats.mean;
    vm_ud_vmmcall = vm_vmmcall_stats.mean;
  }
  info->vm_ud_vmcall_cycles = vm_ud_vmcall;
  info->vm_ud_vmmcall_cycles = vm_ud_vmmcall;
  BOOL use_amd_path = (vm_ud_vmmcall >= vm_ud_vmcall);
  info->vmcall_ud_cycles = use_amd_path ? vm_ud_vmmcall : vm_ud_vmcall;
  if (use_amd_path) {
    info->vmcall_ud_min = vm_vmmcall_stats.vmin;
    info->vmcall_ud_max = vm_vmmcall_stats.vmax;
    info->vmcall_p50    = vm_vmmcall_stats.p50;
    info->vmcall_p90    = vm_vmmcall_stats.p90;
    info->vmcall_p99    = vm_vmmcall_stats.p99;
  } else {
    info->vmcall_ud_min = vm_vmcall_stats.vmin;
    info->vmcall_ud_max = vm_vmcall_stats.vmax;
    info->vmcall_p50    = vm_vmcall_stats.p50;
    info->vmcall_p90    = vm_vmcall_stats.p90;
    info->vmcall_p99    = vm_vmcall_stats.p99;
  }
  measure_ud_path_cycles_ud2(&ud2_stats);
  info->ud2_ud_cycles = ud2_stats.mean;
  info->ud2_ud_min    = ud2_stats.vmin;
  info->ud2_ud_max    = ud2_stats.vmax;
  info->ud2_p50       = ud2_stats.p50;
  info->ud2_p90       = ud2_stats.p90;
  info->ud2_p99       = ud2_stats.p99;

  // Pairwise delta for chosen path (default enabled; disable with DBVM_DISABLE_PAIRWISE=1)
  {
    char disbuf[4]; DWORD dis = GetEnvironmentVariableA("DBVM_DISABLE_PAIRWISE", disbuf, sizeof(disbuf));
    if (!(dis>0 && disbuf[0]=='1')) {
      timing_stats_t d = {0};
      measure_pairwise_delta(use_amd_path ? TRUE : FALSE, &d);
      info->delta_mean = d.mean;
      info->delta_min  = d.vmin;
      info->delta_max  = d.vmax;
      info->delta_p50  = d.p50;
      info->delta_p90  = d.p90;
      info->delta_p99  = d.p99;
    }
  }

  // Syscall path timing
  measure_syscall_path(info);

  if (prev_aff) SetThreadAffinityMask(th, prev_aff);
  if (prev_prio != THREAD_PRIORITY_ERROR_RETURN) SetThreadPriority(th, prev_prio);
}

static void measure_ud_path_cycles_vmcall(BOOL amd_vmmcall, timing_stats_t* out)
{
  hv_call3_t fn = build_vm_ud_stub(amd_vmmcall);
  if (!fn) { if (out) memset(out, 0, sizeof(*out)); return; }

  // Intentionally wrong passwords (so DBVM injects #UD). On bare metal, this is also #UD.
  unsigned iters = 512; // more samples for stability
  char ibuf[16]; DWORD nn = GetEnvironmentVariableA("DBVM_MEASURE_ITERS", ibuf, sizeof(ibuf));
  if (nn>0) { unsigned v=(unsigned)atoi(ibuf); if (v>=64 && v<=4096) iters=v; }
  // Warm-up to fill icache and page tables
  for (int w=0; w<32; w++) {
    vmcall_basic_t data_w = {12, 0xDEADBEEF, 0xFFFFFFFF};
    __try { (void)call_stub_nocf(fn, &data_w, 0x11111111ULL, 0x22222222ULL); } __except(EXCEPTION_EXECUTE_HANDLER) {}
  }
  uint64_t total = 0, ok=0;
  uint64_t vmin = (uint64_t)-1, vmax = 0;
  uint64_t samples[1024]; unsigned sc=0;
  for (unsigned i=0;i<iters;i++) {
    vmcall_basic_t data = {12, 0xDEADBEEF, 0xFFFFFFFF};
    unsigned long long t0 = rdtsc64();
  __try {
      (void)call_stub_nocf(fn, &data, 0x11111111ULL, 0x22222222ULL);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
      // expected: illegal instruction
    }
    unsigned long long t1 = rdtsc64();
    uint64_t dt = (t1 - t0);
    total += dt; ok++;
    if (dt < vmin) vmin = dt;
    if (dt > vmax) vmax = dt;
    if (sc<1024) samples[sc++]=dt;
  }
  // summarize
  if (out) {
    for (unsigned i=1;i<sc;i++){ uint64_t key=samples[i]; int j=(int)i-1; while (j>=0 && samples[j]>key){ samples[j+1]=samples[j]; j--; } samples[j+1]=key; }
    unsigned lo = sc/20; unsigned hi = sc - lo; if (hi<=lo) { lo=0; hi=sc; }
    uint64_t tsum=0; for (unsigned i=lo;i<hi;i++) tsum+=samples[i];
    unsigned kept = (hi>lo)? (hi-lo):sc;
    out->mean = kept ? (tsum / kept) : 0;
    out->vmin = kept? samples[lo] : vmin;
    out->vmax = kept? samples[hi-1] : vmax;
    out->p50 = kept? samples[lo + (kept*50/100)] : 0;
    out->p90 = kept? samples[lo + (kept*90/100)] : 0;
    out->p99 = kept? samples[lo + (kept*99/100)] : 0;
  }
}

static void measure_ud_path_cycles_ud2(timing_stats_t* out)
{
  ud2_t fn = build_ud2_stub();
  if (!fn) { if (out) memset(out, 0, sizeof(*out)); return; }
  // Match VMCALL sample count to reduce variance
  unsigned iters = 512;
  char ibuf2[16]; DWORD nn2 = GetEnvironmentVariableA("DBVM_MEASURE_ITERS", ibuf2, sizeof(ibuf2));
  if (nn2>0) { unsigned v=(unsigned)atoi(ibuf2); if (v>=64 && v<=4096) iters=v; }
  // Warm-up
  for (int w=0; w<32; w++) { __try { fn(); } __except(EXCEPTION_EXECUTE_HANDLER) {} }
  uint64_t total=0, ok=0;
  uint64_t vmin = (uint64_t)-1, vmax = 0;
  uint64_t samples[1024]; unsigned sc=0;
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
    if (sc<1024) samples[sc++]=dt;
  }
  if (out) {
    for (unsigned i=1;i<sc;i++){ uint64_t key=samples[i]; int j=(int)i-1; while (j>=0 && samples[j]>key){ samples[j+1]=samples[j]; j--; } samples[j+1]=key; }
    unsigned lo = sc/20; unsigned hi = sc - lo; if (hi<=lo) { lo=0; hi=sc; }
    uint64_t tsum=0; for (unsigned i=lo;i<hi;i++) tsum+=samples[i];
    unsigned kept = (hi>lo)? (hi-lo):sc;
    out->mean = kept ? (tsum / kept) : 0;
    out->vmin = kept? samples[lo] : vmin;
    out->vmax = kept? samples[hi-1] : vmax;
    out->p50 = kept? samples[lo + (kept*50/100)] : 0;
    out->p90 = kept? samples[lo + (kept*90/100)] : 0;
    out->p99 = kept? samples[lo + (kept*99/100)] : 0;
  }
}

// Interleaved pairwise measurement: delta = (vmcall_dt - ud2_dt)
static void measure_pairwise_delta(BOOL amd_vmmcall, timing_stats_t* out)
{
  if (out) memset(out, 0, sizeof(*out));
  hv_call3_t fn_vm = build_vm_ud_stub(amd_vmmcall);
  ud2_t fn_ud = build_ud2_stub();
  if (!fn_vm || !fn_ud) return;
  unsigned iters = 512;
  char ibuf[16]; DWORD nn = GetEnvironmentVariableA("DBVM_MEASURE_ITERS", ibuf, sizeof(ibuf));
  if (nn>0) { unsigned v=(unsigned)atoi(ibuf); if (v>=64 && v<=4096) iters=v; }
  uint64_t samples[1024]; unsigned sc=0;
  // Warm-up
  for (int w=0; w<32; w++) {
    vmcall_basic_t data_w = {12, 0xDEADBEEF, 0xFFFFFFFF};
    __try { (void)call_stub_nocf(fn_vm, &data_w, 0x11111111ULL, 0x22222222ULL); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    __try { fn_ud(); } __except(EXCEPTION_EXECUTE_HANDLER) {}
  }
  for (unsigned i=0;i<iters;i++) {
    vmcall_basic_t data = {12, 0xDEADBEEF, 0xFFFFFFFF};
    // VM*CALL timing
    uint64_t t0 = rdtsc64();
    __try { (void)call_stub_nocf(fn_vm, &data, 0x11111111ULL, 0x22222222ULL); }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    uint64_t t1 = rdtsc64();
    uint64_t vm_dt = t1 - t0;
    // UD2 timing
    t0 = rdtsc64();
    __try { fn_ud(); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    t1 = rdtsc64();
    uint64_t ud_dt = t1 - t0;
    int64_t delta = (int64_t)vm_dt - (int64_t)ud_dt;
    if (sc<1024) samples[sc++] = (delta<0)?0:(uint64_t)delta; // clamp negatives to 0
  }
  if (out) {
    // sort
    for (unsigned i=1;i<sc;i++){ uint64_t key=samples[i]; int j=(int)i-1; while (j>=0 && samples[j]>key){ samples[j+1]=samples[j]; j--; } samples[j+1]=key; }
    unsigned lo = sc/20; unsigned hi = sc - lo; if (hi<=lo) { lo=0; hi=sc; }
    uint64_t tsum=0; for (unsigned i=lo;i<hi;i++) tsum+=samples[i];
    unsigned kept = (hi>lo)? (hi-lo):sc;
    out->mean = kept ? (tsum / kept) : 0;
    out->vmin = kept? samples[lo] : 0;
    out->vmax = kept? samples[hi-1] : 0;
    out->p50 = kept? samples[lo + (kept*50/100)] : 0;
    out->p90 = kept? samples[lo + (kept*90/100)] : 0;
    out->p99 = kept? samples[lo + (kept*99/100)] : 0;
  }
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

  // For #UD on targeted instruction, record RIP advance if any
  if (code == EXCEPTION_ILLEGAL_INSTRUCTION && g_probe_ctx.capture) {
    uint64_t adv = (uint64_t)((unsigned char*)rip - (unsigned char*)g_probe_ctx.target_insn);
    if (g_probe_ctx.rip_out) *g_probe_ctx.rip_out = adv;
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
    call_stub_nocf(fn, &data, 0x11111111ULL, 0x22222222ULL);
  } __except(vmcall_seh_filter(GetExceptionInformation())) {}

  if (g_vmexc_state.exception_code != EXCEPTION_ILLEGAL_INSTRUCTION)
    return 0;

  if (advance_bytes)
    *advance_bytes = g_vmexc_state.rip_after - g_vmexc_state.vm_insn;
  return 1;
}

// Now that VEH/types exist, define generic TF probe for arbitrary bytes
static int probe_one_insn_tf_first(unsigned char prefix_or_00, unsigned char b1, unsigned char b2, unsigned char b3,
                                   uint8_t* out_first_is_ss)
{
  unsigned char code[64]; size_t i=0;
  // mov rax, rcx; mov rcx, r8
  code[i++]=0x48; code[i++]=0x89; code[i++]=0xC8; code[i++]=0x4C; code[i++]=0x89; code[i++]=0xC1;
  // pushfq; or qword [rsp],0x100; popfq
  code[i++]=0x9C; code[i++]=0x48; code[i++]=0x81; code[i++]=0x0C; code[i++]=0x24; code[i++]=0x00; code[i++]=0x01; code[i++]=0x00; code[i++]=0x00; code[i++]=0x9D;
  // prefix (optional, 0 means none)
  unsigned char* insn = &code[i];
  if (prefix_or_00) code[i++]=prefix_or_00;
  // bytes for instruction
  code[i++]=b1; code[i++]=b2; code[i++]=b3;
  // ret
  code[i++]=0xC3;
  void* mem = VirtualAlloc(NULL, 128, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return 0;
  memcpy(mem, code, i);

  // Arm probe
  g_probe_ctx.target_insn = ((unsigned char*)mem) + (insn - code);
  g_probe_ctx.target_end  = ((unsigned char*)g_probe_ctx.target_insn) + 6;
  g_probe_ctx.active      = 1;
  g_probe_ctx.max_records = 4;
  static PVOID veh = NULL; if (!veh) veh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)vmcall_veh);

  hv_call3_t fn = (hv_call3_t)mem;
  vmcall_basic_t data = {12, 0xDEADBEEF, 0xFFFFFFFF};
  __try { call_stub_nocf(fn, &data, 0x11111111ULL, 0x22222222ULL); } __except(EXCEPTION_EXECUTE_HANDLER) {}
  g_probe_ctx.active = 0;

  int ok = (g_probe_ctx.capture && g_probe_ctx.capture->tf_exc_count>=1 && g_probe_ctx.capture->tf_exc_codes[0]==EXCEPTION_SINGLE_STEP);
  if (out_first_is_ss) *out_first_is_ss = ok ? 1 : 0;
  return ok ? 1 : 0;
}

// Prefixed TF-first probe for password-free confirm
static int probe_prefixed_tf_first(BOOL amd_vmmcall, unsigned char prefix, dbvm_detect_info_t* out)
{
  unsigned char code[64]; size_t i=0;
  // mov rax, rcx; mov rcx, r8
  code[i++]=0x48; code[i++]=0x89; code[i++]=0xC8; code[i++]=0x4C; code[i++]=0x89; code[i++]=0xC1;
  // pushfq; or qword [rsp],0x100; popfq
  code[i++]=0x9C; code[i++]=0x48; code[i++]=0x81; code[i++]=0x0C; code[i++]=0x24; code[i++]=0x00; code[i++]=0x01; code[i++]=0x00; code[i++]=0x00; code[i++]=0x9D;
  // prefix and vm*call
  unsigned char* insn = &code[i];
  code[i++] = prefix;
  code[i++]=0x0F; code[i++]=0x01; code[i++]=(amd_vmmcall?0xD9:0xC1);
  // ret
  code[i++]=0xC3;
  void* mem = VirtualAlloc(NULL, 128, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return 0;
  memcpy(mem, code, i);
  hv_call3_t fn = (hv_call3_t)mem;

  g_probe_ctx.target_insn = ((unsigned char*)mem) + (insn - code);
  g_probe_ctx.target_end  = ((unsigned char*)g_probe_ctx.target_insn) + 4;
  g_probe_ctx.capture     = out; g_probe_ctx.active = 1; g_probe_ctx.max_records = 4;
  out->tf_path_used_vmmcall = amd_vmmcall?1:0;
  // Record RIP advance into prefixed fields
  if (amd_vmmcall) g_probe_ctx.rip_out = &out->pref_vmmcall_rip_advance; else g_probe_ctx.rip_out = &out->pref_vmcall_rip_advance;
  static PVOID veh = NULL; if (!veh) veh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)vmcall_veh);
  vmcall_basic_t data = {12, 0xDEADBEEF, 0xFFFFFFFF};
  __try { call_stub_nocf(fn, &data, 0x11111111ULL, 0x22222222ULL); } __except(EXCEPTION_EXECUTE_HANDLER) {}
  g_probe_ctx.active = 0; g_probe_ctx.rip_out = NULL;
  DWORD ok = (out->tf_exc_count>=1 && out->tf_exc_codes[0]==EXCEPTION_SINGLE_STEP);
  return ok ? 1 : 0;
}

// Probe prefixed variant for RIP advance
// Prefixed variant probes disabled for now

static hv_call3_t build_vm_stub_with_tf(BOOL amd_vmmcall)
{
  // Emit tiny code: mov rax,rcx; mov rcx,r8; pushfq; or [rsp],0x100; popfq; vm*call; ret
  unsigned char code[48]; size_t i=0;
  code[i++]=0x48; code[i++]=0x89; code[i++]=0xC8; // mov rax,rcx
  code[i++]=0x4C; code[i++]=0x89; code[i++]=0xC1; // mov rcx,r8
  code[i++]=0x9C; // pushfq
  code[i++]=0x48; code[i++]=0x81; code[i++]=0x0C; code[i++]=0x24; // or qword [rsp],imm32
  code[i++]=0x00; code[i++]=0x01; code[i++]=0x00; code[i++]=0x00; // 0x100
  code[i++]=0x9D; // popfq
  code[i++]=0x0F; code[i++]=0x01; code[i++]=(amd_vmmcall?0xD9:0xC1); // vm*call
  code[i++]=0xC3; // ret
  void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) return NULL;
  memcpy(mem, code, i);
  return (hv_call3_t)mem;
}

static void run_tf_order_probe(BOOL amd_vmmcall, dbvm_detect_info_t* out)
{
  hv_call3_t fn = build_vm_stub_with_tf(amd_vmmcall);
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
  __try { fn(&data, 0x11111111ULL, 0x22222222ULL); }
  __except(EXCEPTION_EXECUTE_HANDLER) { /* expected */ }
  g_probe_ctx.active = 0;
}

// Return the first exception code observed for a single VM*CALL TF probe (does not clobber caller's info)
static uint32_t vmcall_first_exc_probe(BOOL amd_vmmcall)
{
  dbvm_detect_info_t tmp; memset(&tmp, 0, sizeof(tmp));
  run_tf_order_probe(amd_vmmcall, &tmp);
  return (tmp.tf_exc_count>=1) ? tmp.tf_exc_codes[0] : 0;
}

static void capture_vmcall_first_exc(BOOL amd_vmmcall, dbvm_detect_info_t* out)
{
  out->tf_exc_count = 0;
  run_tf_order_probe(amd_vmmcall, out);
  if (out->tf_exc_count>=1) {
    out->vmcall_first_exc = out->tf_exc_codes[0];
    out->vmcall_first_eflags = out->tf_exc_eflags[0];
  }
}

// Plain VM*CALL TF-first probe (Intel+AMD path); returns 1 on first exception SINGLE_STEP
static int tf_first_plain_once(BOOL amd_vmmcall, dbvm_detect_info_t* out)
{
  out->tf_exc_count = 0;
  run_tf_order_probe(amd_vmmcall, out);
  return (out->tf_exc_count>=1 && out->tf_exc_codes[0]==EXCEPTION_SINGLE_STEP) ? 1 : 0;
}

typedef struct { BOOL amd; dbvm_detect_info_t* out; } tf_ctx_t;
static int tf_plain_probe_thunk(void* p)
{
  tf_ctx_t* c = (tf_ctx_t*)p; return tf_first_plain_once(c->amd, c->out);
}

static int tf_first_plain_crosscore(dbvm_detect_info_t* out)
{
  // Try both VMMCALL and VMCALL; require cross-core consistency for whichever hits
  tf_ctx_t ctxA = { TRUE, out }, ctxI = { FALSE, out };
  if (run_cross_core_consistent(tf_plain_probe_thunk, &ctxA)) return 1;
  if (run_cross_core_consistent(tf_plain_probe_thunk, &ctxI)) return 1;
  return 0;
}

// Prefixed VM*CALL set TF-first probe across 66/F3/F2/67/48; cross-core consistency required
typedef struct { BOOL amd; dbvm_detect_info_t* out; unsigned char prefix; } tfpref_ctx_t;
static int tfpref_probe_thunk(void* p)
{
  tfpref_ctx_t* c = (tfpref_ctx_t*)p; return probe_prefixed_tf_first(c->amd, c->prefix, c->out);
}

static int tf_first_prefixed_crosscore(dbvm_detect_info_t* out)
{
  unsigned char prefs[5] = { 0x66, 0xF3, 0xF2, 0x67, 0x48 };
  // Success if any prefix yields cross-core consistency on either AMD or Intel path
  for (int vmm=0; vmm<2; vmm++) {
    for (int i=0;i<5;i++) {
      tfpref_ctx_t ctx = { vmm?TRUE:FALSE, out, prefs[i] };
      if (run_cross_core_consistent(tfpref_probe_thunk, &ctx)) return 1;
    }
  }
  return 0;
}

// SVM opcode suite TF-first/sequence probe; returns 1 if at least 2 opcodes yield TF-first or consistent non-bare ordering
static int svm_suite_probe(dbvm_detect_info_t* out)
{
  // AMD SVM instruction group: 0F 01 D8..DF
  unsigned char opcodes[8] = {0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF};
  int hits = 0;
  for (int i=0;i<8;i++) {
    out->tf_exc_count = 0;
    // prefix 0, then 0F 01 xx
    g_probe_ctx.capture = out; // ensure capture points at 'out'
    probe_one_insn_tf_first(0x00, 0x0F, 0x01, opcodes[i], NULL);
    // vote if first is SINGLE_STEP or if we see a consistent two-#UD with TF set
    if (out->tf_exc_count>=1 && out->tf_exc_codes[0]==EXCEPTION_SINGLE_STEP) { hits++; }
    else if (out->tf_exc_count>=2 && out->tf_exc_codes[0]==EXCEPTION_ILLEGAL_INSTRUCTION && out->tf_exc_codes[1]==EXCEPTION_ILLEGAL_INSTRUCTION && (out->tf_exc_eflags[0] & 0x100)) { hits++; }
    if (hits>=2) return 1;
  }
  return 0;
}

static int tf_first_confirm(BOOL amd_vmmcall, dbvm_detect_info_t* out, int tries, int need_hits)
{
  int hits = 0;
  for (int i=0;i<tries;i++) {
    out->tf_exc_count = 0;
    run_tf_order_probe(amd_vmmcall, out);
    if (out->tf_exc_count>=1 && out->tf_exc_codes[0]==EXCEPTION_SINGLE_STEP) {
      hits++;
      if (hits>=need_hits) return 1;
    }
    // small yield to reduce back-to-back coalescing
    Sleep(0);
  }
  return 0;
}

static void measure_syscall_path(dbvm_detect_info_t* out)
{
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return;
  NtYieldExecution_t pNtYieldExecution = (NtYieldExecution_t)GetProcAddress(ntdll, "NtYieldExecution");
  NtQuerySystemTime_t pNtQuerySystemTime = (NtQuerySystemTime_t)GetProcAddress(ntdll, "NtQuerySystemTime");
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
  if (pNtQuerySystemTime) {
    total=0; vmin=(uint64_t)-1; vmax=0;
    for (unsigned i=0;i<iters;i++) {
      LARGE_INTEGER li; uint64_t t0=rdtsc64(); (void)pNtQuerySystemTime(&li); uint64_t t1=rdtsc64();
      uint64_t dt = (t1-t0); total += dt; if (dt<vmin) vmin=dt; if (dt>vmax) vmax=dt;
    }
    out->syscall2_mean = total/iters; out->syscall2_min=vmin; out->syscall2_max=vmax;
  }
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

  // Optional tuning: DBVM_SUSPECT_THRESHOLD_PCT (default 40)
  // Interpreted as: vmcall_mean >= ud2_mean * (1 + threshold_pct/100)
  int threshold_pct = 40;
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

  // 0.b) Collect CPUID/XGETBV and vendor string early so they are present even if we confirm early later
  {
    uint32_t vend0[4] = {0};
    cpuid_ex(0, 0, vend0); // EBX, EDX, ECX contain vendor string
    *(uint32_t*)&info->cpu_vendor[0]  = vend0[1]; // EBX
    *(uint32_t*)&info->cpu_vendor[4]  = vend0[3]; // EDX
    *(uint32_t*)&info->cpu_vendor[8]  = vend0[2]; // ECX
    info->cpu_vendor[12] = '\0';
    // CPUID 0x0D, XCR0
    uint32_t r0d[4] = {0};
    cpuid_ex(0x0000000D, 0, r0d);
    info->cpuid_0d_ecx_low16 = (uint16_t)(r0d[2] & 0xFFFF);
    info->xcr0_low32 = (uint32_t)_xgetbv(0);
    // AMD extended leaves
    uint32_t maxext[4] = {0};
    cpuid_ex(0x80000000, 0, maxext);
    if (maxext[0] >= 0x80000001) {
      uint32_t ext1[4] = {0}; cpuid_ex(0x80000001, 0, ext1);
      info->cpuid_80000001_ecx = ext1[2];
    }
    if (maxext[0] >= 0x8000000A) {
      uint32_t exta[4] = {0}; cpuid_ex(0x8000000A, 0, exta);
      info->cpuid_8000000a_eax = exta[0];
      info->cpuid_8000000a_ebx = exta[1];
      info->cpuid_8000000a_ecx = exta[2];
      info->cpuid_8000000a_edx = exta[3];
    }
  }

  // 1) Direct signature (optional, password-based): only when explicitly enabled
  DWORD ex = 0;
  char no_vm_env[8]; DWORD no_vm = GetEnvironmentVariableA("DBVM_NO_VM", no_vm_env, sizeof(no_vm_env));
  char allow_pw_env[8]; DWORD allow_pw = GetEnvironmentVariableA("DBVM_ALLOW_PASSWORD_PROBES", allow_pw_env, sizeof(allow_pw_env));
  // Optional overrides for P1/P3 from env when probes are allowed
  unsigned long long OV_P1 = DBVM_P1, OV_P3 = DBVM_P3;
  {
    char b1[32], b3[32]; DWORD n1 = GetEnvironmentVariableA("DBVM_P1_OVERRIDE", b1, sizeof(b1)); DWORD n3 = GetEnvironmentVariableA("DBVM_P3_OVERRIDE", b3, sizeof(b3));
    if (n1>0) OV_P1 = _strtoui64(b1, NULL, 0);
    if (n3>0) OV_P3 = _strtoui64(b3, NULL, 0);
  }

  if (!no_vm && allow_pw) {
    // Try Intel first (VMCALL)
    unsigned long long rax = try_vmcall_getversion(FALSE, OV_P1, OV_P3, DBVM_P2, &ex);
    if (ex == 0 && ((rax & 0xFF000000ULL) == 0xCE000000ULL)) {
      run_measurements(info, (int)no_vm);
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      info->dbvm_version = (uint32_t)(rax & 0x00FFFFFFULL);
      info->used_vmmcall = 0;
      snprintf(info->reason, sizeof(info->reason),
               "VMCALL GetVersion RAX=0x%llX", rax);
      return info->result;
    }

    // Try AMD (VMMCALL)
    ex = 0;
    rax = try_vmcall_getversion(TRUE, OV_P1, OV_P3, DBVM_P2, &ex);
    if (ex == 0 && ((rax & 0xFF000000ULL) == 0xCE000000ULL)) {
      run_measurements(info, (int)no_vm);
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      info->dbvm_version = (uint32_t)(rax & 0x00FFFFFFULL);
      info->used_vmmcall = 1;
      snprintf(info->reason, sizeof(info->reason),
               "VMMCALL GetVersion RAX=0x%llX", rax);
      return info->result;
    }

    // Try a small dictionary of common password2 variants (lab only)
    {
      BOOL used_vmmcall = 0; uint32_t ver=0;
      if (try_common_passwords(&used_vmmcall, &ver)) {
        run_measurements(info, (int)no_vm);
        info->result = DBVM_DETECT_DBVM_CONFIRMED;
        info->dbvm_version = ver;
        info->used_vmmcall = used_vmmcall;
        snprintf(info->reason, sizeof(info->reason),
                 "GetVersion dictionary hit (P2 variant)");
        return info->result;
      }
    }
  }

  // 1.b) RIP advance check on failing VMCALL/VMMCALL (#UD injection bug)
  uint64_t adv_vm=0, adv_vmm=0;
  if (!no_vm && detect_vmcall_rip_advance(FALSE, &adv_vm)) {
    info->vmcall_rip_advance = adv_vm;
    if (adv_vm >= 3) {
      run_measurements(info, (int)no_vm);
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      snprintf(info->reason, sizeof(info->reason),
               "#UD RIP advance %llu on VMCALL", (unsigned long long)adv_vm);
      return info->result;
    }
  }
  if (!no_vm && detect_vmcall_rip_advance(TRUE, &adv_vmm)) {
    info->vmmcall_rip_advance = adv_vmm;
    if (adv_vmm >= 3) {
      run_measurements(info, (int)no_vm);
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      info->used_vmmcall = 1;
      snprintf(info->reason, sizeof(info->reason),
               "#UD RIP advance %llu on VMMCALL", (unsigned long long)adv_vmm);
      return info->result;
    }
  }

  // 1.b.2) Prefixed variant probes reserved for future hardening

  // 1.c) Fault-semantics check with NOACCESS vmcall struct pointer (password-based; explicitly gated)
  //      ACCESS_VIOLATION here strongly implicates a mediator mapping the pointer.
  if (!no_vm && allow_pw) {
    char enfs[8]; DWORD enfs_dw = GetEnvironmentVariableA("DBVM_ENABLE_FAULT_SEM", enfs, sizeof(enfs));
    if (enfs_dw>0 && enfs[0]=='1') {
      DWORD f_vm = probe_vmcall_fault_semantics(FALSE);
      DWORD f_vmm = probe_vmcall_fault_semantics(TRUE);
      info->vmcall_fault_exc  = f_vm;
      info->vmmcall_fault_exc = f_vmm;
      if (f_vm  == EXCEPTION_ACCESS_VIOLATION || f_vmm == EXCEPTION_ACCESS_VIOLATION) {
        run_measurements(info, (int)no_vm);
        info->result = DBVM_DETECT_DBVM_CONFIRMED;
        snprintf(info->reason, sizeof(info->reason), "VM*CALL with NOACCESS ptr -> ACCESS_VIOLATION (DBVM pagefault injection)");
        return info->result;
      }
    }
  }

  // 2) Password-agnostic side-channels
  info->hv_vendor_leaf_present = (uint32_t)hypervisor_present_bit();

  // Signals (password-free)
  int sig_tf_plain = tf_first_plain_crosscore(info);
  // Snapshot result from the plain cross-core probe
  uint32_t tf_plain_first = (info->tf_exc_count>=1) ? info->tf_exc_codes[0] : 0;
  // Confirm on #PF-first around VM*CALL by default. Allow disabling via DBVM_DISABLE_PF_CONFIRM=1.
  {
    char pfdis[4]; DWORD dis = GetEnvironmentVariableA("DBVM_DISABLE_PF_CONFIRM", pfdis, sizeof(pfdis));
    if (!(dis>0 && pfdis[0]=='1') && tf_plain_first==EXCEPTION_ACCESS_VIOLATION) {
      run_measurements(info, (int)no_vm);
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      snprintf(info->reason, sizeof(info->reason), "VM*CALL first exception ACCESS_VIOLATION");
      return info->result;
    }
  }
  int sig_tf_pref  = tf_first_prefixed_crosscore(info);
  uint32_t tf_pref_first = (info->tf_exc_count>=1) ? info->tf_exc_codes[0] : 0;
  {
    char pfdis[4]; DWORD dis = GetEnvironmentVariableA("DBVM_DISABLE_PF_CONFIRM", pfdis, sizeof(pfdis));
    if (!(dis>0 && pfdis[0]=='1') && tf_pref_first==EXCEPTION_ACCESS_VIOLATION) {
      run_measurements(info, (int)no_vm);
      info->result = DBVM_DETECT_DBVM_CONFIRMED;
      snprintf(info->reason, sizeof(info->reason), "Prefixed VM*CALL first exception ACCESS_VIOLATION");
      return info->result;
    }
  }
  // After confirm checks, capture first-exception snapshots for semantic diffs
  capture_vmcall_first_exc(FALSE, info);
  if (!info->vmcall_first_exc) capture_vmcall_first_exc(TRUE, info);
  capture_ud2_first_exc(info);
  // RF delta on #UD-first comparisons (VM*CALL vs UD2)
  if (info->vmcall_first_exc==EXCEPTION_ILLEGAL_INSTRUCTION && info->ud2_first_exc==EXCEPTION_ILLEGAL_INSTRUCTION) {
    if (((info->vmcall_first_eflags ^ info->ud2_first_eflags) & 0x10000) != 0)
      info->rf_delta_signal = 1;
  }
  int sig_svm      = svm_suite_probe(info);
  int sig_desc     = sgdt_sidt_gueststyle_confirm();
  info->sig_tf_plain    = (uint8_t)(sig_tf_plain?1:0);
  info->sig_tf_prefixed = (uint8_t)(sig_tf_pref?1:0);
  info->sig_svm_suite   = (uint8_t)(sig_svm?1:0);
  info->sig_desc        = (uint8_t)(sig_desc?1:0);

  // Fallback: if any of the just-ran TF probes yielded #PF first, confirm DBVM (password-free)
  if (info->tf_exc_count>=1 && info->tf_exc_codes[0]==EXCEPTION_ACCESS_VIOLATION) {
    run_measurements(info, (int)no_vm);
    info->result = DBVM_DETECT_DBVM_CONFIRMED;
    snprintf(info->reason, sizeof(info->reason), "VM*CALL first exception ACCESS_VIOLATION");
    return info->result;
  }

  // Strong descriptor fingerprint for DBVM Roblox anti-detection patch
  if (info->idtr_limit == (8*256) && info->gdtr_limit == 0x58) {
    run_measurements(info, (int)no_vm);
    info->result = DBVM_DETECT_DBVM_CONFIRMED;
    snprintf(info->reason, sizeof(info->reason), "IDTR=2048 & GDTR=88 (DBVM patch)");
    return info->result;
  }

  // Majority vote (2+ signals) among signals above (no timing, no passwords)
  int votes = (sig_tf_plain?1:0) + (sig_tf_pref?1:0) + (sig_svm?1:0) + (sig_desc?1:0) + (info->rf_delta_signal?1:0);
  if (votes >= 2) {
    run_measurements(info, (int)no_vm);
    info->result = DBVM_DETECT_DBVM_CONFIRMED;
    snprintf(info->reason, sizeof(info->reason), "Confirm (signals=%d, RF-delta=%u)", votes, (unsigned)info->rf_delta_signal);
    return info->result;
  }

  // Perform measurements (always populate telemetry even if decision stays NO/SUSPECT)
  run_measurements(info, (int)no_vm);

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

  // Old TF/desc majority logic removed; decision now above based on signals (2-of-4)
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

  // - Percentile-based side-channel: require both p50 and p90 to exceed threshold
  // Prefer pairwise delta (more stable). Thresholds tuned conservatively for low false positives.
  {
    // Defaults: p50 >= 1800 cycles and p90 >= 2300 cycles
    int d50 = 1800, d90 = 2300;
    char b50[16], b90[16]; DWORD n50 = GetEnvironmentVariableA("DBVM_DELTA_P50_MIN", b50, sizeof(b50)); DWORD n90 = GetEnvironmentVariableA("DBVM_DELTA_P90_MIN", b90, sizeof(b90));
    if (n50>0) d50 = atoi(b50);
    if (n90>0) d90 = atoi(b90);
    if (info->delta_p50 && info->delta_p90) {
      if ((int)info->delta_p50 >= d50 && (int)info->delta_p90 >= d90) {
        info->result = DBVM_DETECT_SUSPECT_DBVM;
        snprintf(info->reason, sizeof(info->reason),
                 "Pairwise delta p50 %llu, p90 %llu (>= %d/%d)",
                 (unsigned long long)info->delta_p50,
                 (unsigned long long)info->delta_p90,
                 d50, d90);
        return info->result;
      }
    } else if (info->vmcall_ud_cycles && info->ud2_ud_cycles) {
      // Fallback to percentile ratio if pairwise not available
      unsigned long long t50_ok = (info->vmcall_p50 * 100ULL) >= (info->ud2_p50 * (100ULL + (unsigned long long)threshold_pct));
      unsigned long long t90_ok = (info->vmcall_p90 * 100ULL) >= (info->ud2_p90 * (100ULL + (unsigned long long)threshold_pct));
      if (t50_ok && t90_ok) {
        info->result = DBVM_DETECT_SUSPECT_DBVM;
        snprintf(info->reason, sizeof(info->reason),
                 "VMCALL#UD p50 %llu vs UD2 %llu; p90 %llu vs %llu (>= %d%%)",
                 (unsigned long long)info->vmcall_p50,
                 (unsigned long long)info->ud2_p50,
                 (unsigned long long)info->vmcall_p90,
                 (unsigned long long)info->ud2_p90,
                 threshold_pct);
        return info->result;
      }
    }
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
