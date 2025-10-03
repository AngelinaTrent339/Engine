 # Roblox DBVM Detection - Complete Analysis

## Overview
Roblox uses multiple DBVM detection checks that execute at different stages:
- **Startup Checks**: One-time, early initialization (before TLS)
- **Runtime Checks**: Continuous validation during execution

All checks exit with the same error: "unexpected checksum" or integrity failure.

## Runtime DBVM Probes (Continuous)

### Probe 1: `0x7ffc54f19dab` - Simple vmcall
```c
__vmcall(rflags);  // 0F 01 C1
// XOR obfuscation: 0xfa7e4872 ^ arg1 ^ arg2
syscall(&data_7ffc54402d38);
```
**Keyed table**: `0x7ffc54402d38`

### Probe 2: `0x7ffc54f1ccb0` - Heavily obfuscated vmcall  
```c
// Complex arithmetic obfuscation with ROLD operations
// Multiple XOR layers to hide syscall number
syscall(&data_7ffc54402d38);
```

### Probe 3: `0x7ffc54f243e7` - Minimal vmcall stub
```c
__vmcall(rflags);
*(uint64_t*)arg3 = arg4;  // Store result
*(uint32_t*)(__return_addr + 4) = 0x57e7cfbf;  // Magic constant
```

### Probe 4: `0x7ffc54f24380` - AMD vmmcall + TEB/PEB checks
```c
__vmmcall();  // 0F 01 D9 - AMD variant

// Check TEB/PEB for hypervisor tampering:
if (gsbase->NtTib.Self != -0x317e549eae772bed) { /* DBVM detected */ }
if (gsbase->ProcessEnvironmentBlock->ProcessHeap != -0x317e549ebf878f37) { /* DBVM detected */ }
```

## Startup DBVM Checks (One-time)

### Dispatcher: `sub_7ffc5444d5e0`
Routes to 42 stub functions via jump table at `0x7ffc541e5b10`

**Execution budget**: `data_7ffc54404274` (decrements on each dispatch)
- If budget reaches 0: `breakpoint()` (anti-single-step)

**Guard tables**:
- `0x7ffc54404270` - Indices/values
- `0x7ffc54404276` - Jump table indices

### TODO: Find startup check locations
- [ ] Search for early vmcall instances before TLS
- [ ] Identify which jump table slots contain startup checks
- [ ] Map initialization order

## Detection Exit Path

When DBVM detected:
```
vmcall succeeds (no #UD) 
  → Integrity check fails
  → Exit with error: "unexpected checksum" / integrity violation
```

### TODO: Trace exit path
- [ ] Find error message strings
- [ ] Locate exit/terminate functions
- [ ] Identify integrity check functions

## Detection Fallback Chain

If one check fails → try next method → eventually exit

### TODO: Map fallback logic
- [ ] Identify fallback order
- [ ] Find check selection logic
- [ ] Determine which checks are mandatory vs optional

## DBVM Stealth Strategy

**Goal**: Make DBVM invisible to ALL checks

### Approach 1: Whitelist Process
```c
// In DBVM vmcall handler
if (is_roblox_process(cr3)) {
    inject_ud_exception();  // Pretend no hypervisor
    return;
}
```

### Approach 2: Don't Touch TEB/PEB
Avoid modifying:
- `gs:[0x30]` (TEB Self)
- `gs:[0x60]` (PEB)

### Approach 3: Hide VM Exit Artifacts
- Clear VMCS indicators
- Restore CPU state perfectly

## Binary Ninja Analysis Summary

### Runtime DBVM Probes (from decompilation)

#### **Probe 1: `0x7ffc54f19dab` - Simple Intel vmcall**
```c
int64_t sub_7ffc54f19dab(int32_t arg1, int32_t arg2) {
    uint64_t rflags;
    __vmcall(rflags);  // 0F 01 C1
    
    // XOR obfuscation: 0xfa7e4872 ^ arg1 ^ arg2
    *(uint32_t*)((0xfa7e4872 ^ arg1 ^ arg2) + &data_7ffc54402d38);
    syscall(&data_7ffc54402d38);
    
    return sub_7ffc54f19dc4(rbp, rsi);  // tail call
}
```
**Detection**: vmcall succeeds → DBVM present  
**Table**: `data_7ffc54402d38` - obfuscated syscall numbers

#### **Probe 2: `0x7ffc54f1ccb0` - Obfuscated vmcall with arithmetic**
```c
int64_t sub_7ffc54f1ccb0(int64_t arg1, void* arg2) {
    // Complex arithmetic obfuscation with ROLD operations
    // Multiple XOR layers: 0x437416, 0x48437416, 0x1210dd05
    // Reads from: **(uint64_t**)&data_7ffc54400e78
    
    int32_t rdx_8 = ROLD(r8_3, 0x1b) ^ r8_3 ^ ...;
    *(uint32_t*)((0xfa7e4872 ^ computed_value) + &data_7ffc54402d38);
    
    return syscall(&data_7ffc54402d38);
}
```
**Detection**: Same pattern, heavily obfuscated
**Purpose**: Prevent pattern recognition

#### **Probe 3: `0x7ffc54f243e7` - Minimal vmcall stub**
```c
void* sub_7ffc54f243e7(int64_t, int64_t, int64_t* arg3, int64_t arg4 @ rax) {
    uint64_t rflags;
    __vmcall(rflags);
    
    *(uint64_t*)arg3 = arg4;  // Store result
    *(uint32_t*)((char*)__return_addr)[4] = 0x57e7cfbf;  // Magic value
    
    return __return_addr;
}
```
**Detection**: Fastest check, writes magic value to return address

### Startup DBVM Checks (from notes)

#### **1. TLS Callback - CPUID XSAVE Check** (`base+0x0D91290`)
- **Method**: `CPUID leaf 0x0D, ECX=0` (XSAVE features)
- **Check**: `pextrw ecx, xmm0, 4` → `xor eax, ecx` → `cmp ax, 0x25`
- **Trigger**: `NtTerminateProcess(..., 0x0BADD00D)` if match
- **Target**: Detects hypervisor CPUID modifications

#### **2. Primary vmcall Probe** (`sub_7FFC54E42BA0`)
- **Calls**: `sub_7FFC54F24380` (vmcall wrapper)
- **Check**: `movzx eax, [rbp-1D]` → `shl eax, 24` → `cmp eax, 0xCE000000`
- **Result**: Sets `dword_7FFC54401F80 = 2` and aborts init
- **Critical**: This is the main startup DBVM detector

#### **3. AMD/SVM Path** (`sub_7FFC54F24380` else-branch)
- **Method**: `vmmcall 0x90909090/0x76543210` (AMD)
- **Checks**: PEB and ProcessHeap against `0xCE81...`
- **Result**: Same `[rbp-1D]` byte check for `0xCE`

### Detection Flow

```
Startup:
  TLS Callback (CPUID check)
    ↓ (if pass)
  DLL Init → sub_7FFC54E42BA0
    ↓
  sub_7FFC54F24380 (vmcall wrapper)
    ↓
  Check [rbp-1D] == 0xCE
    ↓ (if detected)
  Set dword_7FFC54401F80 = 2
    ↓
  sub_7FFC54FA38D0 (fail-fast)
    ↓
  _report_securityfailure → int 0x29

Runtime:
  Periodic checks via dispatcher sub_7ffc5444d5e0
    ↓
  Jump table (0x7ffc541e5b10) routes to probes
    ↓
  Probes execute vmcall
    ↓ (if succeeds)
  Error path (unknown - needs tracing)
```

## Next Steps - Binary Ninja Analysis

### ✅ Completed
1. Analyzed dispatcher function `sub_7ffc5444d5e0`
2. Identified jump table at `0x7ffc541e5b10` (42 entries)
3. Decompiled 3 runtime vmcall probes
4. Documented startup checks from notes

### 🔄 In Progress
1. **Find functions that call the startup check** `sub_7FFC54E42BA0`
   - Search for cross-references to this address
   - Identify initialization/DLLMain flow
   
2. **Trace error paths**
   - Follow what happens after `dword_7FFC54401F80 = 2`
   - Find `sub_7FFC54FA38D0` and `_report_securityfailure`
   - Map the crash/exit flow

3. **Search for ALL vmcall/vmmcall instructions**
   - Need to search raw bytes: `0F 01 C1` (vmcall) and `0F 01 D9` (vmmcall)
   - Categorize into startup vs runtime
   
### 📋 Todo
1. Document complete detection chain
2. Identify DBVM patches needed
3. Test bypass strategies

