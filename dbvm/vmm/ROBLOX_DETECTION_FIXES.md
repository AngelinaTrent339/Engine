# Roblox Anti-Cheat DBVM Detection Fixes

## Summary
This document describes the fixes applied to DBVM to bypass Roblox's anti-cheat detection mechanisms.

## Detection #1: CPUID Leaf 0x0D (XSAVE Enumeration)

### Detection Method
- Roblox calls `CPUID` with `EAX=0x0D`, `ECX=0` (XSAVE features enumeration)
- Stores results in a 128-bit buffer (EAX, EBX, ECX, EDX)
- Extracts word 4 (ECX low 16 bits)
- Performs XOR check: `(ECX_low16 ^ 0x66B5) == 0x25`
- If true (meaning ECX low 16 = 0x6690), calls `NtTerminateProcess(..., 0x0BADD00D)`

### Location
- Triggers in TLS callback (very early, before main execution)
- Code location: `RobloxPlayerBeta_dump.dll+0xD91679`

### Fix Applied
**Files Modified:** `vmeventhandler.c`, `vmeventhandler_amd.c`

Added detection and patching logic:
```c
if (oldeax == 0x0D && subleaf == 0)
{
  UINT16 word4 = (UINT16)(vmregisters->rcx & 0xFFFF);
  UINT16 test_result = word4 ^ 0x66B5;
  
  if (test_result == 0x25)  // Detected signature!
  {
    // Change ECX low 16 bits from 0x6690 to 0x6691
    vmregisters->rcx = (vmregisters->rcx & 0xFFFFFFFFFFFF0000ULL) | 0x6691;
  }
}
```

- Logs all CPUID 0x0D results for debugging
- Automatically patches if signature is detected
- Also logs RBX words for additional signature discovery

## Detection #2: VMCALL/VMMCALL Probe

### Detection Method
- Roblox probes DBVM using vmcall/vmmcall instructions
- Uses DBVM's **default passwords**: `ECX=0x90909090`, `EDX=0x76543210`
- Checks if returned value in RAX has `0xCE` in the high byte
- If high byte == `0xCE`, sets `dword_7FFC54401F80 = 2` and aborts initialization

### Location
- Wrapper: `sub_7FFC54F24380` (RobloxPlayerBeta_dump.dll+0xD24380)
- Caller: `sub_7FFC54E42BA0` (+0xC72BA0)
- Has both Intel (vmcall) and AMD (vmmcall) paths

### Original DBVM Behavior
DBVM's default passwords are:
```c
Password1=0x76543210; // EDX
Password2=0xfedcba98;
Password3=0x90909090; // ECX
```

When an unknown vmcall command is received, DBVM returned:
```c
default:
  vmregisters->rax = 0xcedead;  // HIGH BYTE = 0xCE!
```

### Fix Applied
**File Modified:** `vmcall.c`

1. **Changed default case return value:**
```c
default:
  // Return 0 for unknown vmcalls instead of 0xCEDEAD
  // Roblox checks if high byte == 0xCE to detect DBVM
  vmregisters->rax = 0;
  break;
```

2. **Clear RAX before raising exceptions:**
```c
if ((vmregisters->rdx != Password1) || (vmregisters->rcx != Password3))
{
  // Clear RAX to avoid detection (don't leave 0xCE in high byte)
  vmregisters->rax = 0;
  if (isAMD)
    currentcpuinfo->vmcb->RAX = 0;
  x = raiseInvalidOpcodeException(currentcpuinfo);
  return x;
}
```

## Testing

### For CPUID Detection:
1. Rebuild DBVM
2. Check debug output for `CPUID 0x0D` log messages
3. Look for `>>> PATCHED ECX to avoid Roblox detection!` message
4. Verify the XOR test result values

### For VMCALL Detection:
1. The fix prevents DBVM from returning `0xCEDEAD`
2. Roblox's probe will now see RAX=0 instead
3. High byte check `(RAX >> 56) == 0xCE` will fail
4. Process should proceed normally

## Additional Notes

### CPUID 0x0D Values
The fix logs actual CPUID return values to help identify other potential signatures:
- EAX, EBX, ECX, EDX for subleaf 0
- Word extractions from RBX for additional analysis

### VMCALL Paths
Multiple code paths could trigger the detection:
1. Unknown vmcall command → default case (fixed)
2. Invalid password → exception with RAX cleared (fixed)
3. Invalid structure → exception (RAX cleared)

All paths now avoid returning/leaving 0xCE in RAX's high byte.

## Files Modified
1. `vmeventhandler.c` - Intel CPUID handling
2. `vmeventhandler_amd.c` - AMD CPUID handling  
3. `vmcall.c` - VMCALL/VMMCALL handling

## Rebuild Instructions
```bash
cd /path/to/dbvm/vmm
make clean
make
```

Then reload DBVM and test with Roblox.

