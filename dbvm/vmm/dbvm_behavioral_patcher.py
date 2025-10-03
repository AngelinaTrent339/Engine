#!/usr/bin/env python3
"""
DBVM Behavioral Detection Patcher for RobloxPlayerBeta_dump.dll

This patcher targets REAL behavioral DBVM detection:
- Timing helper checks that detect DBVM's TF/#DB handling footprint
- NO vmcall/vmmcall patching
- NO hypervisor CPUID leaf modifications
- NO TEB/PEB structure patches

These are pure timing/behavior checks that detect DBVM's presence through:
1. Trap Flag (TF) stepping latency differences
2. Debug exception (#DB) handler timing
3. vm_pending_debug_exceptions flag side-effects
4. LBR bit clearing behavior
5. int1 IDT bypass redirection footprint

References:
- vmeventhandler.c:1932, 4142 (TF flag handling)
- vmeventhandler.c:3477 (LBR bit clear)
- vmeventhandler.c:3488-3506 (int1 redirection)
"""

import sys
import struct

# Patch definitions: (RVA, old_bytes, new_bytes, description)
PATCHES = [
    # ===== PRIORITY PATCHES (Timing Helper Checks) =====
    # These detect DBVM's unique TF/#DB timing footprint
    (0x00d3239d, b'\x0f\x84', b'\x0f\x85', 'Timing helper check #1 (0x7ffc54f0239d)'),
    (0x00d30a0c, b'\x0f\x84', b'\x0f\x85', 'Timing helper check #2 (0x7ffc54f00a0c)'),
    
    # ===== ADDITIONAL LAYERS =====
    (0x00d2a5ce, b'\x0f\x85', b'\x0f\x84', 'Seed init check (0x7ffc54efa5ce)'),
    (0x00d2a656, b'\x0f\x84', b'\x0f\x85', 'PEB correlation check #1 (0x7ffc54efa656)'),
    (0x00d2e418, b'\x0f\x84', b'\x0f\x85', 'Magic 0x57e7cfbf gate (0x7ffc54efe418)'),
    (0x00d2b5a6, b'\x0f\x84', b'\x0f\x85', 'PEB.ProcessHeap check (0x7ffc54efb5a6)'),
    (0x00d2a648, b'\x0f\x88', b'\x0f\x89', 'Signed range check #1 (0x7ffc54efa648)'),
    (0x00d2b5f7, b'\x0f\x88', b'\x0f\x89', 'Signed range check #2 (0x7ffc54efb5f7)'),
]

IMAGE_BASE = 0x7ffc541d0000

def rva_to_file_offset(rva, sections):
    """Convert RVA to file offset using PE section table"""
    for section in sections:
        vaddr = section['VirtualAddress']
        vsize = section['VirtualSize']
        if vaddr <= rva < vaddr + vsize:
            return rva - vaddr + section['PointerToRawData']
    raise ValueError(f"RVA 0x{rva:08x} not found in any section")

def parse_pe_sections(data):
    """Parse PE section table"""
    # Read DOS header
    if data[0:2] != b'MZ':
        raise ValueError("Not a valid PE file (missing MZ signature)")
    
    pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
    
    # Read PE header
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        raise ValueError("Not a valid PE file (missing PE signature)")
    
    # Get number of sections
    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    opt_hdr_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    
    # Section table starts after optional header
    section_table_offset = pe_offset + 24 + opt_hdr_size
    
    sections = []
    for i in range(num_sections):
        offset = section_table_offset + (i * 40)
        name = data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        vsize = struct.unpack('<I', data[offset+8:offset+12])[0]
        vaddr = struct.unpack('<I', data[offset+12:offset+16])[0]
        raw_size = struct.unpack('<I', data[offset+16:offset+20])[0]
        raw_ptr = struct.unpack('<I', data[offset+20:offset+24])[0]
        
        sections.append({
            'Name': name,
            'VirtualAddress': vaddr,
            'VirtualSize': vsize,
            'PointerToRawData': raw_ptr,
            'SizeOfRawData': raw_size
        })
    
    return sections

def apply_patches(filepath, output_filepath=None, priority_only=False, verbose=True):
    """Apply patches to the binary"""
    if output_filepath is None:
        output_filepath = filepath.replace('.dll', '_patched.dll')
        if output_filepath == filepath:
            output_filepath = filepath.replace('.exe', '_patched.exe')
        if output_filepath == filepath:
            output_filepath = filepath + '.patched'
    
    # Read binary
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    
    # Parse sections
    sections = parse_pe_sections(data)
    
    if verbose:
        print(f"[*] DBVM Behavioral Detection Patcher")
        print(f"[*] Target: {filepath}")
        print(f"[*] Sections: {len(sections)}")
        for sec in sections:
            print(f"    {sec['Name']:8s} VA=0x{sec['VirtualAddress']:08x} Size=0x{sec['VirtualSize']:08x}")
        print()
    
    # Apply patches
    patches_to_apply = PATCHES[:2] if priority_only else PATCHES
    applied = 0
    skipped = 0
    
    for rva, old_bytes, new_bytes, desc in patches_to_apply:
        try:
            file_offset = rva_to_file_offset(rva, sections)
            
            # Verify old bytes
            actual = bytes(data[file_offset:file_offset+len(old_bytes)])
            if actual != old_bytes:
                if verbose:
                    print(f"[!] MISMATCH at RVA 0x{rva:08x}")
                    print(f"    {desc}")
                    print(f"    Expected: {old_bytes.hex().upper()}")
                    print(f"    Found:    {actual.hex().upper()}")
                    print(f"    [SKIPPED]")
                    print()
                skipped += 1
                continue
            
            # Apply patch
            data[file_offset:file_offset+len(new_bytes)] = new_bytes
            applied += 1
            
            if verbose:
                va = IMAGE_BASE + rva
                print(f"[+] RVA 0x{rva:08x} → File 0x{file_offset:08x} (VA 0x{va:016x})")
                print(f"    {desc}")
                print(f"    {old_bytes.hex().upper()} → {new_bytes.hex().upper()}")
                print()
            
        except Exception as e:
            if verbose:
                print(f"[!] ERROR patching RVA 0x{rva:08x}: {e}")
                print()
            skipped += 1
    
    # Write output
    with open(output_filepath, 'wb') as f:
        f.write(data)
    
    if verbose:
        print(f"{'='*60}")
        print(f"[*] Applied: {applied}/{len(patches_to_apply)} patches")
        if skipped > 0:
            print(f"[*] Skipped: {skipped} patches (mismatches or errors)")
        print(f"[*] Output:  {output_filepath}")
        print(f"{'='*60}")
    
    return applied, skipped

def main():
    if len(sys.argv) < 2:
        print("DBVM Behavioral Detection Patcher")
        print()
        print("Usage: python dbvm_behavioral_patcher.py <input.dll> [options]")
        print()
        print("Options:")
        print("  --output <file>     Output file path (default: input_patched.dll)")
        print("  --priority-only     Only patch critical timing checks (#1, #2)")
        print("  --quiet             Suppress verbose output")
        print()
        print("Examples:")
        print("  # Minimal patch (timing checks only)")
        print("  python dbvm_behavioral_patcher.py RobloxPlayerBeta_dump.dll --priority-only")
        print()
        print("  # Full patch (all detection points)")
        print("  python dbvm_behavioral_patcher.py RobloxPlayerBeta_dump.dll")
        print()
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = None
    priority_only = False
    verbose = True
    
    # Parse args
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--output' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        elif arg == '--priority-only':
            priority_only = True
            i += 1
        elif arg == '--quiet':
            verbose = False
            i += 1
        else:
            print(f"Unknown option: {arg}")
            sys.exit(1)
    
    try:
        apply_patches(input_file, output_file, priority_only, verbose)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()


