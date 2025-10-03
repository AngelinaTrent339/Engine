#!/usr/bin/env python3
"""
Find the DBVM unique check by tracing crash paths in Roblox dump
"""

# Target address from terminal selection
ONE_TIME_DETECTOR = 0x7ffc54efa2e0
IMAGE_BASE = 0x7ffc541d0000
CRASH_EDGE = 0x7ffc54f246a5

rva = ONE_TIME_DETECTOR - IMAGE_BASE
crash_rva = CRASH_EDGE - IMAGE_BASE

print(f"One-time detector:")
print(f"  VA:  0x{ONE_TIME_DETECTOR:016x}")
print(f"  RVA: 0x{rva:08x}")
print()
print(f"Crash edge:")
print(f"  VA:  0x{CRASH_EDGE:016x}")  
print(f"  RVA: 0x{crash_rva:08x}")
print()
print("Use Binary Ninja to decompile these addresses!")

