#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint64_t p1; // Password1 (RDX)
  uint64_t p3; // Password3 (RCX)
  uint32_t p2; // Password2 (DWORD), optional/heuristic
  int      have_p1;
  int      have_p3;
  int      have_p2;
} dbvm_keys_t;

// Attempt to harvest DBVM keys from a PE file on disk (EXE/SYS/DLL)
// Returns 1 on success (any key found), 0 on failure
int dbvm_harvest_from_file_utf16(const wchar_t* path, dbvm_keys_t* out);

#ifdef __cplusplus
}
#endif

