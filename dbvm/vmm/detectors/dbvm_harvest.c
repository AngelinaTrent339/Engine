#define _CRT_SECURE_NO_WARNINGS
#include "dbvm_harvest.h"

#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef struct {
  const uint8_t* base;
  size_t size;
  IMAGE_NT_HEADERS* nth;
  IMAGE_SECTION_HEADER* secs;
  int nsecs;
} pe_image_t;

static int pe_map_sections(pe_image_t* pe, const uint8_t* buf, size_t size)
{
  if (size < sizeof(IMAGE_DOS_HEADER)) return 0;
  const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)buf;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
  if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) return 0;
  IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)buf + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
  pe->base = buf; pe->size = size; pe->nth = nt; pe->secs = IMAGE_FIRST_SECTION(nt); pe->nsecs = nt->FileHeader.NumberOfSections;
  return 1;
}

static const uint8_t* pe_rva_to_ptr(const pe_image_t* pe, DWORD rva, size_t need)
{
  for (int i=0;i<pe->nsecs;i++){
    const IMAGE_SECTION_HEADER* s = &pe->secs[i];
    DWORD va = s->VirtualAddress; DWORD vsz = s->Misc.VirtualSize; DWORD pofs = s->PointerToRawData; DWORD psz = s->SizeOfRawData;
    if (rva >= va && rva + need <= va + vsz) {
      size_t ofs = (size_t)pofs + (size_t)(rva - va);
      if (ofs + need <= pe->size)
        return pe->base + ofs;
      return NULL;
    }
  }
  return NULL;
}

static int is_text_section(const IMAGE_SECTION_HEADER* s)
{
  return (s->Characteristics & IMAGE_SCN_CNT_CODE) != 0;
}

static uint64_t read_u64_le(const uint8_t* p){ uint64_t v=0; for(int i=7;i>=0;i--) v=(v<<8)|p[i]; return v; }
static uint32_t read_u32_le(const uint8_t* p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }

typedef struct { uint64_t p1, p3; int have_p1, have_p3; } keypair_t;

static void scan_block_for_vmcall(const pe_image_t* pe, DWORD rva, const uint8_t* blk, size_t blksz, keypair_t* keys)
{
  for (size_t i=0;i+3<blksz;i++) {
    // look for 0F 01 C1 (VMCALL) or 0F 01 D9 (VMMCALL)
    if (blk[i]==0x0F && blk[i+1]==0x01 && (blk[i+2]==0xC1 || blk[i+2]==0xD9)) {
      // Backward scan up to 64 bytes for mov rdx, imm64 (48 BA ..) and mov rcx, imm64 (48 B9 ..)
      size_t start = (i>64)?(i-64):0;
      for (size_t j=i; j>start; ) {
        j--;
        if (j+10 <= blksz && blk[j]==0x48 && blk[j+1]==0xBA) { // mov rdx, imm64
          uint64_t imm = read_u64_le(&blk[j+2]);
          keys->p1 = imm; keys->have_p1 = 1;
        }
        if (j+10 <= blksz && blk[j]==0x48 && blk[j+1]==0xB9) { // mov rcx, imm64
          uint64_t imm = read_u64_le(&blk[j+2]);
          keys->p3 = imm; keys->have_p3 = 1;
        }
        // mov rdx, [rip+rel32] : 48 8B 15 xx xx xx xx
        if (j+7 <= blksz && blk[j]==0x48 && blk[j+1]==0x8B && blk[j+2]==0x15) {
          int32_t rel = (int32_t)read_u32_le(&blk[j+3]);
          DWORD target_rva = rva + (DWORD)(j+7) + rel;
          const uint8_t* p = pe_rva_to_ptr(pe, target_rva, 8);
          if (p) { keys->p1 = read_u64_le(p); keys->have_p1 = 1; }
        }
        // mov rcx, [rip+rel32] : 48 8B 0D xx xx xx xx
        if (j+7 <= blksz && blk[j]==0x48 && blk[j+1]==0x8B && blk[j+2]==0x0D) {
          int32_t rel = (int32_t)read_u32_le(&blk[j+3]);
          DWORD target_rva = rva + (DWORD)(j+7) + rel;
          const uint8_t* p = pe_rva_to_ptr(pe, target_rva, 8);
          if (p) { keys->p3 = read_u64_le(p); keys->have_p3 = 1; }
        }
        if (keys->have_p1 && keys->have_p3) return;
      }
    }
  }
}

static int harvest_keys_from_pe(const pe_image_t* pe, dbvm_keys_t* out)
{
  memset(out, 0, sizeof(*out));
  for (int i=0;i<pe->nsecs;i++){
    const IMAGE_SECTION_HEADER* s = &pe->secs[i];
    if (!is_text_section(s)) continue;
    DWORD rva = s->VirtualAddress; DWORD vsz = s->Misc.VirtualSize;
    const uint8_t* blk = pe_rva_to_ptr(pe, rva, vsz);
    if (!blk) continue;
    keypair_t keys = {0};
    scan_block_for_vmcall(pe, rva, blk, vsz, &keys);
    if (keys.have_p1 || keys.have_p3) {
      out->p1 = keys.p1; out->have_p1 = keys.have_p1;
      out->p3 = keys.p3; out->have_p3 = keys.have_p3;
      // Heuristic for P2: search entire image for a DWORD that looks like Password2 near references to vmcall header size 12
      // Not robust; leave have_p2=0 by default.
      return 1;
    }
  }
  return 0;
}

int dbvm_harvest_from_file_utf16(const wchar_t* path, dbvm_keys_t* out)
{
  if (!path || !out) return 0;
  int ok = 0;
  HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hf==INVALID_HANDLE_VALUE) return 0;
  HANDLE hm = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hm) {
    const uint8_t* map = (const uint8_t*)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    if (map) {
      pe_image_t pe={0};
      MEMORY_BASIC_INFORMATION mbi;
      SIZE_T q = VirtualQuery(map, &mbi, sizeof(mbi));
      SIZE_T sz = q ? mbi.RegionSize : 0;
      if (sz>=1024 && pe_map_sections(&pe, map, (size_t)sz)) {
        ok = harvest_keys_from_pe(&pe, out);
      }
      UnmapViewOfFile(map);
    }
    CloseHandle(hm);
  }
  CloseHandle(hf);
  return ok;
}

