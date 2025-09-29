-- runtime_proof.lua
-- Usage (Cheat Engine Lua Engine):
--   dofile([[C:\Users\FSOS\Documents\cheat-engine\tools\runtime_proof.lua]])
--   dumpVmcallSignature()
--   dumpAllocationInfo(16)

local signatureBytes = {0xEC,0xCA,0x50,0x40,0xEB,0x31,0x00,0x5F}
local baseVirtualAddress = 0x1000000000
local allocationEntrySize = 8 -- sizeof(PageAllocationInfo.BitMask)

-- precompute powers of two up to 2^52 for integer-safe bit math
local pow2 = {[0]=1}
for i=1,52 do
  pow2[i] = pow2[i-1] * 2
end

local function formatBytes(bytes)
  local parts = {}
  for i,b in ipairs(bytes) do
    parts[#parts+1] = string.format("%02X", b)
  end
  return table.concat(parts, " ")
end

local function bytesToHex(bytes)
  local parts = {}
  for i=#bytes,1,-1 do
    parts[#parts+1] = string.format("%02X", bytes[i] or 0)
  end
  return table.concat(parts)
end

local function bitIsSet(byte, bitIndex)
  return math.floor(byte / pow2[bitIndex]) % 2 == 1
end

local function readPhysicalEntry(pa)
  if type(dbvm_readPhysicalMemory) ~= "function" then
    return nil, "dbvm_readPhysicalMemory API unavailable"
  end
  local ok, bytes = pcall(dbvm_readPhysicalMemory, pa, 8)
  if not ok then
    return nil, string.format("dbvm_readPhysicalMemory failed @ 0x%X: %s", pa, tostring(bytes))
  end
  return bytes
end

local function entryPresent(entryBytes)
  return entryBytes and bitIsSet(entryBytes[1], 0)
end

local function entryIsLargePage(entryBytes)
  return entryBytes and bitIsSet(entryBytes[1], 7)
end

local function extractBits(entryBytes, startBit, endBit)
  local value = 0
  local shift = 0
  for bit=startBit,endBit do
    local byteIndex = math.floor(bit / 8) + 1
    local bitIndex = bit % 8
    local byte = entryBytes[byteIndex]
    if byte == nil then
      return nil, string.format("missing byte %d in entry", byteIndex)
    end
    if math.floor(byte / pow2[bitIndex]) % 2 == 1 then
      value = value + pow2[shift]
    end
    shift = shift + 1
  end
  return value
end

local function alignDown(value, alignment)
  return value - (value % alignment)
end

local function virtualToPhysical(va, cr3)
  local cr3Aligned = alignDown(cr3, 0x1000)

  local pml4Index = math.floor(va / pow2[39]) % 0x200
  local entry, err = readPhysicalEntry(cr3Aligned + pml4Index * 8)
  if not entry then
    return nil, err
  end
  if not entryPresent(entry) then
    return nil, string.format("PML4[%d] not present", pml4Index)
  end
  local base = extractBits(entry, 12, 51)
  if not base then
    return nil, "failed to decode PML4 entry"
  end
  local pdptBase = base * 0x1000

  local pdptIndex = math.floor(va / pow2[30]) % 0x200
  entry, err = readPhysicalEntry(pdptBase + pdptIndex * 8)
  if not entry then
    return nil, err
  end
  if not entryPresent(entry) then
    return nil, string.format("PDPT[%d] not present", pdptIndex)
  end
  if entryIsLargePage(entry) then
    local gbBase = extractBits(entry, 30, 51)
    if not gbBase then
      return nil, "failed to decode PDPT large page"
    end
    local pageBase = gbBase * 0x40000000
    local offset = va % 0x40000000
    return pageBase + offset
  end
  base = extractBits(entry, 12, 51)
  if not base then
    return nil, "failed to decode PDPT entry"
  end
  local pdBase = base * 0x1000

  local pdIndex = math.floor(va / pow2[21]) % 0x200
  entry, err = readPhysicalEntry(pdBase + pdIndex * 8)
  if not entry then
    return nil, err
  end
  if not entryPresent(entry) then
    return nil, string.format("PD[%d] not present", pdIndex)
  end
  if entryIsLargePage(entry) then
    local mbBase = extractBits(entry, 21, 51)
    if not mbBase then
      return nil, "failed to decode PD large page"
    end
    local pageBase = mbBase * 0x200000
    local offset = va % 0x200000
    return pageBase + offset
  end
  base = extractBits(entry, 12, 51)
  if not base then
    return nil, "failed to decode PD entry"
  end
  local ptBase = base * 0x1000

  local ptIndex = math.floor(va / pow2[12]) % 0x200
  entry, err = readPhysicalEntry(ptBase + ptIndex * 8)
  if not entry then
    return nil, err
  end
  if not entryPresent(entry) then
    return nil, string.format("PT[%d] not present", ptIndex)
  end
  base = extractBits(entry, 12, 51)
  if not base then
    return nil, "failed to decode PT entry"
  end
  local pageBase = base * 0x1000
  local offset = va % 0x1000
  return pageBase + offset
end

function dumpVmcallSignature()
  local sig = formatBytes(signatureBytes)
  local result = AOBScan(sig)
  if result == nil then
    print("[runtime_proof] signature not found - ensure DBVM/dbk32 is loaded and target process is attached")
    return
  end
  print("[runtime_proof] signature hits:")
  for i=0,result.Count-1 do
    local addrStr = result[i]
    local addr = tonumber(addrStr, 16)
    local bytes = readBytes(addr, 16, true)
    print(string.format("  %s : %s", addrStr, table.concat(bytes, " ")))
  end
  result.destroy()
end

function dumpAllocationInfo(count)
  count = count or 8
  print(string.format("[runtime_proof] dumping %d AllocationInfoList entries", count))

  if type(dbvm_getCR3) ~= "function" then
    print("[runtime_proof] dbvm_getCR3 API unavailable ? ensure DBVM is loaded")
    return
  end

  local ok, cr3 = pcall(dbvm_getCR3)
  if not ok then
    print(string.format("[runtime_proof] dbvm_getCR3 failed: %s", tostring(cr3)))
    return
  end
  if type(cr3) ~= "number" or cr3 == 0 then
    print(string.format("[runtime_proof] unexpected CR3 value: %s", tostring(cr3)))
    return
  end

  for i=0,count-1 do
    local entryVA = baseVirtualAddress + i * allocationEntrySize
    local phys, terr = virtualToPhysical(entryVA, cr3)
    if not phys then
      print(string.format("  %3d @ VA 0x%013X : <translate failed: %s>", i, entryVA, terr or "?"))
    else
      local bytes, perr = readPhysicalEntry(phys)
      if not bytes then
        print(string.format("  %3d @ VA 0x%013X (PA 0x%013X) : <read failed: %s>", i, entryVA, phys, perr or "?"))
      else
        local hex = bytesToHex(bytes)
        print(string.format("  %3d @ VA 0x%013X (PA 0x%013X) : mask=0x%s", i, entryVA, phys, hex))
      end
    end
  end
end

print("[runtime_proof] loaded. Call dumpVmcallSignature() or dumpAllocationInfo(count).")
