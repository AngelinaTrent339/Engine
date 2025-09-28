-- runtime_proof.lua
-- Usage (Cheat Engine Lua Engine):
--   dofile([[C:\Users\FSOS\Documents\cheat-engine\tools\runtime_proof.lua]])
--   dumpVmcallSignature()
--   dumpAllocationInfo(16)

local signatureBytes = {0xEC,0xCA,0x50,0x40,0xEB,0x31,0x00,0x5F}
local baseVirtualAddress = 0x1000000000

local function formatBytes(bytes)
  local parts = {}
  for i,b in ipairs(bytes) do
    parts[#parts+1] = string.format("%02X", b)
  end
  return table.concat(parts, " ")
end

function dumpVmcallSignature()
  local sig = formatBytes(signatureBytes)
  local result = AOBScan(sig)
  if result == nil then
    print("[runtime_proof] signature not found – ensure DBVM/dbk32 is loaded and target process is attached")
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
  local entrySize = 16
  print(string.format("[runtime_proof] dumping %d AllocationInfoList entries", count))
  for i=0,count-1 do
    local addr = baseVirtualAddress + i*entrySize
    local low = readQword(addr)
    local high = readQword(addr + 8)
    print(string.format("  %3d @ 0x%016X : low=0x%016X high=0x%016X", i, addr, low, high))
  end
end

print("[runtime_proof] loaded. Call dumpVmcallSignature() or dumpAllocationInfo(count).")
