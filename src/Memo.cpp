//
// Created by MicroBlock on 2024/6/22.
//

#include "../include/Memo.h"
#include "Windows.h"
#include <cstdint>
namespace blook {
void *Memo::malloc_rwx(size_t size) {
  return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE,
                      PAGE_EXECUTE_READWRITE);
}
void Memo::protect_rwx(void *p, size_t size) {
  DWORD flOldProtect = 0;
  VirtualProtect(p, size, PAGE_EXECUTE_READWRITE, &flOldProtect);
}
void *Memo::malloc_near_rwx(void *targetAddr, size_t size) {

  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);
  const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

  uint64_t startAddr =
      (uint64_t(targetAddr) &
       ~(PAGE_SIZE - 1)); // round down to nearest page boundary
  uint64_t minAddr = min(startAddr - 0x7FFFFF00,
                         (uint64_t)sysInfo.lpMinimumApplicationAddress);
  uint64_t maxAddr = max(startAddr + 0x7FFFFF00,
                         (uint64_t)sysInfo.lpMaximumApplicationAddress);

  uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

  uint64_t pageOffset = 1;
  while (1) {
    uint64_t byteOffset = pageOffset * PAGE_SIZE;
    uint64_t highAddr = startPage + byteOffset;
    uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

    bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

    if (highAddr < maxAddr) {
      void *outAddr =
          VirtualAlloc((void *)highAddr, size, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
      if (outAddr)
        return outAddr;
    }

    if (lowAddr > minAddr) {
      void *outAddr =
          VirtualAlloc((void *)lowAddr, size, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
      if (outAddr != nullptr)
        return outAddr;
    }

    pageOffset++;

    if (needsExit) {
      break;
    }
  }

  return nullptr;
}
} // namespace blook