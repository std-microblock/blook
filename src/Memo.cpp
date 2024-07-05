//
// Created by MicroBlock on 2024/6/22.
//

#include "../include/Memo.h"
#include "include/Function.h"
#define NOMINMAX
#include "Windows.h"
#include "include/Process.h"
#include <cstdint>
#include <utility>
namespace blook {
void *Pointer::malloc_rwx(size_t size) {
  return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE,
                      PAGE_EXECUTE_READWRITE);
}
void Pointer::protect_rwx(void *p, size_t size) {
  DWORD flOldProtect = 0;
  VirtualProtect(p, size, PAGE_EXECUTE_READWRITE, &flOldProtect);
}
void *Pointer::malloc_near_rwx(void *targetAddr, size_t size) {
  return Process::self()->memo().malloc(size, targetAddr,
                                        MemoryProtection::rwx);
}

void *Pointer::malloc(size_t size, Pointer::MemoryProtection protection) {
  LPVOID lpSpace = (LPVOID)VirtualAllocEx(
      proc->h, NULL, size, MEM_RESERVE | MEM_COMMIT,
      ((protection == MemoryProtection::Read)        ? PAGE_READONLY
       : (protection == MemoryProtection::ReadWrite) ? PAGE_READWRITE
       : (protection == MemoryProtection::ReadWriteExecute)
           ? PAGE_EXECUTE_READWRITE
       : (protection == MemoryProtection::ReadExecute) ? PAGE_EXECUTE_READ
                                                       : PAGE_NOACCESS));
  return lpSpace;
}

Pointer::Pointer(std::shared_ptr<Process> proc) : proc(std::move(proc)) {}

void *Pointer::malloc(size_t size, void *nearby,
                      Pointer::MemoryProtection protection) {
  const auto flag =
      ((protection == MemoryProtection::Read)        ? PAGE_READONLY
       : (protection == MemoryProtection::ReadWrite) ? PAGE_READWRITE
       : (protection == MemoryProtection::ReadWriteExecute)
           ? PAGE_EXECUTE_READWRITE
       : (protection == MemoryProtection::ReadExecute) ? PAGE_EXECUTE_READ
                                                       : PAGE_NOACCESS);
  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);
  const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

  uint64_t startAddr =
      (uint64_t(nearby) &
       ~(PAGE_SIZE - 1)); // round down to nearest page boundary
  uint64_t minAddr = std::min(startAddr - 0x7FFFFF00,
                              (uint64_t)sysInfo.lpMinimumApplicationAddress);
  uint64_t maxAddr = std::max(startAddr + 0x7FFFFF00,
                              (uint64_t)sysInfo.lpMaximumApplicationAddress);

  uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

  uint64_t pageOffset = 1;
  while (true) {
    uint64_t byteOffset = pageOffset * PAGE_SIZE;
    uint64_t highAddr = startPage + byteOffset;
    uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

    bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

    if (highAddr < maxAddr) {
      void *outAddr =
          VirtualAlloc((void *)highAddr, size, MEM_COMMIT | MEM_RESERVE, flag);
      if (outAddr)
        return outAddr;
    }

    if (lowAddr > minAddr) {
      void *outAddr =
          VirtualAlloc((void *)lowAddr, size, MEM_COMMIT | MEM_RESERVE, flag);
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

std::vector<uint8_t> Pointer::read(void *ptr, size_t size) {
  if (proc->is_self()) {
    std::span<uint8_t> a{(uint8_t *)((size_t)proc->h + offset), size};
    return {a.begin(), a.end()};
  }
  const auto x = proc->read((void *)((size_t)proc->h + offset), size).value();
  return x;
}

std::optional<std::vector<uint8_t>> Pointer::try_read(void *ptr, size_t size) {
  return proc->read((void *)((size_t)proc->h + offset), size);
}

std::span<uint8_t> Pointer::read_leaked(void *ptr, size_t size) {
  void *mem = malloc(size);
  proc->read(mem, (uint8_t *)((size_t)proc->h + offset), size);
  return {(uint8_t *)mem, size};
}
Pointer::Pointer(std::shared_ptr<Process> proc, void *offset)
    : offset((size_t)offset), proc(std::move(proc)) {}
Function Pointer::as_function() { return {proc, (void *)offset}; }
Pointer::Pointer(std::shared_ptr<Process> proc, size_t offset)
    : offset(offset), proc(std::move(proc)) {}
MemoryRange::MemoryRange(std::shared_ptr<Process> proc, void *offset,
                         size_t size)
    : Pointer(std::move(proc), offset), size(size) {}
} // namespace blook