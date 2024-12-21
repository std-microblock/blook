#include "blook/blook.h"
#include "blook/memo.h"
#include "blook/process.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "Windows.h"

namespace blook {
ScopedSetMemoryRWX::ScopedSetMemoryRWX(void *ptr, size_t size) {
  this->ptr = ptr;
  this->size = size;
  VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, (PDWORD)&old_protect);
}
ScopedSetMemoryRWX::~ScopedSetMemoryRWX() {
  VirtualProtect(ptr, size, (DWORD)old_protect, nullptr);
}

void *Pointer::malloc_rwx(size_t size) {
  return Process::self()
      ->memo()
      .malloc(size, Pointer::MemoryProtection::rwx)
      .data();
}

void Pointer::protect_rwx(void *p, size_t size) {
  DWORD flOldProtect = 0;
  VirtualProtect(p, size, PAGE_EXECUTE_READWRITE, &flOldProtect);
}

void *Pointer::malloc_near_rwx(void *targetAddr, size_t size) {
  return Process::self()
      ->memo()
      .malloc(size, targetAddr, MemoryProtection::rwx)
      .data();
}

Pointer Pointer::malloc(size_t size, Pointer::MemoryProtection protection) {
  LPVOID lpSpace = (LPVOID)VirtualAllocEx(
      proc->h, NULL, size, MEM_RESERVE | MEM_COMMIT,
      ((protection == MemoryProtection::Read)        ? PAGE_READONLY
       : (protection == MemoryProtection::ReadWrite) ? PAGE_READWRITE
       : (protection == MemoryProtection::ReadWriteExecute)
           ? PAGE_EXECUTE_READWRITE
       : (protection == MemoryProtection::ReadExecute) ? PAGE_EXECUTE_READ
                                                       : PAGE_NOACCESS));
  return absolute(lpSpace);
}

Pointer::Pointer(std::shared_ptr<Process> proc) : proc(std::move(proc)) {}

Pointer Pointer::malloc(size_t size, void *nearby,
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
      void *outAddr = VirtualAllocEx(proc->h, (void *)highAddr, size,
                                     MEM_COMMIT | MEM_RESERVE, flag);
      if (outAddr)
        return absolute(outAddr);
    }

    if (lowAddr > minAddr) {
      void *outAddr = VirtualAllocEx(proc->h, (void *)lowAddr, size,
                                     MEM_COMMIT | MEM_RESERVE, flag);
      if (outAddr != nullptr)
        return absolute(outAddr);
    }

    pageOffset++;

    if (needsExit) {
      break;
    }
  }

  return absolute(nullptr);
}

std::optional<Module> Pointer::owner_module() {
  MEMORY_BASIC_INFORMATION inf;
  VirtualQuery(data(), &inf, 0x8);

  if (inf.AllocationBase)
    return Module{proc, (HMODULE)inf.AllocationBase};
  return {};
}

std::optional<Thread> Pointer::create_thread(bool suspended) {
  if (proc->is_self()) {
    auto thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)data(), nullptr,
                               suspended ? CREATE_SUSPENDED : 0, nullptr);
    if (thread == nullptr)
      return {};
    return Thread(GetThreadId(thread), proc);
  } else {
    auto thread = CreateRemoteThread(proc->h, nullptr, 0, (LPTHREAD_START_ROUTINE)data(),
                                     nullptr, suspended ? CREATE_SUSPENDED : 0, nullptr);
    if (thread == nullptr)
      return {};
    return Thread(GetThreadId(thread), proc);
  }
}
} // namespace blook