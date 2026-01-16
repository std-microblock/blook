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
    auto thread =
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)data(), nullptr,
                     suspended ? CREATE_SUSPENDED : 0, nullptr);
    if (thread == nullptr)
      return {};
    return Thread(GetThreadId(thread), proc);
  } else {
    auto thread =
        CreateRemoteThread(proc->h, nullptr, 0, (LPTHREAD_START_ROUTINE)data(),
                           nullptr, suspended ? CREATE_SUSPENDED : 0, nullptr);
    if (thread == nullptr)
      return {};
    return Thread(GetThreadId(thread), proc);
  }
}

std::expected<void, std::string> Pointer::try_read_into(void *dest,
                                                        size_t size) const {
  if (proc->is_self()) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(data(), &mbi, sizeof(mbi)) == 0 ||
        (mbi.State != MEM_COMMIT) ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
      return std::unexpected("Memory not accessible");
    }
    std::memcpy(dest, data(), size);
  } else {
    SIZE_T read = 0;
    if (!ReadProcessMemory(proc->h, data(), dest, size, &read) ||
        read != size) {
      return std::unexpected("Failed to read remote memory: " +
                             std::to_string(GetLastError()));
    }
  }
  return {};
}

void Pointer::read_into(void *dest, size_t size) const {
  if (proc->is_self()) {
    std::memcpy(dest, data(), size);
  } else {
    SIZE_T read = 0;
    if (!ReadProcessMemory(proc->h, data(), dest, size, &read) ||
        read != size) {
      throw std::runtime_error("Failed to read remote memory: " +
                               std::to_string(GetLastError()));
    }
  }
}

std::expected<std::vector<uint8_t>, std::string>
Pointer::try_read_bytearray(size_t size) const {
  std::vector<uint8_t> buffer(size);
  auto res = try_read_into(buffer.data(), size);
  if (!res)
    return std::unexpected(res.error());
  return buffer;
}

std::expected<Pointer, std::string> Pointer::try_read_pointer() const {
  auto res = try_read_struct<void *>();
  if (!res)
    return std::unexpected(res.error());
  return absolute(*res);
}

std::expected<std::string, std::string>
Pointer::try_read_utf8_string(size_t length) const {
  std::string res;
  Pointer current = *this;
  for (size_t i = 0; length == (size_t)-1 || i < length; ++i) {
    auto b = (current + i).try_read_u8();
    if (!b)
      return std::unexpected(b.error());
    if (*b == 0)
      break;
    res += (char)*b;
  }
  return res;
}

std::expected<std::wstring, std::string>
Pointer::try_read_utf16_string(size_t length) const {
  std::wstring wres;
  Pointer current = *this;
  for (size_t i = 0; length == (size_t)-1 || i < length; ++i) {
    auto b = (current + i * 2).try_read_u16();
    if (!b)
      return std::unexpected(b.error());
    if (*b == 0)
      break;
    wres += (wchar_t)*b;
  }
  return wres;
}

std::expected<void, std::string>
Pointer::try_write_utf8_string(std::string_view str) const {
  return try_write_bytearray(
      std::span<const uint8_t>((const uint8_t *)str.data(), str.size() + 1));
}

std::expected<void, std::string>
Pointer::try_write_utf16_string(std::wstring_view str) const {
  return try_write_bytearray(std::span<const uint8_t>(
      (const uint8_t *)str.data(), (str.size() + 1) * sizeof(wchar_t)));
}

std::expected<void, std::string>
Pointer::try_write_bytearray(std::span<const uint8_t> data_span) const {
  if (proc->is_self()) {
    try {
      std::memcpy(data(), data_span.data(), data_span.size());
    } catch (...) {
      return std::unexpected("Failed to write local memory");
    }
  } else {
    SIZE_T written = 0;
    if (!WriteProcessMemory(proc->h, data(), data_span.data(), data_span.size(),
                            &written) ||
        written != data_span.size()) {
      return std::unexpected("Failed to write remote memory: " +
                             std::to_string(GetLastError()));
    }
  }
  return {};
}

std::expected<void, std::string> Pointer::try_write_pointer(Pointer ptr) const {
  return try_write_struct<void *>(ptr.data());
}

std::vector<uint8_t> Pointer::read_bytearray(size_t size) const {
  auto res = try_read_bytearray(size);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

Pointer Pointer::read_pointer() const {
  auto res = try_read_pointer();
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

std::string Pointer::read_utf8_string(size_t length) const {
  auto res = try_read_utf8_string(length);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

std::wstring Pointer::read_utf16_string(size_t length) const {
  auto res = try_read_utf16_string(length);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

void Pointer::write_utf8_string(std::string_view str) const {
  auto res = try_write_utf8_string(str);
  if (!res)
    throw std::runtime_error(res.error());
}

void Pointer::write_utf16_string(std::wstring_view str) const {
  auto res = try_write_utf16_string(str);
  if (!res)
    throw std::runtime_error(res.error());
}

void Pointer::write_bytearray(std::span<const uint8_t> data) const {
  auto res = try_write_bytearray(data);
  if (!res)
    throw std::runtime_error(res.error());
}

void Pointer::write_pointer(Pointer ptr) const {
  auto res = try_write_pointer(ptr);
  if (!res)
    throw std::runtime_error(res.error());
}
ScopedSetMemoryRWX::ScopedSetMemoryRWX(const MemoryRange &r)
    : ScopedSetMemoryRWX(r.data(), r.size()) {}
} // namespace blook