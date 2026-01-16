#include "blook/blook.h"
#include "blook/memo.h"
#include "blook/process.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "Windows.h"

namespace blook {
ScopedSetMemoryRWX::ScopedSetMemoryRWX(Pointer ptr, size_t size) {
  this->ptr = ptr;
  this->size = size;
  this->old_protect =
      ptr.proc->set_memory_protect(ptr.data(), size, Process::MemoryProtection::rwx);
}

ScopedSetMemoryRWX::~ScopedSetMemoryRWX() {
  ptr.proc->set_memory_protect(ptr.data(), size, old_protect);
}

Pointer Pointer::malloc(size_t size, Pointer::MemoryProtection protection) {
  return absolute(proc->malloc(size, protection));
}

Pointer::Pointer(std::shared_ptr<Process> proc) : proc(std::move(proc)) {}

Pointer Pointer::malloc(size_t size, void *nearby,
                        Pointer::MemoryProtection protection) {
  return absolute(proc->malloc(size, protection, nearby));
}

Pointer Pointer::malloc_rx_near_this(size_t size) {
  return malloc(size, data(), MemoryProtection::rx);
}

void Pointer::free(size_t size) { proc->free(data(), size); }

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
  return proc->try_read(dest, data(), size);
}

void Pointer::read_into(void *dest, size_t size) const {
  proc->read(dest, data(), size);
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
  ScopedSetMemoryRWX protector(*this, data_span.size());
  return proc->try_write(data(), data_span.data(), data_span.size());
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
    : ScopedSetMemoryRWX(Pointer(r.proc, r.data()), r.size()) {}
} // namespace blook