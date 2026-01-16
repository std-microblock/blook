#pragma once

#include "platform_types.h"
#include "utils.h"
#include <cstdint>
#include <expected>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace blook {
class Pointer;
class Module;
struct Thread;
class Process;

using Allocator = struct ProcessAllocator {
  explicit ProcessAllocator(std::shared_ptr<Process> proc);

  std::optional<Pointer> allocate(size_t size, void *nearAddr = nullptr);

  void deallocate(Pointer addr);

private:
  struct AllocatedPageData {
    size_t size;
    std::map<void *, size_t> allocated;
  };
  std::map<void *, AllocatedPageData> allocatedPages;
  std::shared_ptr<Process> proc;
};

class Process : public std::enable_shared_from_this<Process> {
public:
  enum class MemoryProtection {
    None = 0,
    Read = 0x0001,
    Write = 0x0010,
    Execute = 0x0100,
    ReadWrite = Read | Write,
    ReadWriteExecute = Read | Write | Execute,
    ReadExecute = Read | Execute,
    rw = ReadWrite,
    rwx = ReadWriteExecute,
    rx = ReadExecute
  };

#ifdef _WIN32

  explicit Process(HANDLE h);

  explicit Process(DWORD pid);

#endif

  explicit Process(std::string name, size_t skip = 0);
  bool is_self_cached;
protected:
  WIN_ONLY(HANDLE h = nullptr);
  friend Module;
  friend Pointer;

  std::shared_ptr<Pointer> _memo_ptr;
  std::shared_ptr<struct ProcessAllocator> _allocator_ptr;

public:
  CLASS_MOVE_ONLY(Process)
#ifdef _WIN32
  DWORD pid;
#endif

  // Memory APIs
  std::expected<void, std::string> try_read(void *dst, void *src,
                                            size_t size) const;
  void read(void *dst, void *src, size_t size) const;

  std::expected<void, std::string> try_write(void *dst, const void *src,
                                             size_t size) const;
  void write(void *dst, const void *src, size_t size) const;

  std::expected<bool, std::string> try_check_readable(void *addr,
                                                      size_t size) const;
  bool check_readable(void *addr, size_t size) const;

  std::expected<bool, std::string> try_check_writable(void *addr,
                                                      size_t size) const;
  bool check_writable(void *addr, size_t size) const;

  std::expected<MemoryProtection, std::string>
  try_set_memory_protect(void *addr, size_t size,
                         MemoryProtection protect) const;
  MemoryProtection set_memory_protect(void *addr, size_t size,
                                      MemoryProtection protect) const;

  std::expected<bool, std::string> try_check_valid(void *addr) const;
  bool check_valid(void *addr) const;

  std::expected<void *, std::string>
  try_malloc(size_t size, MemoryProtection protect = MemoryProtection::rw,
             void *nearAddr = nullptr) const;
  void *malloc(size_t size, MemoryProtection protect = MemoryProtection::rw,
               void *nearAddr = nullptr) const;

  std::expected<void, std::string> try_free(void *addr, size_t size = 0) const;
  void free(void *addr, size_t size = 0) const;

  [[nodiscard]] std::optional<std::shared_ptr<Module>>
  module(const std::string &name);

  std::map<std::string, std::shared_ptr<Module>> modules();

  // Return the current (dll) module
  [[nodiscard]] std::optional<std::shared_ptr<Module>> module();

  // Return the current process module
  [[nodiscard]] std::optional<std::shared_ptr<Module>> process_module();

  [[nodiscard]] bool is_self() const;

  static std::shared_ptr<Process> self();

  Pointer memo();

  struct ProcessAllocator& allocator();

  std::vector<Thread> threads();

  template <class... T>
  static std::shared_ptr<Process> attach(T &&...argv) {
    return std::shared_ptr<Process>(new Process(argv...));
  }


};

} // namespace blook