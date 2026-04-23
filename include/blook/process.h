#pragma once

#include "platform_types.h"
#include "utils.h"
#include "protect.h"
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
class ProcessAllocator;

class Process : public std::enable_shared_from_this<Process> {
public:
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
  friend ProcessAllocator;

  std::shared_ptr<Pointer> _memo_ptr;
  std::shared_ptr<ProcessAllocator> _allocator_ptr;

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

  std::expected<Protect, std::string>
  try_set_memory_protect(void *addr, size_t size,
                         Protect protect) const;
  Protect set_memory_protect(void *addr, size_t size,
                                      Protect protect) const;

  std::expected<bool, std::string> try_check_valid(void *addr) const;
  bool check_valid(void *addr) const;

  std::expected<Pointer, std::string>
  try_malloc(size_t size, Protect protect = Protect::rw,
             void *nearAddr = nullptr);
  Pointer malloc(size_t size, Protect protect = Protect::rw,
                 void *nearAddr = nullptr);

  std::expected<void, std::string> try_free(void *addr, size_t size = 0);
  void free(void *addr, size_t size = 0);

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

  ProcessAllocator& allocator();

  std::vector<Thread> threads();

  template <class... T>
  static std::shared_ptr<Process> attach(T &&...argv) {
    return std::shared_ptr<Process>(new Process(argv...));
  }

  void suspend();
  void resume();

  WIN_ONLY(
      enum class InjectMethod{CreateRemoteThread, NtCreateThread,
                              RtlCreateUserThread};

      void *inject(const std::string &dll_path,
                   InjectMethod method = InjectMethod::CreateRemoteThread);)

  static std::shared_ptr<Process> launch(const std::string &path,
                                         bool suspended = false);
  static std::shared_ptr<Process> launch_suspended(const std::string &path);
};

} // namespace blook