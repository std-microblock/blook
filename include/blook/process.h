#pragma once

#include "module.h"

#include "platform_types.h"

#include "utils.h"
#include <cstdint>
#include <expected>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace blook {
class Pointer;

class Process : public std::enable_shared_from_this<Process> {
#ifdef _WIN32

  DWORD pid;

  explicit Process(HANDLE h);

  explicit Process(DWORD pid);

#endif

  struct Allocator {
    explicit Allocator(std::shared_ptr<Process> proc);

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

  std::optional<Pointer> _memo{};
  std::optional<Allocator> _allocator{};

  explicit Process(std::string name);

protected:
  WIN_ONLY(HANDLE h = nullptr);
  friend Module;
  friend Pointer;

public:
  CLASS_MOVE_ONLY(Process)

  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  read(void *addr, size_t size) const;

  void *read(void *dest, void *addr, size_t size) const;

  std::expected<void, std::string> write(void *addr, std::span<uint8_t>) const;

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

  Allocator allocator();

  template <class... T>
  static std::shared_ptr<Process> attach(T &&...argv) {
    return std::shared_ptr<Process>(new Process(argv...));
  }
};

} // namespace blook