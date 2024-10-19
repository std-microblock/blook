#pragma once

#include "Module.h"
#include "dirty_windows.h"
#include "utils.h"
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
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

  std::optional<Pointer> _memo{};

  explicit Process(std::string name);

protected:
  HANDLE h = nullptr;
  friend Module;
  friend Pointer;

public:
  CLASS_MOVE_ONLY(Process)

  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  read(void *addr, size_t size) const;

  void *read(void *dest, void *addr, size_t size) const;

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

  template <class... T>
  static std::shared_ptr<Process> Process::attach(T &&...argv) {
    return std::shared_ptr<Process>(new Process(argv...));
  }
};

} // namespace blook