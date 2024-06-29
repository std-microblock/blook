#pragma once

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
class Module;

class Process {
#ifdef _WIN32
  HANDLE h;
  DWORD pid;
  explicit Process(HANDLE h);
  explicit Process(DWORD pid);
#endif
  std::weak_ptr<Process> p_self{};

  explicit Process(std::string name);

public:
  CLASS_MOVE_ONLY(Process)

  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  read(void *addr, size_t size) const;

  [[nodiscard]] std::optional<std::shared_ptr<Module>>
  module(const std::string &name) const;
  [[nodiscard]] bool is_self() const;

  static std::shared_ptr<Process> self();

  template <class... T> static std::shared_ptr<Process> attach(T &&...argv);
};

} // namespace blook