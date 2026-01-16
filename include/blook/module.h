#pragma once

#include "process.h"
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>

#include "platform_types.h"

#include "function.h"

namespace blook {
class Process;

class Module : public std::enable_shared_from_this<Module> {
  std::shared_ptr<Process> proc;
  WIN_ONLY(HMODULE pModule);
  LINUX_ONLY(void *pModule);

  std::unordered_map<std::string, Function> exports_cache;

  std::unordered_map<std::string, Function> *obtain_exports();

public:
  WIN_ONLY(Module(std::shared_ptr<Process> proc, HMODULE pModule));
  LINUX_ONLY(Module(std::shared_ptr<Process> proc, void *pModule));

  CLASS_MOVE_ONLY(Module)

  template <class... T>
  inline static std::shared_ptr<Module> make(T &&...argv) {
    return std::shared_ptr<Module>(new Module(argv...));
  }

  std::optional<Function> exports(const std::string &name);

  template <class... T>
  inline std::optional<Function> exports(const std::string &name, T... rest) {
    return exports(name).or_else([&]() { return exports(rest...); });
  }

  std::optional<MemoryRange> section(const std::string &name);

  inline MemoryRange memo() {
    return base().range_size(size());
  }

  std::optional<Function> entry_point();

  void *data();

  Pointer base();

  size_t size();
  
  WIN_ONLY(
      enum class InjectMethod{CreateRemoteThread, NtCreateThread,
                              RtlCreateUserThread};

      void *inject(const std::string &dll_path,
                   InjectMethod method = InjectMethod::CreateRemoteThread);)
};

} // namespace blook