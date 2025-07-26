#pragma once
#include "blook/memo.h"
#include "function.h"

#include "memo.h"
#include "utils.h"
#include "zasm/x86/assembler.hpp"
#include <optional>

namespace blook {

namespace HwBp {
enum class When { ReadOrWritten, Written, Executed };
}


struct Trampoline {
  Pointer pTrampoline;
  size_t trampolineSize;
  static Trampoline make(Pointer pCode, size_t minByteSize,
                         bool near_alloc = true);
};

class Function;
class InlineHook {
  void *target;
  bool installed = false;
protected:
  void *hook_func = nullptr;
  std::optional<Trampoline> trampoline;
  std::optional<MemoryPatch> patch;

  friend Function;

public:
  CLASS_MOVE_ONLY(InlineHook)
  InlineHook(void *target);
  InlineHook(void *target, void *hook_func);
  void *trampoline_raw();
  inline bool is_installed() const noexcept { return installed; }
  template <typename ReturnVal, typename... Args>
  inline auto trampoline_t() -> ReturnVal (*)(Args...) {
    return reinterpret_cast<ReturnVal (*)(Args...)>(trampoline->pTrampoline.data());
  }

  template <typename Func> inline auto trampoline_t() -> Func * {
    return reinterpret_cast<Func *>(trampoline->pTrampoline.data());
  }

  template <typename ReturnType, typename... Args>
  inline auto call_trampoline(Args... args) -> ReturnType {
    return reinterpret_cast<ReturnType (*)(Args...)>(trampoline->pTrampoline.data())(args...);
  }

  void install(bool try_trampoline = true);
  void uninstall();
  inline void install(auto &&func, bool try_trampoline = true) {
    if (installed)
      throw std::runtime_error("The hook was already installed.");
    hook_func = (void *)Function::into_function_pointer(
        std::forward<decltype(func)>(func));
    install(try_trampoline);
  }
  template <typename T>
  inline void install(T *func, bool try_trampoline = true) {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      if (installed)
        throw std::runtime_error("The hook was already installed.");
      hook_func = (void *)func;
      install(try_trampoline);
    } else {
      static_assert(false, "Only function pointers are allowed");
    }
  }
  inline void install(void *func, bool try_trampoline = true) {
    if (installed)
      throw std::runtime_error("The hook was already installed.");
    hook_func = func;
    install(try_trampoline);
  }
};

class VEHHookManager {
public:
  struct VEHHookContext {};
  using BreakpointCallback = std::function<void(VEHHookContext &ctx)>;

  struct HardwareBreakpoint {
    void *address = nullptr;
    short dr_index = -1;
    int size = 0;
    HwBp::When when = HwBp::When::Executed;
  };

  struct SoftwareBreakpoint {
    void *address = nullptr;
    std::vector<uint8_t> original_bytes;
  };

  struct PagefaultBreakpoint {
    void *address = nullptr;
    int32_t origin_protection = 0;
  };

  struct HardwareBreakpointInformation {
    HardwareBreakpoint bp;
    BreakpointCallback callback;
    void *trampoline_address = nullptr;
    size_t trampoline_size = 0;
  };

  static VEHHookManager &instance() {
    static VEHHookManager instance;
    return instance;
  }

  struct HardwareBreakpointHandler {
    short dr_index = -1;
  };

  using VEHHookHandler =
      std::variant<std::monostate, HardwareBreakpointHandler>;

  VEHHookHandler add_breakpoint(HardwareBreakpoint bp,
                                BreakpointCallback callback);
  VEHHookHandler add_breakpoint(SoftwareBreakpoint bp,
                                BreakpointCallback callback);
  VEHHookHandler add_breakpoint(PagefaultBreakpoint bp,
                                BreakpointCallback callback);
  void remove_breakpoint(const VEHHookHandler &handler);

private:
  std::array<std::optional<HardwareBreakpointInformation>, 4> hw_breakpoints;

  void sync_hw_breakpoints();
  VEHHookManager() {}
};
} // namespace blook