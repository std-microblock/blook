#pragma once
#include "blook/memo.h"
#include "function.h"

#include "memo.h"
#include "utils.h"
#include "zasm/x86/assembler.hpp"
#include <optional>

namespace blook {
class Function;
class InlineHook {
  void *target;
  std::optional<std::vector<unsigned char>> origData;
  size_t trampoline_size = 0;
  bool installed = false;

protected:
  void *hook_func = nullptr;
  void *p_trampoline = nullptr;

  friend Function;

public:
  CLASS_MOVE_ONLY(InlineHook)
  InlineHook(void *target);
  InlineHook(void *target, void *hook_func);
  void *trampoline_raw();
  inline bool is_installed() const noexcept {
    return installed;
  }
  template <typename ReturnVal, typename... Args>
  inline auto trampoline_t() -> ReturnVal (*)(Args...) {
    return reinterpret_cast<ReturnVal (*)(Args...)>(p_trampoline);
  }

  template <typename Func> inline auto trampoline_t() -> Func * {
    return reinterpret_cast<Func *>(p_trampoline);
  }

  template <typename ReturnType, typename... Args>
  inline auto call_trampoline(Args... args) -> ReturnType {
    return reinterpret_cast<ReturnType (*)(Args...)>(p_trampoline)(args...);
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

class AnywhereHook {
  std::optional<MemoryPatch> patch;
  Pointer target;
  void *hook_func = nullptr;
  bool installed = false;

public:
  AnywhereHook(Pointer target);

  void install(auto &&func) {
    if (installed)
      throw std::runtime_error("The hook was already installed.");

    hook_func = Function::into_safe_function_pointer(
        std::forward<decltype(func)>(func));

    patch = target.reassembly([](zasm::x86::Assembler a) {

    });
  }

  void uninstall() {}
};
} // namespace blook