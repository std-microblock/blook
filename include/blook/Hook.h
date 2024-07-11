#pragma once
#include "Function.h"
#include "utils.h"
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

  template <typename ReturnVal, typename... Args>
  inline auto trampoline_t() -> ReturnVal (*)(Args...) {
    return reinterpret_cast<ReturnVal (*)(Args...)>(p_trampoline);
  }

  template <typename Func> inline auto trampoline_t() -> Func * {
    return reinterpret_cast<Func *>(p_trampoline);
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
  inline void install(void *func, bool try_trampoline = true) {
    if (installed)
      throw std::runtime_error("The hook was already installed.");
    hook_func = func;
    install(try_trampoline);
  }
};

template <typename ReturnVal, typename... Args>
struct InlineHookT : public InlineHook {
  inline constexpr InlineHookT(void *target, void *hook_func)
      : InlineHook(target, hook_func) {}
  inline auto trampoline() -> ReturnVal (*)(Args...) {
    return reinterpret_cast<ReturnVal (*)(Args...)>(p_trampoline);
  }
};
template <typename... T> using SIH = std::shared_ptr<InlineHookT<T...>>;
} // namespace blook