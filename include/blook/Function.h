#pragma once

#include <format>
#include <functional>
#include <iostream>
#include <memory>

#include "Memo.h"
#include "dirty_windows.h"
#include "utils.h"
#include "zasm/zasm.hpp"

extern "C" int64_t getR11();

namespace blook {
class Module;
class InlineHook;
class Function {

  std::shared_ptr<Process> process;
  void *ptr;
  std::string name = "<unnamed function>";

  template <typename ReturnVal, typename... Args>
  static ReturnVal function_fp_wrapper(Args... args) {
    const auto r11 = getR11();
    const auto fn = reinterpret_cast<std::function<ReturnVal(Args...)> *>(r11);
    return (*fn)(args...);
  }

  size_t guess_size();

public:
  Function(std::shared_ptr<Process> proc, void *p_func);
  Function(std::shared_ptr<Process> proc, void *p_func, std::string name);
  CLASS_MOVE_ONLY(Function)

  static inline auto into_function_pointer(auto &&fn) {
    return into_function_pointer(std::function(std::forward<decltype(fn)>(fn)));
  }

  template <typename ReturnVal, typename... Args>
  static inline auto
  into_function_pointer(std::function<ReturnVal(Args...)> &&fn)
      -> ReturnVal (*)(Args...) {
    return into_function_pointer(new std::function(std::move(fn)));
  }

  template <typename ReturnVal, typename... Args>
  static inline auto
  into_function_pointer(std::function<ReturnVal(Args...)> *fn)
      -> ReturnVal (*)(Args...) {
    using namespace zasm;
    Program program(MachineMode::AMD64);

    x86::Assembler a(program);
    const auto label = a.createLabel();
    a.bind(label);
    a.mov(x86::r11, Imm((size_t)fn));
    a.mov(x86::r12, Imm((int64_t)&function_fp_wrapper<ReturnVal, Args...>));
    a.jmp(x86::r12);

    Serializer serializer;
    void *pCodePage = Pointer::malloc_rwx(utils::estimateCodeSize(program));
    if (auto err =
            serializer.serialize(program, reinterpret_cast<int64_t>(pCodePage));
        err != zasm::ErrorCode::None)
      throw std::runtime_error(
          std::format("JIT Serialization failure: {}", err.getErrorName()));

    std::memcpy(pCodePage, serializer.getCode(), serializer.getCodeSize());
    const auto funcAddress = serializer.getLabelAddress(label.getId());
    assert(funcAddress != -1);
    return reinterpret_cast<ReturnVal (*)(Args...)>(funcAddress);
  }

  std::shared_ptr<InlineHook> inline_hook();
};

template <typename T>
concept can_convert_into_function_pointer =
    requires(T a) { Function::into_function_pointer(a); };

} // namespace blook