#pragma once
#include "blook/utils.h"
#include "dirty_windows.h"

#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <iostream>
#include <memory>

#include "Memo.h"
#include "misc.h"
#include "utils.h"
#include "zasm/base/memory.hpp"
#include "zasm/core/bitsize.hpp"
#include "zasm/zasm.hpp"

namespace blook {

class Module;
class InlineHook;
class Function {
  static constexpr auto STACK_MAGIC_NUMBER = 0xb10c;

  template <typename ReturnVal, typename... Args>
  static ReturnVal function_fp_wrapper(Args... args) {
    auto stack = (size_t *)utils::getStackPointer();

    void *ptr = nullptr;
    for (int i = 0; i < 100; i++) {
      if (stack[i] == STACK_MAGIC_NUMBER) {
        
        ptr = (void *)(stack[i + 1]);
        break;
      }
    }

    const auto fn = reinterpret_cast<std::function<ReturnVal(Args...)> *>(ptr);
    return (*fn)(args...);
  }

  std::shared_ptr<Process> process;
  void *ptr;
  std::string name = "<unnamed function>";

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
    std::cout << (void *)fn << std::endl;
    using namespace zasm;

    Program program(utils::compileMachineMode());

    x86::Assembler a(program);
    const auto label = a.createLabel();
    a.bind(label);

    if constexpr (utils::compileArchitecture() == utils::Architecture::x86_64) {
      a.mov(x86::r11, Imm((size_t)fn));
      a.push(x86::r11);
      a.push(Imm(STACK_MAGIC_NUMBER));
      a.mov(x86::rax, Imm((int64_t)&function_fp_wrapper<ReturnVal, Args...>));
      a.call(x86::rax);
      a.add(x86::rsp, Imm(16));
      a.ret();
    } else if constexpr (utils::compileArchitecture() ==
                         utils::Architecture::x86_32) {
      a.push(Imm((int32_t)fn));
      a.push(Imm(STACK_MAGIC_NUMBER));
      a.mov(x86::eax, Imm((size_t)&function_fp_wrapper<ReturnVal, Args...>));
      a.call(x86::eax);
      a.add(x86::esp, Imm(8));
      a.ret();
    }

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
  template <typename T = void *> T data() const { return (T)ptr; }
  std::shared_ptr<InlineHook> inline_hook();
};

template <typename T>
concept can_convert_into_function_pointer =
    requires(T a) { Function::into_function_pointer(a); };

} // namespace blook