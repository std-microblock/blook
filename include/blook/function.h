#pragma once
#include "blook/memo.h"
#include "blook/utils.h"

#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <iostream>
#include <memory>

#include "memo.h"
#include "misc.h"
#include "utils.h"
#include "zasm/base/memory.hpp"
#include "zasm/core/bitsize.hpp"
#include "zasm/x86/memory.hpp"
#include "zasm/x86/register.hpp"
#include "zasm/zasm.hpp"

namespace blook {

class Module;
class InlineHook;
class Function {
  static constexpr auto STACK_MAGIC_NUMBER = 0xb10c;

  template <typename ReturnVal, typename... Args>
  static ReturnVal function_fp_wrapper(Args... args) {
    auto stack = (size_t *)utils::getStackPointer();
    static short stackMagicOffset = -1;
    if (stackMagicOffset == -1) {
      for (int i = 0; i > -100; i--) {
        if (stack[i] == STACK_MAGIC_NUMBER) {
          stackMagicOffset = i + 1;
          break;
        }
      }

      if (stackMagicOffset == -1)
        throw std::runtime_error("Failed to find stack magic number");
    }

    auto ptr = (void *)(stack[stackMagicOffset]);
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

  // specialization for function pointers
  template <typename ReturnVal, typename... Args>
  static inline auto into_function_pointer(ReturnVal (*fn)(Args...)) {
    return fn;
  }

  static inline auto into_function_pointer(auto &&fn) {
    return into_function_pointer(std::function(std::forward<decltype(fn)>(fn)));
  }

  template <typename ReturnVal, typename... Args>
  static inline auto into_function_pointer(
      std::function<ReturnVal(Args...)> &&fn) -> ReturnVal (*)(Args...) {
    return into_function_pointer(new std::function(std::move(fn)));
  }

  template <typename ReturnVal, typename... Args>
  static inline auto into_function_pointer(
      std::function<ReturnVal(Args...)> *fn) -> ReturnVal (*)(Args...) {
    using namespace zasm;

    Program program(utils::compileMachineMode());

    x86::Assembler a(program);
    const auto label = a.createLabel();
    a.bind(label);

    auto fillAddress = [&a](auto reg, size_t offset, size_t value) {
      if constexpr (utils::compileArchitecture() ==
                    utils::Architecture::x86_64) {
        a.mov(x86::word_ptr(reg, offset + 0), Imm16(value & 0xFFFF));
        a.mov(x86::word_ptr(reg, offset + 2), Imm16((value >> 16) & 0xFFFF));
        a.mov(x86::word_ptr(reg, offset + 4), Imm16((value >> 32) & 0xFFFF));
        a.mov(x86::word_ptr(reg, offset + 6), Imm16((value >> 48) & 0xFFFF));
        // a.mov(x86::rax, Imm((int64_t)value));
        // a.mov(x86::qword_ptr(reg, offset), x86::rax);
      } else {
        a.push(x86::eax);
        a.mov(x86::eax, Imm((int32_t)value));
        // a.mov(x86::dword_ptr(reg, offset), x86::eax);
        // ^... the above line is not working for some reason,
        // likely a bug of zydis
        // it's supposed to produce code like following:
        // but it ends up with "impossible instruction" error
        a.db(0x89);
        a.db(0x44);
        a.db(0x24);
        a.db(offset);
        a.pop(x86::eax);
      }
    };

    if constexpr (utils::compileArchitecture() == utils::Architecture::x86_64) {
      fillAddress(x86::rsp, -8 * 25, (size_t)fn);
      fillAddress(x86::rsp, -8 * 26, STACK_MAGIC_NUMBER);
      a.mov(x86::rax, Imm((int64_t)&function_fp_wrapper<ReturnVal, Args...>));
      a.jmp(x86::rax);
    } else if constexpr (utils::compileArchitecture() ==
                         utils::Architecture::x86_32) {
      fillAddress(x86::esp, -4 * 30, (size_t)fn);
      fillAddress(x86::esp, -4 * 31, STACK_MAGIC_NUMBER);
      a.jmp(Imm((int32_t)&function_fp_wrapper<ReturnVal, Args...>));
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

  /*
   This function is used to convert a function pointer into a safe function
   pointer, which is a function pointer that would not contaminate the
   registers

    * @param func the function pointer to convert
    * @param thread_safety whether the function is thread safe. This is
    * implemented by occupying some space on the unused stack to store the
    * registers. So this might cause some problems if the function is so big
    * that it would overwrite the stack.
   */
  static void *into_safe_function_pointer(void *func, bool thread_safety);

  static inline auto into_safe_function_pointer(auto &&fn,
                                                bool thread_safety = false) {
    return (decltype(into_function_pointer(std::forward<decltype(fn)>(fn))))
        into_safe_function_pointer(
            (void *)into_function_pointer(std::forward<decltype(fn)>(fn)),
            thread_safety);
  }

  template <typename T = void *> inline T data() const { return (T)ptr; }
  inline Pointer pointer() const { return Pointer(process, ptr); }
  std::shared_ptr<InlineHook> inline_hook();
};

template <typename T>
concept can_convert_into_function_pointer =
    requires(T a) { Function::into_function_pointer(a); };

} // namespace blook