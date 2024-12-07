#include "blook/function.h"
#include "blook/hook.h"
#include "blook/memo.h"
#include "blook/process.h"
#include <cstdlib>
#include <format>
#include <print>
#include <string>

#include "blook/misc.h"
#include "blook/utils.h"
#include "zasm/core/bitsize.hpp"
#include "zasm/x86/assembler.hpp"
#include "zasm/x86/memory.hpp"
#include "zasm/x86/register.hpp"
#include <iostream>
#include <utility>

namespace blook {
Function::Function(std::shared_ptr<Process> proc, void *p_func,
                   std::string name)
    : process(std::move(proc)), ptr(p_func), name(std::move(name)) {}

std::shared_ptr<InlineHook> Function::inline_hook() {
  const auto h = std::make_shared<InlineHook>((void *)ptr);
  return h;
}

Function::Function(std::shared_ptr<Process> proc, void *p_func)
    : process(std::move(proc)), ptr(p_func) {}

size_t Function::guess_size() {
  for (size_t p = (size_t)ptr; p < (size_t)ptr + 50000; p++) {
    if ((*(uint8_t *)p) == 0xCC) {
      return p - (size_t)ptr;
    }
  }

  return 50000;
}
void *Function::into_safe_function_pointer(void *func, bool thread_safety) {
  using namespace zasm;
  static constexpr auto regs_to_save = std::array{
#ifdef BLOOK_ARCHITECTURE_X86_64
      // rax, rcx must be saved at the first place
      x86::rax, x86::rcx, x86::rbx, x86::rdx, x86::rsi,
      x86::rdi, x86::r8,  x86::r9,  x86::r10, x86::r11,
      x86::r12, x86::r13, x86::r14, x86::r15, x86::rbp,
#elif defined(BLOOK_ARCHITECTURE_X86_32)
      x86::eax, x86::ecx, x86::ebx, x86::edx, x86::esi, x86::edi, x86::ebp,
#endif
  };

  auto program = Program(utils::compileMachineMode());
  auto a = x86::Assembler(program);

  auto ptr = ((Pointer)Pointer::malloc_near_rwx(func, 300));
  ptr.reassembly([=](auto a) {
#ifdef BLOOK_ARCHITECTURE_X86_64
       auto sp = x86::rsp;
       auto tmp = x86::rax;
       auto tmp2 = x86::rcx;
       auto pc = x86::rip;

       auto word_ptr = [](auto &&...args) {
         return x86::qword_ptr(std::forward<decltype(args)>(args)...);
       };
#elif defined(BLOOK_ARCHITECTURE_X86_32)
       auto sp = x86::esp;
       auto tmp = x86::eax;
       auto tmp2 = x86::ecx;
       auto pc = x86::eip;

       auto word_ptr = [](auto &&...args) {
         return x86::dword_ptr(std::forward<decltype(args)>(args)...);
       };
#endif

       // saver struct:
       // 0: origin content on [sp + size_t] as we are going to overwrite it
       //    to store the pointer to the saver
       // 1: origin return address
       // 2: regs_to_save[0] --> the origin value of tmp; this have to be
       //    processed specially
       // 3: regs_to_save[1] --> the origin value of tmp2
       auto saver_size = sizeof(size_t) * (regs_to_save.size() + 2);
       auto saver = thread_safety ? 0 : malloc(saver_size);

       static constexpr auto magic_stack_offset = -500;

       auto restoreSaverAddr = [&](bool after_call = false) {
         if (thread_safety) {
           a.lea(tmp, word_ptr(sp, (magic_stack_offset - after_call) * sizeof(size_t)));
         } else {
           a.mov(tmp, Imm((size_t)saver));
         }
       };

       // borrow some space from unused stack to store the sp value
       // we are going to overwrite it
       a.mov(word_ptr(sp, -sizeof(size_t)), tmp);
       a.mov(word_ptr(sp, -2 * sizeof(size_t)), tmp2);

       // rax -> saver address
       restoreSaverAddr();

       auto saverOffset = [&](auto i) {
         return word_ptr(tmp, i * sizeof(size_t));
       };

       for (size_t i = 0; i < regs_to_save.size(); i++) {
         a.mov(saverOffset(i + 2), regs_to_save[i]);
       }

       // save the return address
       auto returnAddr = word_ptr(sp, 0);
       auto saverAddr = word_ptr(sp, sizeof(size_t));
       a.mov(tmp2, returnAddr);
       a.mov(saverOffset(1), tmp2);

       //  override the stack
       a.mov(tmp2, saverAddr);
       a.mov(saverOffset(0), tmp2);
       restoreSaverAddr();
       a.mov(saverAddr, tmp);

       // hook the return address
       auto restorerLabel = a.createLabel();
       a.mov(tmp, restorerLabel);
       a.mov(returnAddr, tmp);

       restoreSaverAddr();

       // record the value of tmp1 and tmp2
       a.mov(tmp2, word_ptr(sp, -sizeof(size_t)));
       a.mov(saverOffset(2), tmp2);
       a.mov(tmp2, word_ptr(sp, -2 * sizeof(size_t)));
       a.mov(saverOffset(3), tmp2);

       // restore tmp and tmp2
       a.mov(tmp, word_ptr(sp, -sizeof(size_t)));
       a.mov(tmp2, word_ptr(sp, -2 * sizeof(size_t)));
// jump to the function
#ifdef BLOOK_ARCHITECTURE_X86_64
       a.mov(x86::rax, Imm((int64_t)func));
       a.jmp(x86::rax);
#elif defined(BLOOK_ARCHITECTURE_X86_32)
       a.jmp(Imm((int32_t)func));
#endif

       // ---------- restorer ----------
       a.int3();
       a.bind(restorerLabel);

       restoreSaverAddr(true);

       // restore the stack we occupied
       a.mov(tmp, saverOffset(0));
       a.mov(word_ptr(sp, 0), tmp);

       restoreSaverAddr(true);

       // pushs the return address onto the stack
       a.push(saverOffset(1));

       // the order of restoring is reversed to ensure tmp is restored last
       for (int i = regs_to_save.size() - 1; i >= 0; i--) {
         a.mov(regs_to_save[i], saverOffset(i + 2));
       }

       a.ret();
       // why the fuck we need to dd here to get our ret
       a.dd(1);
     })
      .patch();

  return ptr.data();
}

#ifdef BLOOK_ARCHITECTURE_X86_64
BLOOK_TEXT_SECTION uint8_t _getCaller[] = {
    0x55,             // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0x48, 0x89, 0xec, // mov rsp, rbp
    0x5d,             // pop rbp
    0xc3              // ret
}; //
#elif defined(BLOOK_ARCHITECTURE_X86_32)
BLOOK_TEXT_SECTION uint8_t _getCaller[] = {
    0x55,       // push ebp
    0x89, 0xe5, // mov ebp, esp
    0x5d,       // pop ebp
    0xc3        // ret
};
#endif
using getCaller_t = void *();
auto getCaller = (getCaller_t *)(void *)_getCaller;

} // namespace blook