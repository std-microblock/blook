#include "Function.h"
#include "Memo.h"
#include "zasm/zasm.hpp"
#include <string>
#include <format>

#include <Windows.h>

namespace blook {
Function::Function(std::shared_ptr<Module> module, void *p_func,
                   std::string name)
    :
      module(module), p_func(p_func), name(name)
{

}

template <typename ReturnVal, typename ...Args>
static ReturnVal function_fp_wrapper(Args... args) {
  CONTEXT context;
  RtlCaptureContext(&context);

#ifdef _WIN64
  DWORD_PTR* ebp = (DWORD_PTR*)context.Rsp;
  DWORD_PTR* eip = (DWORD_PTR*)context.Rip;
#else
  DWORD_PTR* ebp = (DWORD_PTR*)context.Ebp;
  DWORD_PTR* eip = (DWORD_PTR*)context.Eip;
#endif

}

template <typename ReturnVal, typename ...Args>
auto Function::into_function_pointer(std::function<ReturnVal(Args...)>* fn) -> ReturnVal(*)(Args...) {
  using namespace zasm;
  Program program;
  x86::Assembler a(program);


}
}