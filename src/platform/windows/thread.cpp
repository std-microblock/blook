#include "blook/thread.h"
#include "windows.h"

namespace blook {
Thread::Thread(size_t id, std::shared_ptr<Process> proc) : id(id), proc(proc) {
  handle = (size_t)OpenThread(THREAD_ALL_ACCESS, false, id);
}
bool Thread::set_context(const ThreadContextCapture &ctx) {
  CONTEXT context{};
  context.ContextFlags = CONTEXT_FULL;
#ifdef BLOOK_ARCHITECTURE_X86_64
  context.Rax = ctx.rax;
  context.Rcx = ctx.rcx;
  context.Rdx = ctx.rdx;
  context.Rbx = ctx.rbx;
  context.Rsp = ctx.rsp;
  context.Rbp = ctx.rbp;
  context.Rsi = ctx.rsi;
  context.Rdi = ctx.rdi;
  context.R8 = ctx.r8;
  context.R9 = ctx.r9;
  context.R10 = ctx.r10;
  context.R11 = ctx.r11;
  context.R12 = ctx.r12;
  context.R13 = ctx.r13;
  context.R14 = ctx.r14;
  context.R15 = ctx.r15;
  context.Rip = ctx.rip;
  context.EFlags = ctx.rflags;
#elif defined(BLOOK_ARCHITECTURE_X86_32)
  context.Eax = ctx.eax;
  context.Ecx = ctx.ecx;
  context.Edx = ctx.edx;
  context.Ebx = ctx.ebx;
  context.Esp = ctx.esp;
  context.Ebp = ctx.ebp;
  context.Esi = ctx.esi;
  context.Edi = ctx.edi;
  context.Eip = ctx.eip;
  context.EFlags = ctx.eflags;
#endif

  return SetThreadContext((HANDLE)handle.value(), &context);
};
std::optional<Thread::ThreadContextCapture> Thread::capture_context() {
  bool need_resume = suspend();
  ThreadContextCapture ctx;
  CONTEXT context{};
  context.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext((HANDLE)handle.value(), &context))
    return {};
#ifdef BLOOK_ARCHITECTURE_X86_64
  ctx.rax = context.Rax;
  ctx.rcx = context.Rcx;
  ctx.rdx = context.Rdx;
  ctx.rbx = context.Rbx;
  ctx.rsp = context.Rsp;
  ctx.rbp = context.Rbp;
  ctx.rsi = context.Rsi;
  ctx.rdi = context.Rdi;
  ctx.r8 = context.R8;
  ctx.r9 = context.R9;
  ctx.r10 = context.R10;
  ctx.r11 = context.R11;
  ctx.r12 = context.R12;
  ctx.r13 = context.R13;
  ctx.r14 = context.R14;
  ctx.r15 = context.R15;
  ctx.rip = context.Rip;
  ctx.rflags = context.EFlags;
#elif defined(BLOOK_ARCHITECTURE_X86_32)
  ctx.eax = context.Eax;
  ctx.ecx = context.Ecx;
  ctx.edx = context.Edx;
  ctx.ebx = context.Ebx;
  ctx.esp = context.Esp;
  ctx.ebp = context.Ebp;
  ctx.esi = context.Esi;
  ctx.edi = context.Edi;
  ctx.eip = context.Eip;
  ctx.eflags = context.EFlags;
#endif
  if (need_resume)
    resume();
  return ctx;
};
size_t Thread::stack(size_t offset) {
  return proc->memo().read<size_t>(capture_context()
                                       .value()
#ifdef BLOOK_ARCHITECTURE_X86_64
                                       .rsp
#elif defined(BLOOK_ARCHITECTURE_X86_32)
                                       .esp
#endif
                                   + offset);
}
bool Thread::resume() { return ResumeThread((HANDLE)handle.value()) != -1; }
bool Thread::suspend() { return SuspendThread((HANDLE)handle.value()) != -1; }

std::optional<std::string> Thread::name() const {
  PWSTR name;
  if (GetThreadDescription((HANDLE)handle.value(), &name) && name)
    return std::filesystem::path(name).string();
  return {};
}
bool Thread::is_suspended() {
  auto suspended = suspend();
  if (!suspended)
    return true;
  resume();
  return false;
};
} // namespace blook