#pragma once
#include <cstdint>
#include <memory>
#include <optional>

#include "utils.h"
#include "process.h"

namespace blook {
class Process;
struct Thread : public std::enable_shared_from_this<Thread> {
  size_t id;
  std::shared_ptr<Process> proc;
  std::optional<size_t> handle;
  Thread(size_t id, std::shared_ptr<Process> proc);
  std::optional<std::string> name() const;

  struct ThreadContextCapture {
#ifdef BLOOK_ARCHITECTURE_X86_64
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13,
        r14, r15;
    uint64_t rip, rflags;
#elif defined(BLOOK_ARCHITECTURE_X86_32)
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t eip, eflags;
#endif
  };

  std::optional<ThreadContextCapture> capture_context();
  inline auto context() { return capture_context(); }
  bool set_context(const ThreadContextCapture &ctx);

  size_t stack(size_t offset);
  bool suspend();
  bool resume();
  bool is_suspended();
  bool exists();
  bool terminate();
};
} // namespace blook