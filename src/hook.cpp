
#include "blook/hook.h"
#include "blook/blook.h"
#include <cstdint>
#include <format>
#include <zasm/formatter/formatter.hpp>

#include "./platform/windows/hwbplib.hpp"
#include "zasm/x86/memory.hpp"

namespace blook {
InlineHook::InlineHook(void *target, void *hook_func)
    : target(target), hook_func(hook_func) {}
void InlineHook::install(bool try_trampoline) {
  if (installed)
    throw std::runtime_error("The hook was already installed.");
  if (!hook_func || !target)
    throw std::runtime_error("The hook is invalid.");

  using namespace zasm;
  Program programRewrite(utils::compileMachineMode());
  x86::Assembler a(programRewrite);

  if constexpr (utils::compileArchitecture() == utils::Architecture::x86_64) {
    auto addr2jmp = (size_t)hook_func;
    a.push(Imm32(addr2jmp & 0xFFFFFFFF));
    a.mov(x86::dword_ptr(x86::rsp, 4), Imm32((addr2jmp >> 32) & 0xFFFFFFFF));
    a.ret();
  } else {
    a.jmp(Imm((uint32_t)hook_func));
  }

  Serializer serializer;
  if (auto err = serializer.serialize(programRewrite,
                                      reinterpret_cast<int64_t>(target));
      err != zasm::ErrorCode::None)
    throw std::runtime_error(std::format("JIT Serialization failure: {} {}",
                                         err.getErrorName(),
                                         err.getErrorMessage()));

  const auto hookSize = serializer.getCodeSize();

  trampoline = Trampoline::make(target, hookSize, try_trampoline);

  patch = MemoryPatch{
      Pointer{Process::self(), target},
      std::vector<uint8_t>(serializer.getCode(),
                           serializer.getCode() + serializer.getCodeSize())};
  if (!patch->patch())
    throw std::runtime_error("Failed to patch memory for the hook.");

  installed = true;
}
void *InlineHook::trampoline_raw() { return trampoline->pTrampoline.data(); }
InlineHook::InlineHook(void *target) : target(target) {}
void InlineHook::uninstall() {
  if (!installed)
    throw std::runtime_error("The hook was not installed.");

  patch->restore();

  installed = false;
}

Trampoline Trampoline::make(Pointer pCode, size_t minByteSize,
                            bool near_alloc) {
  Trampoline t;

  auto disasm = blook::disasm::DisassembleRange<blook::MemoryRange>(
      blook::MemoryRange(pCode, minByteSize + 15), pCode);

  zasm::Program program(utils::compileMachineMode());
  zasm::x86::Assembler a(program);
  size_t occupiedBytes = 0;
  for (const auto &instr : disasm) {
    if (occupiedBytes >= minByteSize) {
      break;
    }

    if (auto res = a.emit(instr->getInstruction());
        res != zasm::ErrorCode::None) {
      throw std::runtime_error(std::format("Failed to emit instruction: {} {}",
                                           res.getErrorName(),
                                           res.getErrorMessage()));
    }

    occupiedBytes += instr->getLength();
  }

  auto addr_to_jump_back =
      (size_t)pCode + occupiedBytes; // Address to jump back to after trampoline
  if (near_alloc) {
    a.jmp(zasm::Imm(addr_to_jump_back));
  } else {
    a.push(zasm::Imm32(addr_to_jump_back & 0xFFFFFFFF));
    a.mov(zasm::x86::dword_ptr(zasm::x86::rsp, 4),
          zasm::Imm32((addr_to_jump_back >> 32) & 0xFFFFFFFF));
    a.ret();
  }

  zasm::Serializer serializer;
  auto pCodePage = pCode.malloc(utils::estimateCodeSize(program),
                                near_alloc ? pCode.data() : nullptr,
                                Pointer::MemoryProtection::rwx);
  if (pCodePage == nullptr) {
    throw std::runtime_error("Failed to allocate memory for trampoline.");
  }

  serializer.serialize(program, (size_t)pCodePage);
  if (auto res = pCodePage.write(
          nullptr, std::span<uint8_t>((uint8_t *)serializer.getCode(),
                                      serializer.getCodeSize()));
      !res) {
    throw std::runtime_error(
        std::format("Failed to write trampoline code: {}", res.error()));
  }

  t.pTrampoline = pCodePage;
  t.trampolineSize = serializer.getCodeSize();
  return t;
}

VEHHookManager::VEHHookHandler
VEHHookManager::add_breakpoint(HardwareBreakpoint bp,
                               BreakpointCallback callback) {
  if (bp.dr_index == -1) {
    for (int i = 0; i < 4; ++i) {
      if (!hw_breakpoints[i].has_value()) {
        bp.dr_index = i;
        break;
      }
    }
  }

  if (bp.dr_index < 0 || bp.dr_index > 3) {
    throw std::runtime_error(
        std::format("Invalid DR index: {}. Must be 0-3.", bp.dr_index));
  }
  if (hw_breakpoints[bp.dr_index].has_value()) {
    throw std::runtime_error(std::format(
        "Hardware breakpoint DR{} is already in use.", bp.dr_index));
  }

  hw_breakpoints[bp.dr_index] = {
      .bp = bp,
      .callback = callback,
      .trampoline_address = nullptr,
      .trampoline_size = 0,
  };

  // allocate trampoline

  sync_hw_breakpoints();
  return HardwareBreakpointHandler{bp.dr_index};
}
VEHHookManager::VEHHookHandler
VEHHookManager::add_breakpoint(SoftwareBreakpoint bp,
                               BreakpointCallback callback) {
  throw std::runtime_error("Software breakpoints are not supported yet.");
}
VEHHookManager::VEHHookHandler
VEHHookManager::add_breakpoint(PagefaultBreakpoint bp,
                               BreakpointCallback callback) {
  throw std::runtime_error("Pagefault breakpoints are not supported yet.");
}
void VEHHookManager::remove_breakpoint(const VEHHookHandler &handler) {
  if (auto _hwbp = std::get_if<HardwareBreakpointHandler>(&handler)) {
    if (_hwbp->dr_index < 0 || _hwbp->dr_index > 3) {
      throw std::runtime_error(
          std::format("Invalid DR index: {}. Must be 0-3.", _hwbp->dr_index));
    }
    hw_breakpoints[_hwbp->dr_index].reset();
    sync_hw_breakpoints();
  } else {
    throw std::runtime_error("Unsupported breakpoint type.");
  }
}
void VEHHookManager::sync_hw_breakpoints() {
  auto threads = Process::self()->threads();
  for (const auto &thread : threads) {
    for (auto &bp : hw_breakpoints) {
      if (bp.has_value()) {
        HwBp::Set(bp->bp.address, bp->bp.size, bp->bp.when, bp->bp.dr_index,
                  OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                 THREAD_SUSPEND_RESUME,
                             false, thread.id));
      } else {
        HwBp::Remove(bp->bp.dr_index,
                     OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                    THREAD_SUSPEND_RESUME,
                                false, thread.id));
      }
    }
  }
}
} // namespace blook