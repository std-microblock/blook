
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

static LONG blook_VectoredExceptionHandler(_EXCEPTION_POINTERS *ExceptionInfo) {
    auto &manager = blook::VEHHookManager::instance();
    auto code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    auto address = ExceptionInfo->ExceptionRecord->ExceptionAddress;
    auto thread_id = GetCurrentThreadId();

    if (code == EXCEPTION_SINGLE_STEP) {
        // Check if this is a re-enable step for a SW/Page-Guard BP
        if (manager.thread_bp_in_progress.contains(thread_id)) {
            void *bp_address = manager.thread_bp_in_progress.at(thread_id);
            
            if (manager.sw_breakpoints.contains(bp_address)) {
                uint8_t int3 = 0xCC;
                Pointer(bp_address).write(nullptr, std::span(&int3, 1));
            } else if (manager.pf_breakpoints.contains(bp_address)) {
                auto &bp = manager.pf_breakpoints.at(bp_address);
                DWORD old_protect;
                VirtualProtect(bp_address, 1, bp.origin_protection | PAGE_GUARD, &old_protect);
            }
            manager.thread_bp_in_progress.erase(thread_id);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // If not a re-enable step, check for a hardware breakpoint
        for (auto &bp_opt : manager.hw_breakpoints) {
            if (bp_opt.has_value() && bp_opt->bp.address == address) {
                if (bp_opt->callback) {
                    size_t origRip = ExceptionInfo->ContextRecord->Rip;
                    VEHHookManager::VEHHookContext ctx(ExceptionInfo);
                    bp_opt->callback(ctx);
                    if (ExceptionInfo->ContextRecord->Rip == origRip) {
                        ExceptionInfo->ContextRecord->Rip =
                            (size_t)bp_opt->trampoline.pTrampoline.data();
                    }
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

    } else if (code == EXCEPTION_BREAKPOINT) {
        if (manager.sw_breakpoints.contains(address)) {
            auto &bp = manager.sw_breakpoints.at(address);
            Pointer(address).write(nullptr, bp.original_bytes);
            ExceptionInfo->ContextRecord->Rip = (DWORD_PTR)address;

            if (bp.callback) {
                VEHHookManager::VEHHookContext ctx(ExceptionInfo);
                bp.callback(ctx);
            }
            
            ExceptionInfo->ContextRecord->EFlags |= (1 << 8);
            manager.thread_bp_in_progress[thread_id] = address;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } else if (code == EXCEPTION_GUARD_PAGE) {
        if (manager.pf_breakpoints.contains(address)) {
            auto &bp = manager.pf_breakpoints.at(address);
            if (bp.callback) {
                VEHHookManager::VEHHookContext ctx(ExceptionInfo);
                bp.callback(ctx);
            }
            manager.thread_bp_in_progress[thread_id] = address;
            ExceptionInfo->ContextRecord->EFlags |= (1 << 8);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


void ensureVectoredExceptionHandler() {
  static bool handler_installed = false;
  if (!handler_installed) {
    AddVectoredExceptionHandler(1, blook_VectoredExceptionHandler);
    handler_installed = true;
  }
}

VEHHookManager::VEHHookHandler
VEHHookManager::add_breakpoint(HardwareBreakpoint bp,
                               BreakpointCallback callback) {
  ensureVectoredExceptionHandler();
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
      .trampoline = Trampoline::make(bp.address, bp.size, true),
  };

  sync_hw_breakpoints();
  return HardwareBreakpointHandler{bp.dr_index};
}
VEHHookManager::VEHHookHandler
VEHHookManager::add_breakpoint(SoftwareBreakpoint bp,
                               BreakpointCallback callback) {
  ensureVectoredExceptionHandler();
  if (sw_breakpoints.contains(bp.address)) {
    throw std::runtime_error("Software breakpoint already exists at this address.");
  }

  SoftwareBreakpointInformation info;
  info.bp = bp;
  info.callback = callback;
  
  auto original_byte = Pointer(bp.address).try_read<uint8_t>();
  if (!original_byte) {
      throw std::runtime_error("Failed to read original byte for software breakpoint.");
  }
  info.original_bytes.push_back(*original_byte);

  uint8_t int3 = 0xCC;
  if (!Pointer(bp.address).write(nullptr, std::span(&int3, 1))) {
      throw std::runtime_error("Failed to write INT3 for software breakpoint.");
  }

  sw_breakpoints[bp.address] = std::move(info);
  return SoftwareBreakpointHandler{bp.address};
}
VEHHookManager::VEHHookHandler
VEHHookManager::add_breakpoint(PagefaultBreakpoint bp,
                               BreakpointCallback callback) {
    ensureVectoredExceptionHandler();
    if (pf_breakpoints.contains(bp.address)) {
        throw std::runtime_error("Pagefault breakpoint already exists at this address.");
    }

    PagefaultBreakpointInformation info;
    info.bp = bp;
    info.callback = callback;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(bp.address, &mbi, sizeof(mbi)) == 0) {
        throw std::runtime_error("VirtualQuery failed for pagefault breakpoint.");
    }
    info.origin_protection = mbi.Protect;

    DWORD old_protect;
    if (!VirtualProtect(bp.address, 1, info.origin_protection | PAGE_GUARD, &old_protect)) {
        throw std::runtime_error("VirtualProtect failed for pagefault breakpoint.");
    }

    pf_breakpoints[bp.address] = std::move(info);
    return PagefaultBreakpointHandler{bp.address};
}
void VEHHookManager::remove_breakpoint(const VEHHookHandler &handler) {
  if (auto _hwbp = std::get_if<HardwareBreakpointHandler>(&handler)) {
    if (_hwbp->dr_index < 0 || _hwbp->dr_index > 3) {
      throw std::runtime_error(
          std::format("Invalid DR index: {}. Must be 0-3.", _hwbp->dr_index));
    }
    hw_breakpoints[_hwbp->dr_index].reset();
    sync_hw_breakpoints();
  } else if (auto _swbp = std::get_if<SoftwareBreakpointHandler>(&handler)) {
    if (!sw_breakpoints.contains(_swbp->address)) {
        return;
    }
    auto& bp_info = sw_breakpoints.at(_swbp->address);
    Pointer(_swbp->address).write(nullptr, bp_info.original_bytes);
    sw_breakpoints.erase(_swbp->address);
  } else if (auto _pfbp = std::get_if<PagefaultBreakpointHandler>(&handler)) {
      if (!pf_breakpoints.contains(_pfbp->address)) {
          return;
      }
      auto& bp_info = pf_breakpoints.at(_pfbp->address);
      DWORD old_protect;
      VirtualProtect(_pfbp->address, 1, bp_info.origin_protection, &old_protect);
      pf_breakpoints.erase(_pfbp->address);
  }
  else {
    throw std::runtime_error("Unsupported breakpoint type.");
  }
}
void VEHHookManager::sync_hw_breakpoints() {
  auto threads = Process::self()->threads();
  for (const auto &thread : threads) {
    for (int i = 0; i < 4; ++i) {
      auto &bp = hw_breakpoints[i];
      if (bp.has_value()) {
        if (auto res = HwBp::Set(
                bp->bp.address, bp->bp.size, bp->bp.when, bp->bp.dr_index,
                OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                               THREAD_SUSPEND_RESUME,
                           false, thread.id));
            res.m_error != HwBp::Result::Success) {
          std::println(
              "Failed to set hardware breakpoint on DR{} for thread ID {}: {}",
              bp->bp.dr_index, thread.id, (int)res.m_error);
        }
      } else {
        HwBp::Remove(i, OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                       THREAD_SUSPEND_RESUME,
                                   false, thread.id));
      }
    }
  }
}
} // namespace blook