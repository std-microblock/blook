// Modified from: https://github.com/biocomp/hw_break/tree/master/HwBpLib

#pragma once
#pragma warning(push)
#include <Windows.h>
#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <cstddef>
#include "blook/hook.h"

#pragma warning(pop)
namespace blook {
namespace HwBp {
enum class Result {
  Success,
  CantGetThreadContext,
  CantSetThreadContext,
  NoAvailableRegisters,
  BadWhen,
  BadSize
};

struct Breakpoint {
  static constexpr Breakpoint MakeFailed(Result result) { return {0, result}; }

  const std::uint8_t m_registerIndex;
  const Result m_error;
};

namespace Detail {
template <typename TAction, typename TFailure>
auto UpdateThreadContext(HANDLE thread, TAction action, TFailure failure) {
  CONTEXT ctx{0};
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (::GetThreadContext(thread, &ctx) == FALSE) {
    return failure(Result::CantGetThreadContext);
  }

  std::array<bool, 4> busyDebugRegister{{false, false, false, false}};
  auto checkBusyRegister = [&](std::size_t index, DWORD64 mask) {
    if (ctx.Dr7 & mask)
      busyDebugRegister[index] = true;
  };

  checkBusyRegister(0, 1);
  checkBusyRegister(1, 4);
  checkBusyRegister(2, 16);
  checkBusyRegister(3, 64);

  const auto actionResult = action(ctx, busyDebugRegister);

  if (::SetThreadContext(thread, &ctx) == FALSE) {
    return failure(Result::CantSetThreadContext);
  }

  return actionResult;
}
} // namespace Detail

Breakpoint Set(const void *onPointer, std::uint8_t size, When when, int drIndex,
               HANDLE thread = ::GetCurrentThread()) {
  return Detail::UpdateThreadContext(
      thread,
      [&](CONTEXT &ctx,
          const std::array<bool, 4> &busyDebugRegister) -> Breakpoint {
        const auto registerIndex = drIndex;
        switch (registerIndex) {
        case 0:
          ctx.Dr0 = reinterpret_cast<DWORD_PTR>(const_cast<void *>(onPointer));
          break;
        case 1:
          ctx.Dr1 = reinterpret_cast<DWORD_PTR>(const_cast<void *>(onPointer));
          break;
        case 2:
          ctx.Dr2 = reinterpret_cast<DWORD_PTR>(const_cast<void *>(onPointer));
          break;
        case 3:
          ctx.Dr3 = reinterpret_cast<DWORD_PTR>(const_cast<void *>(onPointer));
          break;
        default:
          assert(!"Impossible happened - searching in array of 4 got index < 0 "
                  "or > 3");
          std::exit(EXIT_FAILURE);
        }

        std::bitset<sizeof(ctx.Dr7) * 8> dr7;
        std::memcpy(&dr7, &ctx.Dr7, sizeof(ctx.Dr7));

        dr7.set(registerIndex * 2);

        switch (when) {
        case When::ReadOrWritten:
          dr7.set(16 + registerIndex * 4 + 1, true);
          dr7.set(16 + registerIndex * 4, true);
          break;

        case When::Written:
          dr7.set(16 + registerIndex * 4 + 1, false);
          dr7.set(16 + registerIndex * 4, true);
          break;

        case When::Executed:
          dr7.set(16 + registerIndex * 4 + 1, false);
          dr7.set(16 + registerIndex * 4, false);
          break;

        default:
          return Breakpoint::MakeFailed(Result::BadWhen);
        }

        switch (size) {
        case 1:
          dr7.set(16 + registerIndex * 4 + 3, false);
          dr7.set(16 + registerIndex * 4 + 2, false);
          break;

        case 2:
          dr7.set(16 + registerIndex * 4 + 3, false);
          dr7.set(16 + registerIndex * 4 + 2, true);
          break;

        case 8:
          dr7.set(16 + registerIndex * 4 + 3, true);
          dr7.set(16 + registerIndex * 4 + 2, false);
          break;

        case 4:
          dr7.set(16 + registerIndex * 4 + 3, true);
          dr7.set(16 + registerIndex * 4 + 2, true);
          break;

        default:
          return Breakpoint::MakeFailed(Result::BadSize);
        }

        std::memcpy(&ctx.Dr7, &dr7, sizeof(ctx.Dr7));

        return Breakpoint{static_cast<std::uint8_t>(registerIndex),
                          Result::Success};
      },
      [](auto failureCode) { return Breakpoint::MakeFailed(failureCode); });
}

void Remove(int drIndex, HANDLE thread = ::GetCurrentThread()) {
  const Breakpoint bp{static_cast<std::uint8_t>(drIndex), Result::Success};
  if (bp.m_error != Result::Success) {
    return;
  }

  Detail::UpdateThreadContext(
      thread,
      [&](CONTEXT &ctx, const std::array<bool, 4> &) -> Breakpoint {
        std::bitset<sizeof(ctx.Dr7) * 8> dr7;
        std::memcpy(&dr7, &ctx.Dr7, sizeof(ctx.Dr7));

        dr7.set(bp.m_registerIndex * 2, false);

        std::memcpy(&ctx.Dr7, &dr7, sizeof(ctx.Dr7));

        return Breakpoint{};
      },
      [](auto failureCode) { return Breakpoint::MakeFailed(failureCode); });
}
} // namespace HwBp
} // namespace blook