#pragma once

#include "ctype.h"
#include "zasm/base/mode.hpp"
#include "zasm/decoder/decoder.hpp"
#include "zasm/zasm.hpp"
#include <string>

#ifndef CLASS_MOVE_ONLY
#define CLASS_MOVE_ONLY(classname)                                             \
  classname(const classname &) = delete;                                       \
  classname &operator=(const classname &) = delete;                            \
  classname(classname &&) noexcept = default;                                  \
  classname &operator=(classname &&) noexcept = default;
#endif


#if defined(__x86_64__) || defined(_M_X64)
#define BLOOK_ARCHITECTURE_X86_64
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#define BLOOK_ARCHITECTURE_X86_32
#endif

namespace blook {

namespace utils {
using getreg_fn_t = void *(*)(void);
#ifdef BLOOK_ARCHITECTURE_X86_64
extern getreg_fn_t getR11;
#elif defined(BLOOK_ARCHITECTURE_X86_32)
extern getreg_fn_t getEDX;
#endif

extern getreg_fn_t getStackPointer;
#ifdef _WIN32
extern getreg_fn_t getPEB;
#endif 

std::size_t estimateCodeSize(const zasm::Program &program);

enum class Architecture : std::uint8_t {
  Invalid = 0,
  x86_32,
  x86_64,
};

constexpr Architecture compileArchitecture() {
#if defined(BLOOK_ARCHITECTURE_X86_64)
  return Architecture::x86_64;
#elif defined(BLOOK_ARCHITECTURE_X86_32)
  return Architecture::x86_32;
#else
  static_assert(false, "Unsupported architecture");
#endif
}

template <Architecture arch = compileArchitecture()>
constexpr auto compileMachineMode() {
  if constexpr (arch == Architecture::x86_32) {
    return zasm::MachineMode::I386;
  } else if constexpr (arch == Architecture::x86_64) {
    return zasm::MachineMode::AMD64;
  } else {
    static_assert(false, "Unsupported architecture");
  }
}

std::string to_lower(const std::string &str);

}; // namespace utils

} // namespace blook