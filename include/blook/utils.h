#pragma once
#include "ctype.h"
#include "zasm/base/mode.hpp"
#include "zasm/decoder/decoder.hpp"
#include "zasm/zasm.hpp"

#define CLASS_MOVE_ONLY(classname)                                             \
  classname() = delete;                                                        \
  classname(classname &) = delete;                                             \
  classname &operator=(classname &) = delete;                                  \
  classname(classname &&) noexcept = default;                                  \
  classname &operator=(classname &&) noexcept = default;

namespace blook {

namespace utils {
using getreg_fn_t = void *(*)(void);
#ifdef __x86_64__
extern getreg_fn_t getR11;
#elif defined(__i386__)
extern getreg_fn_t getECX;
#endif

std::size_t estimateCodeSize(const zasm::Program &program);

enum class Architecture : std::uint8_t {
  Invalid = 0,
  x86_32,
  x86_64,
};

constexpr Architecture getCompileArchitecture() {
#ifdef __x86_64__
  return Architecture::x86_64;
#elif defined(__i386__)
  return Architecture::x86_32;
#else
  static_assert(false, "Unsupported architecture");
#endif
}

template <Architecture arch = getCompileArchitecture()>
constexpr auto getCompileMachineMode() {
  if constexpr (arch == Architecture::x86_32) {
    return zasm::MachineMode::I386;
  } else if constexpr (arch == Architecture::x86_64) {
    return zasm::MachineMode::AMD64;
  } else {
    static_assert(false, "Unsupported architecture");
  }
}
}; // namespace utils

} // namespace blook