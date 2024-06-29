#pragma once
#include "ctype.h"
#include "zasm/zasm.hpp"

#define CLASS_MOVE_ONLY(classname)                                             \
  classname() = delete;                                                        \
  classname(classname &) = delete;                                             \
  classname &operator=(classname &) = delete;                                  \
  classname(classname &&) noexcept = default;                                  \
  classname &operator=(classname &&) noexcept = default;

namespace blook {

struct utils {
  static std::size_t estimateCodeSize(const zasm::Program &program);
};

} // namespace blook