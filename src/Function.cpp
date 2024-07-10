#include "blook/Function.h"
#include "blook/Hook.h"
#include "blook/Memo.h"
#include <format>
#include <string>

#include <Windows.h>
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
} // namespace blook