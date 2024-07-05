#include "include/Function.h"
#include "include/Hook.h"
#include "include/Memo.h"
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
} // namespace blook