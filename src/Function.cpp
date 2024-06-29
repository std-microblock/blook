#include "include/Function.h"
#include "include/Memo.h"

#include <format>
#include <string>

#include <Windows.h>
#include <iostream>

namespace blook {
Function::Function(std::shared_ptr<Module> module, void *p_func,
                   std::string name)
    : module(module), ptr(p_func), name(name) {}
} // namespace blook