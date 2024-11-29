#include "blook/Function.h"
#include "blook/Hook.h"
#include "blook/Memo.h"
#include "blook/Process.h"
#include <format>
#include <string>

#include "blook/misc.h"

#include <Windows.h>
#include <iostream>
#include <utility>


namespace blook {
    Function::Function(std::shared_ptr<Process> proc, void *p_func,
                       std::string name)
            : process(std::move(proc)), ptr(p_func), name(std::move(name)) {}

    std::shared_ptr<InlineHook> Function::inline_hook() {
        const auto h = std::make_shared<InlineHook>((void *) ptr);
        return h;
    }

    Function::Function(std::shared_ptr<Process> proc, void *p_func)
            : process(std::move(proc)), ptr(p_func) {}

    size_t Function::guess_size() {
        for (size_t p = (size_t) ptr; p < (size_t) ptr + 50000; p++) {
            if ((*(uint8_t *) p) == 0xCC) {
                return p - (size_t) ptr;
            }
        }

        return 50000;
    }
} // namespace blook

#ifdef __x86_64__
BLOOK_TEXT_SECTION uint8_t _getCaller[] = {
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x48, 0x89, 0xec, // mov rsp, rbp
        0x5d, // pop rbp
        0xc3 // ret
};//
#elif defined(__i386__)
BLOOK_TEXT_SECTION uint8_t _getCaller[] = {
        0x55, // push ebp
        0x89, 0xe5, // mov ebp, esp
        0x5d, // pop ebp
        0xc3 // ret
};
#endif
using getCaller_t = void *();
auto getCaller = (getCaller_t *) _getCaller;
