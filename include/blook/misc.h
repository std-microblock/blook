#pragma once

#include <string>

#ifdef _MSC_VER
#pragma section(".text")
#define BLOOK_TEXT_SECTION __declspec(allocate(".text"))
#else
#define BLOOK_TEXT_SECTION __attribute__((section(".text"))) __attribute__((used))
#endif

namespace blook {

    namespace misc {
        void install_optimize_dll_hijacking(void *orig_module);

        void install_optimize_dll_hijacking(std::string_view orig_module);

        void *load_system_module(std::string_view module_name);

        void *get_current_module();
    };

} // namespace blook