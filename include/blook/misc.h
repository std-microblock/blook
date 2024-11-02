#pragma once

#include "dirty_windows.h"
#include <string>

namespace blook {

    namespace misc {
        void initialize_dll_hijacking();

        void install_optimize_dll_hijacking(void *orig_module);

        void install_optimize_dll_hijacking(std::string_view orig_module);

        void *load_system_module(std::string_view module_name);

        void *get_current_module();

        class ContextGuard {
        public:
            ContextGuard();

            ~ContextGuard();

            _CONTEXT context;
        };
    };

} // namespace blook