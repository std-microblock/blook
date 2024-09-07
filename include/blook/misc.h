#pragma once

#include "dirty_windows.h"
#include <string>

namespace blook {

    class misc {
    public:
        static void initialize_dll_hijacking();

        static void install_optimize_dll_hijacking(void *orig_module);

        static void *
        get_current_module();

        class ContextGuard {
        public:
            ContextGuard();

            ~ContextGuard();

            _CONTEXT context;
        };
    };

} // namespace blook