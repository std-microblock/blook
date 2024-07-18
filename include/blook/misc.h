#pragma once
namespace blook {

    class misc {
    public:
        static void initialize_dll_hijacking();

        static void *get_current_module();

        class ContextGuard {
        public:
            ContextGuard();

            ~ContextGuard();

            _CONTEXT context;
        };
    };


} // namespace blook