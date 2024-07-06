#pragma once
namespace blook {

    class misc {
    public:
        static void initialize_dll_hijacking();

        static void *get_current_module();
    };

} // namespace blook