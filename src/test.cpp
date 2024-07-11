#include "blook/blook.h"
#include "Windows.h"
#include <format>

void test_wrap_function() {
    int evilNum = 1919810;
    const auto wrapped = blook::Function::into_function_pointer(
            [=](int64_t a, int64_t b) { return a + b + evilNum; });

    const auto non_wrapped =
            std::function([=](int64_t a, int64_t b) { return a + b + evilNum; });

    constexpr auto num = 100000000;
    const auto clock = std::chrono::high_resolution_clock();

    const auto s2 = clock.now();
    for (int a = 0; a < num; a++)
        non_wrapped(114, 514);
    const auto x = clock.now() - s2;
    std::cout << std::format("non-wrapped version took {} for {} calls\n", x,
                             num);

    const auto s1 = clock.now();
    for (int a = 0; a < num; a++)
        wrapped(114, 514);
    const auto b = clock.now() - s1;
    std::cout << std::format("wrapped version took {} for {} calls\n", b, num);

    std::cout << std::format("delta: {}, radio: {}\n", b - x,
                             b.count() / (double) x.count());
}

void test_inline_hook() {
    auto process = blook::Process::self();
    auto hook = process->module("USER32.DLL")
            .value()
            ->exports("MessageBoxA")
            ->inline_hook();
    hook->install([=](int64_t a, char *text, char *title, int64_t b) -> int64_t {
        return hook->trampoline_t<int64_t(int64_t, char *, char *, int64_t)>()(
                a, (char *) "oh fuck", text, b);
    });

    MessageBoxA(nullptr, "hi", "hi", 0);

    hook->uninstall();
    MessageBoxA(nullptr, "hi", "hi", 0);
}

void test_section_view() {
    auto process = blook::Process::self();
    auto mod = process->module().value();
    auto text = mod->section(".rdata").value();
    static auto a_special_variable = "this_is_some_special_string_that_represents_a_damn_vip_proc";
    std::cout << text.data() << " " << text.size() << std::endl;
    const auto p = text.find_one("special_string");
    std::cout << std::hex << "" << p.value().data();
}

int main() {
    try {
        test_section_view();
    } catch (std::exception &e) {
        std::cerr << e.what();
        abort();
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, // handle to DLL module
                    DWORD fdwReason,    // reason for calling function
                    LPVOID lpvReserved) // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(nullptr, "hi", "hi", 0);
            blook::misc::initialize_dll_hijacking();

            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:

            if (lpvReserved != nullptr) {
                break; // do not do cleanup if process termination scenario
            }

            // Perform any necessary cleanup.
            break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}
