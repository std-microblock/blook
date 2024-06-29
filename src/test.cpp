#include "../blook.h"
#include "Windows.h"

int main() {
    auto process = blook::Process::self();
    process->module("KERNEL32.DLL").value()
        ->exports("MessageBoxA");
//        ->inline_hook([](){
//
//        });

    MessageBoxA(nullptr, "hi", "hi", 0);
}