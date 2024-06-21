#include "blook.h"

int main() {
    auto process = blook::Process::self();
    process.module("Kernel32.dll")
        ->exports("MessageBoxA")
        ->inline_hook([](){

        });

}