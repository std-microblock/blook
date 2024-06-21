#include "blook.h"

int main() {
    auto process = blook::Process("Notepad.exe");
    process.module("Kernal32.dll")->exports("MessageBoxA");

}