//
// Created by MicroBlock on 2024/6/30.
//

#include "blook/misc.h"
#include "blook/Hook.h"
#include "blook/Module.h"
#include "blook/Process.h"
#include "windows.h"
#include "winternl.h"
#include <filesystem>
#include <string>

namespace blook {

    std::filesystem::path current_dll_path() {
        char path[_MAX_PATH];
        GetModuleFileNameA((HMODULE) misc::get_current_module(), path, _MAX_PATH);
        return path;
    }


    void *misc::get_current_module() {
        HMODULE hModule = nullptr;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                          (LPCTSTR) get_current_module, &hModule);

        return (void *) hModule;
    }

    void misc::install_optimize_dll_hijacking(void *orig_module) {
        PBYTE pImageBase = (PBYTE) get_current_module();
        PIMAGE_DOS_HEADER pimDH = (PIMAGE_DOS_HEADER) pImageBase;
        if (pimDH->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS pimNH = (PIMAGE_NT_HEADERS) (pImageBase + pimDH->e_lfanew);
            if (pimNH->Signature == IMAGE_NT_SIGNATURE) {
                PIMAGE_EXPORT_DIRECTORY pimExD =
                        (PIMAGE_EXPORT_DIRECTORY) (pImageBase +
                                                   pimNH->OptionalHeader
                                                           .DataDirectory
                                                   [IMAGE_DIRECTORY_ENTRY_EXPORT]
                                                           .VirtualAddress);
                DWORD *pName = (DWORD *) (pImageBase + pimExD->AddressOfNames);

                auto module = (HINSTANCE) orig_module;
                for (size_t i = 0; i < pimExD->NumberOfNames; ++i) {
                    void *orig =
                            (void *) GetProcAddress(module, (char *) (pImageBase + pName[i]));
                    void *fake = (void *) GetProcAddress((HMODULE) pImageBase,
                                                         (char *) (pImageBase + pName[i]));
                    if (orig) {
                        if (fake == orig) {
                            throw std::runtime_error(
                                    "The origin module cannot be the same as the fake module. This "
                                    "will cause a deadloop.");
                        }
                        VirtualProtect(fake, 16, PAGE_EXECUTE_READWRITE, nullptr);
                        blook::Pointer(fake)
                                .reassembly([&](auto a) {
                                    a.mov(zasm::x86::r10, zasm::Imm((size_t) orig));
                                    a.jmp(zasm::x86::r10);
                                })
                                .patch();
                    }
                }
            }
        }
    }

    void *misc::load_system_module(std::string_view module_name) {
        char system_dir_path[MAX_PATH];
        GetSystemDirectoryA(system_dir_path, MAX_PATH);
        std::filesystem::path path = system_dir_path;
        path /= module_name;
        HMODULE lib = LoadLibraryW(path.c_str());

        return lib;
    }

    void misc::install_optimize_dll_hijacking(std::string_view orig_module) {
        return install_optimize_dll_hijacking(load_system_module(orig_module));
    }
} // namespace blook
