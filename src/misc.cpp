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
    void *NtCurrentPeb() {
        /*   __asm {
                   mov eax, fs:[0x30];
           }*/
    }

    PEB_LDR_DATA *NtGetPebLdr(void *peb) {
        /*   __asm {
                   mov eax, peb;
                   mov eax, [eax + 0xc];
           }*/
    }
// https://anhkgg.com/dllhijack/
    VOID SuperDllHijack(const char *dllname, HMODULE hMod) {
        char wszDllName[200] = {0};
        void *peb = NtCurrentPeb();
        PEB_LDR_DATA *ldr = NtGetPebLdr(peb);

        for (LIST_ENTRY *entry = ldr->InMemoryOrderModuleList.Blink;
             entry != (LIST_ENTRY *) (&ldr->InMemoryOrderModuleList);
             entry = entry->Blink) {
            PLDR_DATA_TABLE_ENTRY data = (PLDR_DATA_TABLE_ENTRY) entry;

            memset(wszDllName, 0, 100 * 2);
            memcpy(wszDllName, data->FullDllName.Buffer, data->FullDllName.Length);

            if (!strcmp(wszDllName, dllname)) {
                data->DllBase = hMod;
                break;
            }
        }
    }

    std::filesystem::path current_dll_path() {
        char path[_MAX_PATH];
        GetModuleFileNameA((HMODULE) misc::get_current_module(), path, _MAX_PATH);
        return path;
    }

    void misc::initialize_dll_hijacking() {
        const auto currentDllPath = current_dll_path();
        const auto currentDll = currentDllPath.filename().string();

        const auto origDll = LoadLibraryExA(currentDll.c_str(), nullptr,
                                            LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                            LOAD_LIBRARY_SEARCH_USER_DIRS);
        SuperDllHijack(currentDll.c_str(), origDll);
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
                DWORD *pFunction = (DWORD *) (pImageBase + pimExD->AddressOfFunctions);
                WORD *pNameOrdinals =
                        (WORD *) (pImageBase + pimExD->AddressOfNameOrdinals);

                auto module = (HINSTANCE) orig_module;
                for (size_t i = 0; i < pimExD->NumberOfNames; ++i) {
                    PBYTE Original =
                            (PBYTE) GetProcAddress(module, (char *) (pImageBase + pName[i]));
                    if (Original) {
                        VirtualProtect(&pFunction[pNameOrdinals[i]], sizeof(DWORD),
                                       PAGE_EXECUTE_READWRITE, nullptr);
                        blook::Pointer(&pFunction[pNameOrdinals[i]])
                                .reassembly([&](auto a) {
                                    a.mov(zasm::x86::r10, zasm::Imm((size_t) orig_module));
                                    a.jmp(zasm::x86::r10);
                                })
                                .patch();
                    }
                }
            }
        }
    }

    misc::ContextGuard::ContextGuard() { RtlCaptureContext(&context); }

    misc::ContextGuard::~ContextGuard() { RtlRestoreContext(&context, nullptr); }
} // namespace blook
