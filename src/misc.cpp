//
// Created by MicroBlock on 2024/6/30.
//

#include "include/misc.h"
#include "include/Hook.h"
#include "include/Module.h"
#include "include/Process.h"
#include "windows.h"
#include "winternl.h"
#include <filesystem>
#include <string>
void *NtCurrentPeb() {
  __asm {
		mov eax, fs:[0x30];
  }
}
PEB_LDR_DATA *NtGetPebLdr(void *peb) {
  __asm {
		mov eax, peb;
		mov eax, [eax + 0xc];
  }
}
// https://anhkgg.com/dllhijack/
VOID SuperDllHijack(const char *dllname, HMODULE hMod) {
  char wszDllName[100] = {0};
  void *peb = NtCurrentPeb();
  PEB_LDR_DATA *ldr = NtGetPebLdr(peb);

  for (LIST_ENTRY *entry = ldr->InMemoryOrderModuleList.Blink;
       entry != (LIST_ENTRY *)(&ldr->InMemoryOrderModuleList);
       entry = entry->Blink) {
    PLDR_DATA_TABLE_ENTRY data = (PLDR_DATA_TABLE_ENTRY)entry;

    memset(wszDllName, 0, 100 * 2);
    memcpy(wszDllName, data->FullDllName.Buffer, data->FullDllName.Length);

    if (!strcmp(wszDllName, dllname)) {
      data->DllBase = hMod;
      break;
    }
  }
}

HMODULE GetCurrentModule() {
  HMODULE hModule = NULL;
  GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    (LPCTSTR)GetCurrentModule, &hModule);

  return hModule;
}

std::filesystem::path current_dll_path() {
  char path[_MAX_PATH];
  GetModuleFileNameA(GetCurrentModule(), path, _MAX_PATH);
  return path;
}

namespace blook {
void misc::initialize_dll_hijacking() {
  const auto currentDllPath = current_dll_path();
  const auto currentDll = currentDllPath.filename().string();

  const auto origDll = LoadLibraryExA(currentDll.c_str(), nullptr,
                                      LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                          LOAD_LIBRARY_SEARCH_USER_DIRS);
  SuperDllHijack(currentDll.c_str(), origDll);
}
} // namespace blook