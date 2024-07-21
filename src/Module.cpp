
#include "blook/Module.h"
#include "Windows.h"
#include "blook/Process.h"

#include <Psapi.h>
#include <cassert>
#include <libloaderapi.h>
#include <map>
#include <utility>

HANDLE RtlCreateUserThread(HANDLE hProcess, LPVOID lpBaseAddress,
                           LPVOID lpSpace) {
  // undocumented.ntinternals.com
  typedef DWORD(WINAPI * functypeRtlCreateUserThread)(
      HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
      BOOL CreateSuspended, ULONG StackZeroBits, PULONG StackReserved,
      PULONG StackCommit, LPVOID StartAddress, LPVOID StartParameter,
      HANDLE ThreadHandle, LPVOID ClientID);
  HANDLE hRemoteThread = NULL;
  HMODULE hNtDllModule = GetModuleHandle("ntdll.dll");
  if (hNtDllModule == NULL) {
    return NULL;
  }
  functypeRtlCreateUserThread funcRtlCreateUserThread =
      (functypeRtlCreateUserThread)GetProcAddress(hNtDllModule,
                                                  "RtlCreateUserThread");
  if (!funcRtlCreateUserThread) {
    return NULL;
  }
  funcRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, lpBaseAddress, lpSpace,
                          &hRemoteThread, NULL);
  DWORD lastError = GetLastError();
  if (lastError)
    throw std::runtime_error(std::to_string(lastError));
  return hRemoteThread;
}

HANDLE NtCreateThreadEx(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpSpace) {
  // undocumented.ntinternals.com
  typedef DWORD(WINAPI * functypeNtCreateThreadEx)(
      PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes,
      HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress,
      LPVOID lpParameter, BOOL CreateSuspended, DWORD dwStackSize,
      DWORD Unknown1, DWORD Unknown2, LPVOID Unknown3);
  HANDLE hRemoteThread = NULL;
  HMODULE hNtDllModule = NULL;
  functypeNtCreateThreadEx funcNtCreateThreadEx = NULL;
  hNtDllModule = GetModuleHandle("ntdll.dll");
  if (hNtDllModule == NULL) {
    return NULL;
  }
  funcNtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress(
      hNtDllModule, "NtCreateThreadEx");
  if (!funcNtCreateThreadEx) {
    return NULL;
  }
  funcNtCreateThreadEx(&hRemoteThread, GENERIC_ALL, NULL, hProcess,
                       (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, FALSE,
                       NULL, NULL, NULL, NULL);
  return hRemoteThread;
}

namespace blook {
std::optional<Function> Module::exports(const std::string &name) {
  if (!proc->is_self())
    throw std::runtime_error("The operation can only be accomplished for the "
                             "current process currently. "
                             "Inject your code into target process first.");
  const auto addr = GetProcAddress(pModule, name.c_str());
  if (addr)
    return Function(proc, (void *)addr, name);
  return {};
}

Module::Module(std::shared_ptr<Process> proc, HMODULE pModule)
    : proc(std::move(proc)), pModule(pModule) {}

std::unordered_map<std::string, Function> *Module::obtain_exports() {
  if (exports_cache.empty()) {
    HMODULE lib = pModule;
    assert(((PIMAGE_DOS_HEADER)lib)->e_magic == IMAGE_DOS_SIGNATURE);
    auto header =
        (PIMAGE_NT_HEADERS)((BYTE *)lib + ((PIMAGE_DOS_HEADER)lib)->e_lfanew);
    assert(header->Signature == IMAGE_NT_SIGNATURE);
    assert(header->OptionalHeader.NumberOfRvaAndSizes > 0);
    auto exports =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE *)lib +
                                  header->OptionalHeader
                                      .DataDirectory
                                          [IMAGE_DIRECTORY_ENTRY_EXPORT]
                                      .VirtualAddress);
    assert(exports->AddressOfNames != 0);
    auto names = (BYTE **)((BYTE *)lib + exports->AddressOfNames);
    for (int i = 0; i < exports->NumberOfNames; i++) {
      const char *functionName = reinterpret_cast<const char *>(
          reinterpret_cast<BYTE *>(lib) + (size_t)names[i]);
    }
  }
  return &exports_cache;
}

void *Module::inject(const std::string &dll_path, Module::InjectMethod method) {
  LPVOID lpSpace =
      (LPVOID)VirtualAllocEx(proc->h, NULL, dll_path.length(),
                             MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!lpSpace)
    throw std::runtime_error(std::format("Failed to alloc in proc"));

  int n = WriteProcessMemory(proc->h, lpSpace, dll_path.c_str(),
                             dll_path.length(), NULL);
  if (n == 0)
    throw std::runtime_error(std::format("failed to write into process"));

  switch (method) {
  case InjectMethod::NtCreateThread:
    return NtCreateThreadEx(proc->h, (void *)LoadLibraryA, lpSpace);
  case InjectMethod::RtlCreateUserThread:
    return RtlCreateUserThread(proc->h, (void *)LoadLibraryA, lpSpace);
  default:
    return CreateRemoteThread(proc->h, NULL, 0,
                              (LPTHREAD_START_ROUTINE)(void *)LoadLibraryA,
                              lpSpace, NULL, NULL);
  }
}

std::optional<MemoryRange> Module::section(const std::string &name) {
  if (!proc->is_self())
    throw std::runtime_error("The operation can only be accomplished for the "
                             "current process currently. "
                             "Inject your code into target process first.");

  auto NtHeaders = (PIMAGE_NT_HEADERS)((char *)pModule +
                                       ((PIMAGE_DOS_HEADER)pModule)->e_lfanew);
  PIMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
  for (WORD SectionIndex = 0;
       SectionIndex < NtHeaders->FileHeader.NumberOfSections; SectionIndex++) {
    PIMAGE_SECTION_HEADER SectionHeader = &SectionHeaders[SectionIndex];

    if (std::strcmp((char *)SectionHeader->Name, name.c_str()) == 0) {
      return MemoryRange(
          proc, (void *)((size_t)pModule + SectionHeader->VirtualAddress),
          SectionHeader->SizeOfRawData);
    }
  }
  return {};
}

size_t Module::size() {
#ifdef WIN32
  MODULEINFO moduleInfo;
  GetModuleInformation(GetCurrentProcess(), (HMODULE)pModule, &moduleInfo,
                       sizeof(MODULEINFO));
  return moduleInfo.SizeOfImage;
#else
  return 0;
#endif
}
} // namespace blook