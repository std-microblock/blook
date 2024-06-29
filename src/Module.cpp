
#include "include/Module.h"
#include <cassert>
#include <libloaderapi.h>
#include <map>
#include <utility>

namespace blook {
std::optional<Function> Module::exports(const std::string &name) {
  if (!proc->is_self())
    throw std::runtime_error("The operation can only be accomplished for the "
                             "current process currently. "
                             "Inject your code into target process first.");
  const auto addr = GetProcAddress(pModule, name.c_str());
  if (addr)
    return Function(p_self.lock(), addr, name);
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
} // namespace blook