#include <print>
#include <thread>

#include "blook/blook.h"

#include "windows.h"

#include "psapi.h"
#include <TlHelp32.h>

#include <expected>
#include <ranges>
#include <utility>

#ifdef _WIN32

static std::optional<uint64_t> FindProcessByName(const std::string &name,
                                                 size_t skip = 0) {
  PROCESSENTRY32 entry{.dwSize = sizeof(PROCESSENTRY32)};

  auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Process32First(snapshot, &entry)) {
    do {
      if (std::string(entry.szExeFile) == name && (skip--) == 0) {
        return entry.th32ProcessID;
      }
    } while (Process32Next(snapshot, &entry));
  }

  return {};
}

static HMODULE GetProcessBaseAddress(HANDLE processHandle,
                                     std::string modulename) {
  HMODULE baseAddress = 0;
  HMODULE *moduleArray;
  LPBYTE moduleArrayBytes;
  DWORD bytesRequired;
  std::transform(modulename.begin(), modulename.end(), modulename.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (processHandle) {
    if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired)) {
      if (bytesRequired) {
        moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

        if (moduleArrayBytes) {
          unsigned int moduleCount;

          moduleCount = bytesRequired / sizeof(HMODULE);
          moduleArray = (HMODULE *)moduleArrayBytes;

          if (EnumProcessModules(processHandle, moduleArray, bytesRequired,
                                 &bytesRequired)) {
            for (int i = 0; i < moduleCount; i++) {
              const auto module = moduleArray[i];
              char name[MAX_PATH];
              if (GetModuleFileNameA(module, name, MAX_PATH)) {
                auto filename = std::filesystem::path(name).filename().string();

                std::transform(filename.begin(), filename.end(),
                               filename.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                if (modulename == filename) {
                  baseAddress = module;
                  break;
                }
              }
            }
          }

          LocalFree(moduleArrayBytes);
        }
      }
    }
  }

  return baseAddress;
}

static bool acquireDebugPrivilege() {
  static bool permissionAcquired = false;
  if (!permissionAcquired) {
    TOKEN_PRIVILEGES NewState;
    NewState.PrivilegeCount = 1;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME,
                              &NewState.Privileges[0].Luid))
      return false;

    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
      return false;

    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token, FALSE, &NewState, sizeof(NewState),
                               nullptr, nullptr))
      return false;

    permissionAcquired = true;
  }

  return true;
}

#endif

namespace blook {

static DWORD ProtectToWin(Process::MemoryProtection protect) {
  using MP = Process::MemoryProtection;
  if ((int)protect & (int)MP::Execute) {
    if ((int)protect & (int)MP::Write)
      return PAGE_EXECUTE_READWRITE;
    if ((int)protect & (int)MP::Read)
      return PAGE_EXECUTE_READ;
    return PAGE_EXECUTE;
  }
  if ((int)protect & (int)MP::Write)
    return PAGE_READWRITE;
  if ((int)protect & (int)MP::Read)
    return PAGE_READONLY;
  return PAGE_NOACCESS;
}

static Process::MemoryProtection WinToProtect(DWORD win) {
  using MP = Process::MemoryProtection;
  switch (win & 0xFF) {
  case PAGE_EXECUTE:
    return MP::Execute;
  case PAGE_EXECUTE_READ:
    return MP::ReadExecute;
  case PAGE_EXECUTE_READWRITE:
  case PAGE_EXECUTE_WRITECOPY:
    return MP::ReadWriteExecute;
  case PAGE_READONLY:
    return MP::Read;
  case PAGE_READWRITE:
  case PAGE_WRITECOPY:
    return MP::ReadWrite;
  case PAGE_NOACCESS:
  default:
    return MP::None;
  }
}

static bool safe_memcpy(void *dst, const void *src, size_t size) {
  __try {
    std::memcpy(dst, src, size);
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

std::expected<void, std::string> Process::try_read(void *dst, void *src,
                                                   size_t size) const {
  if (is_self()) {
    if (safe_memcpy(dst, src, size)) {
      return {};
    } else {
      return std::unexpected("Failed to read memory: access violation");
    }
  } else {
    SIZE_T read = 0;
    if (ReadProcessMemory(this->h, src, dst, size, &read) && read == size)
      return {};
    return std::unexpected(
        std::format("Failed to read process memory: {}", GetLastError()));
  }
}

void Process::read(void *dst, void *src, size_t size) const {
  auto res = try_read(dst, src, size);
  if (!res)
    throw std::runtime_error(res.error());
}

std::expected<void, std::string> Process::try_write(void *dst, const void *src,
                                                    size_t size) const {
  if (is_self()) {
    if (safe_memcpy(dst, src, size)) {
      return {};
    } else {
      return std::unexpected(std::format("Failed to write memory {:p}: access violation", dst));
    }
  } else {
    SIZE_T written = 0;
    if (WriteProcessMemory(this->h, dst, src, size, &written) &&
        written == size)
      return {};
    return std::unexpected(
        std::format("Failed to write process memory: {}", GetLastError()));
  }
}

void Process::write(void *dst, const void *src, size_t size) const {
  auto res = try_write(dst, src, size);
  if (!res)
    throw std::runtime_error(res.error());
}

std::expected<bool, std::string>
Process::try_check_readable(void *addr, size_t size) const {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQueryEx(this->h, addr, &mbi, sizeof(mbi)) == 0)
    return std::unexpected(
        std::format("VirtualQueryEx failed: {}", GetLastError()));

  if (mbi.State != MEM_COMMIT)
    return false;
  if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
    return false;
  return true;
}

bool Process::check_readable(void *addr, size_t size) const {
  auto res = try_check_readable(addr, size);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

std::expected<bool, std::string>
Process::try_check_writable(void *addr, size_t size) const {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQueryEx(this->h, addr, &mbi, sizeof(mbi)) == 0)
    return std::unexpected(
        std::format("VirtualQueryEx failed: {}", GetLastError()));

  if (mbi.State != MEM_COMMIT)
    return false;
  if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_READONLY | PAGE_EXECUTE |
                     PAGE_EXECUTE_READ))
    return false;
  return true;
}

bool Process::check_writable(void *addr, size_t size) const {
  auto res = try_check_writable(addr, size);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

std::expected<Process::MemoryProtection, std::string>
Process::try_set_memory_protect(void *addr, size_t size,
                                MemoryProtection protect) const {
  DWORD old_protect;
  if (VirtualProtectEx(this->h, addr, size, ProtectToWin(protect),
                       &old_protect)) {
    return WinToProtect(old_protect);
  }
  return std::unexpected(
      std::format("VirtualProtectEx failed: {}", GetLastError()));
}

Process::MemoryProtection
Process::set_memory_protect(void *addr, size_t size,
                            MemoryProtection protect) const {
  auto res = try_set_memory_protect(addr, size, protect);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

std::expected<bool, std::string> Process::try_check_valid(void *addr) const {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQueryEx(this->h, addr, &mbi, sizeof(mbi)) == 0)
    return std::unexpected(
        std::format("VirtualQueryEx failed: {}", GetLastError()));
  return mbi.State == MEM_COMMIT;
}

bool Process::check_valid(void *addr) const {
  auto res = try_check_valid(addr);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

std::expected<void *, std::string>
Process::try_malloc(size_t size, MemoryProtection protection,
                    void *nearAddr) const {
  if (nearAddr) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

    uint64_t startAddr = (uint64_t(nearAddr) & ~(PAGE_SIZE - 1));
    uint64_t minAddr =
        (uint64_t)std::max((int64_t)startAddr - 0x7FFFFF00,
                           (int64_t)sysInfo.lpMinimumApplicationAddress);
    uint64_t maxAddr =
        (uint64_t)std::min((int64_t)startAddr + 0x7FFFFF00,
                           (int64_t)sysInfo.lpMaximumApplicationAddress);

    uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));
    uint64_t pageOffset = 1;

    while (true) {
      uint64_t byteOffset = pageOffset * PAGE_SIZE;
      uint64_t highAddr = startPage + byteOffset;
      uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

      bool canTryHigh = highAddr < maxAddr;
      bool canTryLow = lowAddr > minAddr;

      if (!canTryHigh && !canTryLow)
        break;

      if (canTryHigh) {
        void *outAddr =
            VirtualAllocEx(this->h, (void *)highAddr, size,
                           MEM_COMMIT | MEM_RESERVE, ProtectToWin(protection));
        if (outAddr)
          return outAddr;
      }

      if (canTryLow) {
        void *outAddr =
            VirtualAllocEx(this->h, (void *)lowAddr, size,
                           MEM_COMMIT | MEM_RESERVE, ProtectToWin(protection));
        if (outAddr)
          return outAddr;
      }

      pageOffset++;
    }
    return std::unexpected("Failed to allocate memory near address");
  } else {
    void *ptr = VirtualAllocEx(this->h, nullptr, size, MEM_COMMIT | MEM_RESERVE,
                               ProtectToWin(protection));
    if (ptr)
      return ptr;
    return std::unexpected(
        std::format("VirtualAllocEx failed: {}", GetLastError()));
  }
}

void *Process::malloc(size_t size, MemoryProtection protection,
                      void *nearAddr) const {
  auto res = try_malloc(size, protection, nearAddr);
  if (!res)
    throw std::runtime_error(res.error());
  return *res;
}

std::expected<void, std::string> Process::try_free(void *addr,
                                                   size_t size) const {
  if (VirtualFreeEx(this->h, addr, 0, MEM_RELEASE))
    return {};
  return std::unexpected(
      std::format("VirtualFreeEx failed: {}", GetLastError()));
}

void Process::free(void *addr, size_t size) const {
  auto res = try_free(addr, size);
  if (!res)
    throw std::runtime_error(res.error());
}

std::optional<std::shared_ptr<Module>>
Process::module(const std::string &name) {
  acquireDebugPrivilege();
  if (is_self()) {
    const auto h = GetProcessBaseAddress(this->h, name);
    if (h)
      return Module::make(const_cast<Process *>(this)->shared_from_this(), h);
    return {};
  } else {
    auto modules = this->modules();
    auto it = modules.find(name);
    if (it != modules.end())
      return it->second;
    return {};
  }
}

Process::Process(std::string name, size_t skip) {

  const auto pid = FindProcessByName(name, skip);
  if (pid.has_value()) {
    *this = Process(pid.value());
  } else {
    throw std::runtime_error("Failed to find specified process.");
  }
}

Process::Process(HANDLE h) : h(h) {
  WIN_ONLY(this->pid = GetProcessId(h));
  this->is_self_cached = this->pid == GetCurrentProcessId();
}

Process::Process(DWORD pid) {
  acquireDebugPrivilege();
  HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
  if (!hproc)
    throw std::runtime_error("Failed to open specified process.");
  this->h = hproc;
  WIN_ONLY(this->pid = GetProcessId(h));
  this->is_self_cached = this->pid == GetCurrentProcessId();
}

std::shared_ptr<Process> Process::self() {
  static std::optional<std::shared_ptr<Process>> _self;
  if (!_self.has_value())
    _self = attach(GetCurrentProcessId());
  return _self.value();
}

bool Process::is_self() const { return is_self_cached; }

Pointer Process::memo() {
  if (!_memo_ptr)
    _memo_ptr = std::make_shared<Pointer>(shared_from_this());
  return *_memo_ptr;
}

std::optional<std::shared_ptr<Module>> Process::module() {
  if (is_self())
    return std::make_shared<Module>(
        const_cast<Process *>(this)->shared_from_this(),
        (HMODULE)misc::get_current_module());

  return {};
}
std::optional<std::shared_ptr<Module>> Process::process_module() {
  if (is_self())
    return std::make_shared<Module>(
        const_cast<Process *>(this)->shared_from_this(),
        GetModuleHandleW(nullptr));

  static auto _module = modules();
  for (const auto &[name, module] : _module) {
    if (name.ends_with(".exe"))
      return module;
  }

  return {};
}

std::map<std::string, std::shared_ptr<Module>> Process::modules() {
  std::map<std::string, std::shared_ptr<Module>> modules;
  HMODULE hMods[1024];
  DWORD cbNeeded;
  if (EnumProcessModules(this->h, hMods, sizeof(hMods), &cbNeeded)) {
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      char szModName[MAX_PATH];
      if (GetModuleFileNameExA(this->h, hMods[i], szModName,
                               sizeof(szModName))) {
        auto name = std::filesystem::path(szModName).filename().string();
        std::transform(name.begin(), name.end(), name.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        modules[name] = Module::make(
            const_cast<Process *>(this)->shared_from_this(), hMods[i]);
      }
    }
  }
  return modules;
}

ProcessAllocator &Process::allocator() {
  if (!_allocator_ptr)
    _allocator_ptr = std::make_shared<ProcessAllocator>(shared_from_this());
  return *_allocator_ptr;
}

std::optional<Pointer> ProcessAllocator::allocate(size_t size, void *nearAddr) {
  constexpr const size_t nearAccepted = /* 2GiB */ 2ll * 1024 * 1024 * 1024;
  for (auto &[addr, data] : allocatedPages) {
    if (!nearAddr ||
        std::abs((int64_t)addr - (int64_t)nearAddr) < nearAccepted) {
      auto &allocated = data.allocated;

      auto it = allocated.begin();
      auto itNext = allocated.begin()++;
      while (it != allocated.end()) {
        if (itNext == allocated.end()) {
          if (size + (char *)it->first + it->second < addr) {
            auto ptr = (char *)it->first + it->second;
            allocated[ptr] = size;
            return ptr;
          }
        } else {
          if (size + (char *)it->first + it->second < itNext->first) {
            auto ptr = (char *)it->first + it->second;
            allocated[ptr] = size;
            return ptr;
          }
        }

        it++;
        itNext++;
      }
    }
  }

  constexpr auto pageSize = 4096;

  auto ptr = proc->malloc(size, Process::MemoryProtection::rw, nearAddr);

  if (!ptr)
    return {};

  auto page = (void *)((size_t)ptr & ~(pageSize - 1));
  auto &data = allocatedPages[page];
  data.size = /* pageSize * n > size */ (size / pageSize) * pageSize + pageSize;
  data.allocated[ptr] = size;

  return Pointer(proc, ptr);
}

ProcessAllocator::ProcessAllocator(std::shared_ptr<Process> proc)
    : proc(std::move(proc)) {}

void ProcessAllocator::deallocate(Pointer addr) {
  for (auto &[page, data] : allocatedPages) {
    auto &allocated = data.allocated;
    auto it = allocated.find(addr.data());
    if (it != allocated.end()) {
      allocated.erase(it);
      if (allocated.empty()) {
        proc->free(page);
      }
      return;
    }
  }
}
std::vector<Thread> Process::threads() {
  std::vector<Thread> threads;
  THREADENTRY32 entry{.dwSize = sizeof(THREADENTRY32)};
  auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (Thread32First(snapshot, &entry)) {
    do {
      if (entry.th32OwnerProcessID == pid)
        threads.emplace_back(entry.th32ThreadID,
                             const_cast<Process *>(this)->shared_from_this());
    } while (Thread32Next(snapshot, &entry));
  }
  return threads;
}
} // namespace blook