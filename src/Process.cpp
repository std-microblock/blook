#include <thread>

#include "blook/Module.h"
#include "blook/Process.h"
#include "blook/misc.h"

#include "psapi.h"
#include "windows.h"
#include <TlHelp32.h>

#include <expected>
#include <ranges>
#include <utility>

#ifdef _WIN32

static std::optional<uint64_t> FindProcessByName(const std::string &name) {
    PROCESSENTRY32 entry{.dwSize = sizeof(PROCESSENTRY32)};

    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry)) {
        do {
            if (std::string(entry.szExeFile) == name) {
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
                moduleArrayBytes = (LPBYTE) LocalAlloc(LPTR, bytesRequired);

                if (moduleArrayBytes) {
                    unsigned int moduleCount;

                    moduleCount = bytesRequired / sizeof(HMODULE);
                    moduleArray = (HMODULE *) moduleArrayBytes;

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
    std::optional<std::vector<std::uint8_t>> Process::read(void *addr,
                                                           size_t size) const {
        std::vector<std::uint8_t> data;
        data.resize(size);
        if (read(data.data(), addr, size))
            return data;
        return {};
    }

    std::optional<std::shared_ptr<Module>>
    Process::module(const std::string &name) {
        acquireDebugPrivilege();
        const auto h = GetProcessBaseAddress(this->h, name);
        if (h)
            return Module::make(shared_from_this(), h);
        return {};
    }

    Process::Process(std::string name) {

        const auto pid = FindProcessByName(name);
        if (pid.has_value()) {
            *this = Process(pid.value());
        } else {
            throw std::runtime_error("Failed to find specified process.");
        }
    }

    Process::Process(HANDLE h) : h(h) { this->pid = GetProcessId(h); }

    Process::Process(DWORD pid) {
        acquireDebugPrivilege();
        HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (!hproc)
            throw std::runtime_error("Failed to open specified process.");
        this->h = hproc;
        this->pid = GetProcessId(h);
    }

    std::shared_ptr<Process> Process::self() {
        static std::optional<std::shared_ptr<Process>> _self;
        if (!_self.has_value())
            _self = attach(GetCurrentProcessId());
        return _self.value();
    }

    bool Process::is_self() const { return GetCurrentProcessId() == pid; }

    Pointer Process::memo() {
        if (!_memo)
            _memo = Pointer(shared_from_this());
        return _memo.value();
    }

    void *Process::read(void *dest, void *addr, size_t size) const {
        if (ReadProcessMemory(this->h, (void *) (addr), dest, size, nullptr))
            return dest;
        return nullptr;
    }

    std::optional<std::shared_ptr<Module>> Process::module() {
        if (is_self())
            return std::make_shared<Module>(shared_from_this(),
                                            (HMODULE) misc::get_current_module());

        return {};
    }

    std::optional<std::shared_ptr<Module>> Process::process_module() {
        if (is_self())
            return std::make_shared<Module>(shared_from_this(),
                                            GetModuleHandleW(nullptr));

        static auto _module = modules();
        for (const auto &[name, module]: _module) {
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
                    modules[name] = Module::make(shared_from_this(), hMods[i]);
                }
            }
        }
        return modules;
    }


    std::expected<void, std::string> Process::write(void *addr,
                                                    std::span<uint8_t> data) const {
        SIZE_T written;
        DWORD old_protect;
        if (!VirtualProtectEx(this->h, addr, data.size(), PAGE_EXECUTE_READWRITE,
                              &old_protect))
            return std::unexpected(
                    std::format("Failed to change memory protection: {}", GetLastError()));

        WriteProcessMemory(this->h, addr, data.data(), data.size(), &written);

        if (!VirtualProtectEx(this->h, addr, data.size(), old_protect, &old_protect))
            return std::unexpected(
                    std::format("Failed to restore memory protection: {}", GetLastError()));

        if (written != data.size())
            return std::unexpected(
                    std::format("Failed to write memory: {}", GetLastError()));
        return {};
    }

    Process::Allocator Process::allocator() {
        if (!_allocator)
            _allocator = Allocator(shared_from_this());
        return _allocator.value();
    }

    std::optional<Pointer> Process::Allocator::allocate(size_t size,
                                                        void *nearAddr) {
        constexpr const size_t nearAccepted = /* 2GiB */ 2ll * 1024 * 1024 * 1024;
        for (auto &[addr, data]: allocatedPages) {
            if (!nearAddr || std::abs((char *) addr - (char *) nearAddr) < nearAccepted) {
                auto &allocated = data.allocated;

                auto it = allocated.begin();
                auto itNext = allocated.begin()++;
                while (it != allocated.end()) {
                    if (itNext == allocated.end()) {
                        if (size + (char *) it->first + it->second < addr) {
                            auto ptr = (char *) it->first + it->second;
                            allocated[ptr] = size;
                            return ptr;
                        }
                    } else {
                        if (size + (char *) it->first + it->second < itNext->first) {
                            auto ptr = (char *) it->first + it->second;
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

        auto ptr = proc->memo().malloc(size, nearAddr);

        if (!ptr)
            return {};

        auto page = (void *) ((size_t) ptr & ~(pageSize - 1));
        auto &data = allocatedPages[page];
        data.size = /* pageSize * n > size */ (size / pageSize) * pageSize + pageSize;
        data.allocated[ptr] = size;

        return proc->memo().add(ptr);
    }

    Process::Allocator::Allocator(std::shared_ptr<Process> proc)
            : proc(std::move(proc)) {}

    void Process::Allocator::deallocate(Pointer addr) {
        for (auto &[page, data]: allocatedPages) {
            auto &allocated = data.allocated;
            auto it = allocated.find(addr.data());
            if (it != allocated.end()) {
                allocated.erase(it);
                if (allocated.empty())
                    //            proc->memo().free(page);
                    return;
            }
        }
    }
} // namespace blook