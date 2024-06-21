//
// Created by MicroBlock on 2024/6/21.
//

#include "Process.h"
#include "windows.h"
#include <TlHelp32.h>
#include "psapi.h"

#ifdef _WIN32
static std::optional<uint64_t> FindProcessByName(const std::string& name) {
    PROCESSENTRY32 entry{
            .dwSize = sizeof(PROCESSENTRY32)
    };

    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Process32First(snapshot, &entry)) {
        do {
            if(std::string(entry.szExeFile) == name) {
                return entry.th32ProcessID;
            }
        } while(Process32Next(snapshot, &entry));

    }
}

static DWORD_PTR GetProcessBaseAddress(HANDLE processHandle, const std::string& modulename)
{
    DWORD_PTR   baseAddress = 0;
    HMODULE     *moduleArray;
    LPBYTE      moduleArrayBytes;
    DWORD       bytesRequired;

    const auto a = GetProcessId(processHandle);
    if ( processHandle )
    {
        if ( EnumProcessModules( processHandle, NULL, 0, &bytesRequired ) )
        {
            if ( bytesRequired )
            {
                moduleArrayBytes = (LPBYTE)LocalAlloc( LPTR, bytesRequired );

                if ( moduleArrayBytes )
                {
                    unsigned int moduleCount;

                    moduleCount = bytesRequired / sizeof( HMODULE );
                    moduleArray = (HMODULE *)moduleArrayBytes;

                    if ( EnumProcessModules( processHandle, moduleArray, bytesRequired, &bytesRequired ) )
                    {
                        for (int i=0; i<moduleCount; i++ ) {
                            const auto module = moduleArray[i];
                            char name[MAX_PATH];
                            if(GetModuleFileNameA(module, name, MAX_PATH)) {
                                const auto filename = std::filesystem::path(name).filename();
                                std::cout<<filename<<" "<<i<<std::endl;
                                if (name == filename) {
                                    baseAddress = (DWORD_PTR)module;
                                    break;
                                }
                            }
                        }
                    }



                    LocalFree( moduleArrayBytes );
                }
            }
        }

        CloseHandle( processHandle );
    }

    return baseAddress;
}

static bool acquireDebugPrivilege() {
    static bool permissionAcquired = false;
    if(!permissionAcquired) {
        TOKEN_PRIVILEGES NewState;
        NewState.PrivilegeCount = 1;
        if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &NewState.Privileges[0].Luid))
            return false;

        HANDLE token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
            return false;

        NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(token, FALSE, &NewState, sizeof(NewState), nullptr, nullptr))
            return false;

        permissionAcquired = true;
    }

    return true;
}

#endif

namespace blook {
    std::optional<std::vector<std::uint8_t>> Process::read(void *addr, size_t size) const {
        std::vector<std::uint8_t> data;
        data.resize(size);

        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);

        if(ReadProcessMemory(this->h, (void*)(addr), data.data(), size, nullptr))
            return data;
        return {};
    }

    std::optional<Module> Process::module(const std::string &name) const {
        acquireDebugPrivilege();
        const auto h = GetProcessBaseAddress(this->h, name);
        if(h) return {};// (void*)h;
        return {};
    }

    Process::Process(std::string name) {
        const auto pid = FindProcessByName(name);
        if(pid.has_value()) {
            Process(pid.value());
        } else {
            throw std::runtime_error("Failed to find specified process.");
        }
    }

    Process::Process(HANDLE h) : h(h) {
        this->pid = GetProcessId(h);
    }

    Process::Process(DWORD pid) {
        acquireDebugPrivilege();
        HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if(!hproc) throw std::runtime_error("Failed to open specified process.");
        this->h = hproc;
        this->pid = GetProcessId(h);
    }

    Process Process::self() {
        return Process(getpid());
    }
} // blook