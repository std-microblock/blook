#include "blook/blook.h"

#include <sys/mman.h>
#include <unistd.h>
#include <optional>
#include <link.h>
#include <dlfcn.h>

namespace blook {
ScopedSetMemoryRWX::ScopedSetMemoryRWX(void *ptr, size_t size) {
    this->ptr = ptr;
    this->size = size;
    old_protect = 0;
    mprotect(ptr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
}

ScopedSetMemoryRWX::~ScopedSetMemoryRWX() {
    mprotect(ptr, size, old_protect);
}

void *Pointer::malloc_rwx(size_t size) {
    return mmap(nullptr, size, 
                PROT_READ | PROT_WRITE | PROT_EXEC, 
                MAP_PRIVATE | MAP_ANONYMOUS, 
                -1, 0);
}

void Pointer::protect_rwx(void *p, size_t size) {
    mprotect(p, size, PROT_READ | PROT_WRITE | PROT_EXEC);
}

void *Pointer::malloc_near_rwx(void *targetAddr, size_t size) {
    return Process::self()->memo().malloc(size, targetAddr,
                                          MemoryProtection::rwx);
}

void *Pointer::malloc(size_t size, Pointer::MemoryProtection protection) {
    int prot_flags = 0;
    switch (protection) {
        case MemoryProtection::Read:
            prot_flags = PROT_READ;
            break;
        case MemoryProtection::ReadWrite:
            prot_flags = PROT_READ | PROT_WRITE;
            break;
        case MemoryProtection::ReadWriteExecute:
            prot_flags = PROT_READ | PROT_WRITE | PROT_EXEC;
            break;
        case MemoryProtection::ReadExecute:
            prot_flags = PROT_READ | PROT_EXEC;
            break;
        default:
            prot_flags = PROT_NONE;
    }

    return mmap(nullptr, size, prot_flags, 
                MAP_PRIVATE | MAP_ANONYMOUS, 
                -1, 0);
}

Pointer::Pointer(std::shared_ptr<Process> proc) : proc(std::move(proc)) {}

void *Pointer::malloc(size_t size, void *nearby,
                      Pointer::MemoryProtection protection) {
    long pagesize = sysconf(_SC_PAGESIZE);
    int prot_flags = 0;
    switch (protection) {
        case MemoryProtection::Read:
            prot_flags = PROT_READ;
            break;
        case MemoryProtection::ReadWrite:
            prot_flags = PROT_READ | PROT_WRITE;
            break;
        case MemoryProtection::ReadWriteExecute:
            prot_flags = PROT_READ | PROT_WRITE | PROT_EXEC;
            break;
        case MemoryProtection::ReadExecute:
            prot_flags = PROT_READ | PROT_EXEC;
            break;
        default:
            prot_flags = PROT_NONE;
    }

    // Attempt to allocate memory near the target address
    uintptr_t start = reinterpret_cast<uintptr_t>(nearby);
    uintptr_t min_addr = start - 0x7FFFFF00;
    uintptr_t max_addr = start + 0x7FFFFF00;

    for (uintptr_t addr = start; addr >= min_addr && addr <= max_addr; addr += pagesize) {
        void *result = mmap((void*)addr, size, prot_flags, 
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 
                            -1, 0);
        if (result != MAP_FAILED) {
            return result;
        }
    }

    // Fallback to standard allocation if near allocation fails
    return mmap(nullptr, size, prot_flags, 
                MAP_PRIVATE | MAP_ANONYMOUS, 
                -1, 0);
}

std::optional<Module> Pointer::owner_module() {
    Dl_info info;
    if (dladdr(data(), &info)) {
        return Module{proc, info.dli_fbase};
    }
    return {};
}
} // namespace blook
