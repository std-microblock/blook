#pragma once
#include <memory>
#include <span>
#include <optional>
#include <vector>

namespace blook {
class Process;
class Pointer {
    std::shared_ptr<Process> proc;
    size_t offset;
public:
  static void *malloc_rwx(size_t size);
  static void protect_rwx(void *p, size_t size);
  static void *malloc_near_rwx(void *near, size_t size);

    enum class MemoryProtection {
        Read = 0x0001,
        Write = 0x0010,
        Execute = 0x0100,
        ReadWrite = Read | Write,
        ReadWriteExecute = Read | Write | Execute,
        ReadExecute = Read | Execute,
        rw = ReadWrite,
        rwx = ReadWriteExecute,
        rx = ReadExecute
    };
    void *malloc(size_t size, void* near, MemoryProtection protection = MemoryProtection::rw);
    void *malloc(size_t size, MemoryProtection protection = MemoryProtection::rw);
    std::vector<uint8_t> read(void* ptr, size_t size);
    std::span<uint8_t> read_leaked(void* ptr, size_t size);

    template<typename Struct>
    inline std::optional<Struct> read(void* ptr) {
        const auto val = read_leaked(ptr, sizeof(Struct));
        return reinterpret_cast<Struct>(val.data());
    }
    std::optional<std::vector<uint8_t>> try_read(void* ptr, size_t size);
    explicit Pointer(std::shared_ptr<Process> proc);
};


} // namespace blook