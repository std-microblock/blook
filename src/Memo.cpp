//
// Created by MicroBlock on 2024/6/22.
//

#include "blook/Memo.h"
#include "blook/Function.h"

#include "blook/Disassembly.h"

#define NOMINMAX

#include "Windows.h"
#include "blook/Process.h"
#include "zasm/formatter/formatter.hpp"
#include <cstdint>
#include <algorithm>
#include <utility>

#include <iostream>

namespace blook {
    void *Pointer::malloc_rwx(size_t size) {
        return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
    }

    void Pointer::protect_rwx(void *p, size_t size) {
        DWORD flOldProtect = 0;
        VirtualProtect(p, size, PAGE_EXECUTE_READWRITE, &flOldProtect);
    }

    void *Pointer::malloc_near_rwx(void *targetAddr, size_t size) {
        return Process::self()->memo().malloc(size, targetAddr,
                                              MemoryProtection::rwx);
    }

    void *Pointer::malloc(size_t size, Pointer::MemoryProtection protection) {
        LPVOID lpSpace = (LPVOID) VirtualAllocEx(
                proc->h, NULL, size, MEM_RESERVE | MEM_COMMIT,
                ((protection == MemoryProtection::Read) ? PAGE_READONLY
                                                        : (protection == MemoryProtection::ReadWrite) ? PAGE_READWRITE
                                                                                                      : (protection ==
                                                                                                         MemoryProtection::ReadWriteExecute)
                                                                                                        ? PAGE_EXECUTE_READWRITE
                                                                                                        : (protection ==
                                                                                                           MemoryProtection::ReadExecute)
                                                                                                          ? PAGE_EXECUTE_READ
                                                                                                          : PAGE_NOACCESS));
        return lpSpace;
    }

    Pointer::Pointer(std::shared_ptr<Process> proc) : proc(std::move(proc)) {}

    void *Pointer::malloc(size_t size, void *nearby,
                          Pointer::MemoryProtection protection) {
        const auto flag =
                ((protection == MemoryProtection::Read) ? PAGE_READONLY
                                                        : (protection == MemoryProtection::ReadWrite) ? PAGE_READWRITE
                                                                                                      : (protection ==
                                                                                                         MemoryProtection::ReadWriteExecute)
                                                                                                        ? PAGE_EXECUTE_READWRITE
                                                                                                        : (protection ==
                                                                                                           MemoryProtection::ReadExecute)
                                                                                                          ? PAGE_EXECUTE_READ
                                                                                                          : PAGE_NOACCESS);
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

        uint64_t startAddr =
                (uint64_t(nearby) &
                 ~(PAGE_SIZE - 1)); // round down to nearest page boundary
        uint64_t minAddr = std::min(startAddr - 0x7FFFFF00,
                                    (uint64_t) sysInfo.lpMinimumApplicationAddress);
        uint64_t maxAddr = std::max(startAddr + 0x7FFFFF00,
                                    (uint64_t) sysInfo.lpMaximumApplicationAddress);

        uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

        uint64_t pageOffset = 1;
        while (true) {
            uint64_t byteOffset = pageOffset * PAGE_SIZE;
            uint64_t highAddr = startPage + byteOffset;
            uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

            bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

            if (highAddr < maxAddr) {
                void *outAddr =
                        VirtualAlloc((void *) highAddr, size, MEM_COMMIT | MEM_RESERVE, flag);
                if (outAddr)
                    return outAddr;
            }

            if (lowAddr > minAddr) {
                void *outAddr =
                        VirtualAlloc((void *) lowAddr, size, MEM_COMMIT | MEM_RESERVE, flag);
                if (outAddr != nullptr)
                    return outAddr;
            }

            pageOffset++;

            if (needsExit) {
                break;
            }
        }

        return nullptr;
    }

    std::vector<uint8_t> Pointer::read(void *ptr, size_t size) const {
        return try_read(ptr, size).value();
    }

    std::optional<std::vector<uint8_t>> Pointer::try_read(void *ptr,
                                                          size_t size) const {
        //        if (proc->is_self()) {
        //            std::span<uint8_t> a{(uint8_t *) ((size_t) proc->h + offset),
        //            size}; return std::vector<uint8_t>{a.begin(), a.end()};
        //        }
        const auto x = proc->read((void *) ((size_t) ptr + _offset), size);
        return x;
    }

    std::span<uint8_t> Pointer::read_leaked(void *ptr, size_t size) {
        void *mem = malloc(size);
        proc->read(mem, (uint8_t *) (_offset + (size_t) ptr), size);
        return {(uint8_t *) mem, size};
    }

    Pointer::Pointer(std::shared_ptr<Process> proc, void *offset)
            : _offset((size_t) offset), proc(std::move(proc)) {}

    Function Pointer::as_function() { return {proc, (void *) _offset}; }

    Pointer::Pointer(std::shared_ptr<Process> proc, size_t offset)
            : _offset(offset), proc(std::move(proc)) {}

    MemoryPatch
    Pointer::reassembly(std::function<void(zasm::x86::Assembler)> func) {
        using namespace zasm;
        Program program(MachineMode::AMD64);
        x86::Assembler b(program);
        func(b);

        const auto code_size = utils::estimateCodeSize(program);
        std::vector<uint8_t> data(code_size);

        Serializer serializer;
        if (auto err = serializer.serialize(program, this->_offset);
                err != zasm::ErrorCode::None)
            throw std::runtime_error(std::format("JIT Serialization failure: {} {}",
                                                 err.getErrorName(),
                                                 err.getErrorMessage()));
        std::memcpy(data.data(), serializer.getCode(), code_size);
        return {*this, data};
    }

    MemoryPatch::MemoryPatch(Pointer ptr, std::vector<uint8_t> buffer)
            : ptr(std::move(ptr)), buffer(std::move(buffer)) {}

    void MemoryPatch::swap() {
        const auto target = reinterpret_cast<void *>(ptr._offset);
        Pointer::protect_rwx(target, buffer.size());
        std::vector<uint8_t> tmp(buffer.size());
        std::memcpy(tmp.data(), buffer.data(), buffer.size());
        std::memcpy(buffer.data(), target, buffer.size());
        std::memcpy(target, tmp.data(), tmp.size());
        patched = !patched;
    }

    bool MemoryPatch::patch() {
        if (!patched)
            swap();
        else
            throw std::runtime_error("MemoryPatch already applied!");

        return true;
    }

    bool MemoryPatch::restore() {
        if (patched)
            swap();
        else
            throw std::runtime_error("MemoryPatch is not patched!");

        return true;
    }

    void *Pointer::data() const { return (void *) _offset; }

    std::optional<Function> Pointer::guess_function(size_t max_scan_size) {
        for (auto p = (size_t) _offset; p > (size_t) _offset - max_scan_size; p -= 1) {
            const auto v = (*(uint8_t *) p);
            const auto v1 = (*((uint8_t *) p - 1));
            const auto v2 = (*((uint8_t *) p - 2));
            const auto v3 = (*((uint8_t *) p - 3));
            if (v == 0xCC || v == 0xC3) {
                return blook::Function{proc, (void *) (p + 1)};
            }
            if (v1 == 0 && v2 == 0 && v3 == 0 && v == 0)
                return blook::Function{proc, (void *) (p + 1)};
        }

        return {};
    }

    std::optional<Module> Pointer::owner_module() {
        MEMORY_BASIC_INFORMATION inf;
        VirtualQuery(data(), &inf, 0x8);

        if (inf.AllocationBase)
            return Module{proc, (HMODULE) inf.AllocationBase};
        return {};
    }

    std::optional<Pointer> Pointer::offsets(const std::vector<size_t> &offsets,
                                            size_t scale) {
        Pointer ptr = *this;
        for (const auto &offset_next:
                std::span(offsets.begin(), offsets.end() - 1)) {
            ptr += offset_next * scale;
            const auto data = ptr.read_leaked<size_t>();
            if (!data)
                return {};
            ptr = (void *) *data.value();
        }

        return ptr.add(offsets.back() * scale);
    }

    Pointer::Pointer(void *offset) : Pointer(blook::Process::self(), offset) {}

    std::optional<Pointer>
    Pointer::find_upwards(std::initializer_list<uint8_t> pattern,
                          size_t max_scan_size) {
        Pointer p = *this;
        for (; p > this - max_scan_size; p -= 1) {
            if (memcmp(pattern.begin(), (unsigned char *) p.data(), pattern.size()) ==
                0) {
                return p;
            }
        }

        return {};
    }

    MemoryRange Pointer::range_to(Pointer ptr) {
        if (ptr <= (*this))
            return MemoryRange{*this, 0};
        return MemoryRange{*this, (size_t) (ptr - this)};
    }

    MemoryRange Pointer::range_size(std::size_t size) {
        return MemoryRange{*this, size};
    }

    std::expected<void, std::string> Pointer::write(void *addr,
                                                    std::span<uint8_t> data) const {
        return proc->write((void *) ((size_t) addr + _offset), data);
    }

    MemoryRange::MemoryRange(std::shared_ptr<Process> proc, void *offset,
                             size_t size)
            : Pointer(std::move(proc), offset), _size(size) {}

    std::optional<Pointer> MemoryRange::find_xref(Pointer p) {
        auto disasm = this->disassembly();
        auto res = std::ranges::find_if(disasm, [=](const auto &c) {
            auto xrefs = c.xrefs();
            return std::ranges::contains(xrefs, p);
        });

        if (res == disasm.end())
            return {};
        return (*res).ptr();
    }

    MemoryRange::MemoryRange(Pointer pointer, size_t size)
            : Pointer(pointer), _size(size) {}

    disasm::DisassembleRange<MemoryRange> MemoryRange::disassembly() const {
        //  if (proc->is_self())
        //    return disasm::DisassembleIterator{
        //        std::span<uint8_t>((uint8_t *)offset, _size),
        //        *static_cast<const Pointer *>(this)};
        MemoryRange range = *this;
        return disasm::DisassembleRange<MemoryRange>{
                range, *static_cast<const Pointer *>(this)};
    };

    consteval std::array<uint32_t, 256> make_crc32_table() {
        std::array<uint32_t, 256> table;
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (uint32_t j = 0; j < 8; j++) {
                crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
            }
            table[i] = crc;
        }
        return table;
    }

    constinit std::array<uint32_t, 256> crc32_table = make_crc32_table();

    int32_t MemoryRange::crc32() const {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < _size; i++) {
            crc = crc32_table[(crc ^ *((uint8_t *) _offset)) & 0xFF] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFF;
    }

} // namespace blook