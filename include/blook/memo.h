#pragma once

#include "concepts.h"
#include "memory_scanner/mb_kmp.h"
#include "zasm/zasm.hpp"
#include <deque>
#include <expected>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace blook {
    class Process;

    class Function;

    class MemoryRange;

    class MemoryPatch;

    class Module;
    namespace disasm {
        template<typename Range>
        class DisassembleRange;

        using DisassembleIterator = DisassembleRange<std::span<uint8_t>>;
    } // namespace disasm

    class Pointer {

    protected:
        size_t _offset = 0;
        std::shared_ptr<Process> proc = nullptr;
        friend MemoryPatch;

    public:
        static void *malloc_rwx(size_t size);

        static void protect_rwx(void *p, size_t size);

        static void *malloc_near_rwx(void *near, size_t size);

        bool operator==(const Pointer &other) const = default;

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

        void *malloc(size_t size, void *near,
                     MemoryProtection protection = MemoryProtection::rw);

        void *malloc(size_t size, MemoryProtection protection = MemoryProtection::rw);

        std::vector<uint8_t> read(void *ptr, size_t size) const;

        std::span<uint8_t> read_leaked(void *ptr, size_t size);


        std::expected<void, std::string> write(void *addr, std::span<uint8_t>) const;

        template<typename Struct>
        inline std::optional<Struct *> read_leaked(void *ptr = nullptr) {
            const auto val = read_leaked(ptr, sizeof(Struct));
            return reinterpret_cast<Struct *>(val.data());
        }

        template<typename Struct>
        [[nodiscard]] inline Struct read(size_t ptr = 0) const {
            auto data = try_read((void *) ptr, sizeof(Struct));
            if (!data.has_value()) {
                throw std::runtime_error("Failed to read memory");
            }
            return *reinterpret_cast<Struct *>(data.value().data());
        }

        template<typename Struct>
        [[nodiscard]] inline auto write(Struct data, size_t ptr = 0) {
            return write((void *) ptr, std::span((uint8_t *) &data, sizeof(Struct)));
        }

        template<typename Struct>
        [[nodiscard]] inline std::optional<Struct> try_read(size_t ptr = 0) const {
            auto data = try_read((void *) ptr, sizeof(Struct));
            if (!data.has_value()) {
                return {};
            }
            return *reinterpret_cast<Struct *>(data.value().data());
        }

        std::optional<std::vector<uint8_t>> try_read(void *ptr, size_t size) const;

        explicit Pointer(std::shared_ptr<Process> proc);

        Pointer(std::shared_ptr<Process> proc, void *offset);

        Pointer(std::shared_ptr<Process> proc, size_t offset);

        // Construct a pointer within current process.
        Pointer(void *offset);

        Pointer() = default;

        operator size_t() const { return (size_t) this->_offset; }

        Function as_function();

        [[nodiscard]] void *data() const;

        [[nodiscard]] inline size_t offset() const {
            return _offset;
        }

        // Pointer operations
        inline Pointer add(const auto &t) const {
            return {proc, (void *) (_offset + (size_t) t)};
        }

        inline Pointer sub(const auto &t) const {
            return {proc, (void *) (_offset - (size_t) t)};
        }

        inline auto operator+(const auto &t) { return this->add(t); }

        inline auto operator-(const auto &t) { return this->sub(t); }

        inline auto operator+=(const auto &t) { this->_offset += (size_t) t; };

        inline auto operator-=(const auto &t) { this->_offset -= (size_t) t; };

        inline auto operator<=>(const Pointer &o) const {
            return this->_offset <=> o._offset;
        }

        [[nodiscard]] MemoryPatch
        reassembly(std::function<void(zasm::x86::Assembler)>);

        std::optional<Function> guess_function(size_t max_scan_size = 50000);

        std::optional<Pointer> find_upwards(std::initializer_list<uint8_t> pattern,
                                            size_t max_scan_size = 50000);

        std::optional<Module> owner_module();

        // ptr.offsets(0x1f, 0x3f) equals to (*(ptr + 0x1f) + 0x3f)
        std::optional<Pointer> offsets(const std::vector<size_t> &offsets,
                                       size_t scale = sizeof(void *));

        MemoryRange range_to(Pointer ptr);

        MemoryRange range_size(std::size_t size);
    };

    struct ScopedSetMemoryRWX {
        void *ptr;
        size_t size;
        void *old_protect;

        ScopedSetMemoryRWX(void *ptr, size_t size);

        ~ScopedSetMemoryRWX();
    };

    class MemoryPatch {
        Pointer ptr;
        std::vector<uint8_t> buffer;
        bool patched = false;

    public:
        MemoryPatch(Pointer ptr, std::vector<uint8_t> buffer);

        void swap();

        bool patch();

        bool restore();
    };

    class MemoryRange : public Pointer {
        size_t _size = 0;

    public:
        MemoryRange(std::shared_ptr<Process> proc, void *offset, size_t size);

        MemoryRange() = default;

        MemoryRange(const MemoryRange &other) = default;

        MemoryRange &operator=(const MemoryRange &other) = default;

        [[nodiscard]] size_t size() const { return _size; }

        template<size_t bufSize, size_t step = 1>
        struct MemoryIteratorBuffered {
            Pointer ptr = nullptr;
            size_t size = 1;

            struct CacheBuffer {
                std::vector<uint8_t> buffer{};
                size_t offset = 0;
            };

            std::shared_ptr<CacheBuffer> cache = std::make_shared<CacheBuffer>();

            MemoryIteratorBuffered() = default;

            MemoryIteratorBuffered(const MemoryIteratorBuffered &) = default;

            MemoryIteratorBuffered(MemoryIteratorBuffered &&) = default;

            MemoryIteratorBuffered &operator=(const MemoryIteratorBuffered &) = default;

            MemoryIteratorBuffered &operator=(MemoryIteratorBuffered &&) = default;

            MemoryIteratorBuffered(Pointer ptr, size_t size) : ptr(ptr), size(size) {}

            inline MemoryIteratorBuffered &operator+=(size_t t) {
                if (t * step > size) {
                    this->ptr = ptr + size;
                    size = 0;
                } else {
                    ptr += t * step;
                    size -= t * step;
                }

                return *this;
            }

            inline MemoryIteratorBuffered operator+(size_t t) {
                return {ptr + t * step, std::max(size - t * step, (size_t) 0)};
            }

            inline MemoryIteratorBuffered &operator++() {
                ptr += step;
                size -= step;
                return *this;
            }

            inline MemoryIteratorBuffered operator++(int) {
                auto tmp = *this;
                ++(*this);
                return tmp;
            }

            inline bool operator==(const MemoryIteratorBuffered &other) const {
                return ptr == other.ptr || (size == 0 && other.size == 0);
            }

            inline bool operator!=(const MemoryIteratorBuffered &other) const {
                return !(*this == other);
            }

            inline uint8_t operator*() {
                if (cache->buffer.empty() || /* !(cache->offset ∈ [ptr, ptr+cache->size]) */
                    cache->offset > ptr.offset() ||
                    cache->offset + cache->buffer.size() <= ptr.offset()) {
                    cache->buffer = std::move(ptr.read(0, bufSize));
                    cache->offset = ptr.offset();
                }

                return cache->buffer[ptr.offset() - cache->offset];
            }

            using value_type = uint8_t;
            using difference_type = std::ptrdiff_t;
            using pointer = uint8_t *;
            using reference = uint8_t &;
            using iterator_category = std::input_iterator_tag;
        };

        using MemoryIterator = MemoryIteratorBuffered<1024 * 1024>;

        using iterator = MemoryIterator;
        using const_iterator = MemoryIterator;

        bool operator==(const MemoryRange &other) const = default;

        [[nodiscard]] MemoryIterator begin() const {
            return {*static_cast<const Pointer *>(this), _size};
        }

        [[nodiscard]] MemoryIterator end() const {
            return {(*static_cast<const Pointer *>(this)).add(_size), 0};
        }

        template<class Scanner = memory_scanner::mb_kmp>
        inline std::optional<Pointer>
        find_one(const std::vector<uint8_t> pattern) const {
            const auto span = std::span<uint8_t>((uint8_t *) _offset, _size);
            std::optional<size_t> res = Scanner::searchOne(span, pattern);
            return res.and_then([this](const auto val) {
                return std::optional<Pointer>(Pointer(this->proc, this->_offset + val));
            });
        }

        template<class Scanner = memory_scanner::mb_kmp>
        inline std::optional<Pointer>
        find_one(std::initializer_list<uint8_t> pattern) const {
            return find_one<Scanner>(
                    std::vector<uint8_t>(std::forward<decltype(pattern)>(pattern)));
        }

        template<class Scanner = memory_scanner::mb_kmp>
        inline std::optional<Pointer> find_one(
                std::initializer_list<std::initializer_list<uint8_t>> pattern) const {
            for (const auto &pat: pattern) {
                const auto res = find_one<Scanner>(
                        std::vector<uint8_t>(std::forward<decltype(pat)>(pat)));
                if (res.has_value())
                    return res;
            }

            return {};
        }

        template<class Scanner = memory_scanner::mb_kmp, typename I>
        inline std::optional<Pointer>
        find_one(const std::pair<I, size_t> &pattern) const {
            const auto res = find_one<Scanner>(pattern.first);
            return res.and_then(
                    [&](const auto val) { return std::optional(val + pattern.second); });
        }

        inline auto find_one(std::string_view sv) const {
            return find_one(std::vector<uint8_t>(sv.begin(), sv.end()));
        }

        std::optional<Pointer> find_xref(Pointer p);

        MemoryRange(Pointer pointer, size_t size);

        int32_t crc32() const;

        [[nodiscard]] disasm::DisassembleRange<MemoryRange> disassembly() const;
    };

    static_assert(std::sentinel_for<decltype(std::declval<MemoryRange>().begin()),
            decltype(std::declval<MemoryRange>().end())>);
    static_assert(std::ranges::range<MemoryRange>);

    static_assert(std::is_constructible_v<MemoryRange>);
} // namespace blook