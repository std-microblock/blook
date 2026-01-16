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
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

#include "process.h"

namespace blook {
class Process;

class Function;

class MemoryRange;

class MemoryPatch;
struct Thread;
class Module;
namespace disasm {
template <typename Range> class DisassembleRange;

using DisassembleIterator = DisassembleRange<std::span<uint8_t>>;
} // namespace disasm

class Pointer {

protected:
  size_t _offset = 0;
  friend MemoryPatch;

public:
  using MemoryProtection = Process::MemoryProtection;

  std::shared_ptr<Process> proc = nullptr;
  bool is_self() const;
  bool is_valid() const;

  bool operator==(const Pointer &other) const = default;

  Pointer malloc(size_t size, void *near,
                 MemoryProtection protection = MemoryProtection::rw);

  Pointer malloc(size_t size,
                 MemoryProtection protection = MemoryProtection::rw);

  Pointer malloc_rx_near_this(size_t size);

  void free(size_t size = 0);

  std::optional<Thread> create_thread(bool suspended = false);

  // Read operations
  /**
   * @brief Try to read a byte array from the pointer.
   * This function will check if the memory is readable before reading in try
   * mode.
   */
  std::expected<std::vector<uint8_t>, std::string>
  try_read_bytearray(size_t size) const;

  std::expected<Pointer, std::string> try_read_pointer() const;

  template <typename T>
    requires std::is_standard_layout_v<T> && std::is_trivial_v<T>
  std::expected<T, std::string> try_read_struct() const {
    T val;
    auto res = try_read_into(&val, sizeof(T));
    if (!res)
      return std::unexpected(res.error());
    return val;
  }

  std::expected<std::string, std::string>
  try_read_utf8_string(size_t length = -1) const;

  std::expected<std::wstring, std::string>
  try_read_utf16_string(size_t length = -1) const;

  // Write operations
  std::expected<void, std::string>
  try_write_bytearray(std::span<const uint8_t> data) const;

  inline std::expected<void, std::string>
  try_write_bytearray(const std::vector<uint8_t> &data) const {
    return try_write_bytearray(std::span(data));
  }

  inline std::expected<void, std::string>
  try_write_bytearray(std::string_view data) const {
    return try_write_bytearray(
        std::span<const uint8_t>((const uint8_t *)data.data(), data.size()));
  }

  inline std::expected<void, std::string>
  try_write_bytearray(std::wstring_view data) const {
    return try_write_bytearray(std::span<const uint8_t>(
        (const uint8_t *)data.data(), data.size() * sizeof(wchar_t)));
  }

  std::expected<void, std::string> try_write_pointer(Pointer ptr) const;

  template <typename T>
    requires std::is_standard_layout_v<T> && std::is_trivial_v<T>
  std::expected<void, std::string> try_write_struct(const T &value) const {
    return try_write_bytearray(
        std::span<const uint8_t>((const uint8_t *)&value, sizeof(T)));
  }

  // Raw read into buffer, avoids extra vector allocation
  std::expected<void, std::string> try_read_into(void *dest, size_t size) const;
  void read_into(void *dest, size_t size) const;

  // Throwing wrappers
  /**
   * @brief Read a byte array from the pointer.
   * Note: This function does NOT perform extra safety checks like
   * try_read_bytearray. It is intended for high-performance use when memory is
   * known to be valid.
   */
  std::vector<uint8_t> read_bytearray(size_t size) const;
  Pointer read_pointer() const;

  template <typename T>
    requires std::is_standard_layout_v<T> && std::is_trivial_v<T>
  T read_struct() const {
    T val;
    read_into(&val, sizeof(T));
    return val;
  }

  std::string read_utf8_string(size_t length = -1) const;
  std::wstring read_utf16_string(size_t length = -1) const;

  std::expected<void, std::string>
  try_write_utf8_string(std::string_view str) const;
  std::expected<void, std::string>
  try_write_utf16_string(std::wstring_view str) const;

  void write_utf8_string(std::string_view str) const;
  void write_utf16_string(std::wstring_view str) const;

  void write_bytearray(std::span<const uint8_t> data) const;

  inline void write_bytearray(const std::vector<uint8_t> &data) const {
    write_bytearray(std::span(data));
  }

  inline void write_bytearray(std::string_view data) const {
    write_bytearray(
        std::span<const uint8_t>((const uint8_t *)data.data(), data.size()));
  }

  inline void write_bytearray(std::wstring_view data) const {
    write_bytearray(std::span<const uint8_t>((const uint8_t *)data.data(),
                                             data.size() * sizeof(wchar_t)));
  }

  void write_pointer(Pointer ptr) const;

  template <typename T> void write_struct(const T &value) const {
    auto res = try_write_struct<T>(value);
    if (!res)
      throw std::runtime_error(res.error());
  }

#define BLOOK_READ_WRITE_HELPER(type, name)                                    \
  inline std::expected<type, std::string> try_read_##name() const {            \
    type val;                                                                  \
    auto res = try_read_into(&val, sizeof(type));                              \
    if (!res)                                                                  \
      return std::unexpected(res.error());                                     \
    return val;                                                                \
  }                                                                            \
  inline type read_##name() const {                                            \
    type val;                                                                  \
    read_into(&val, sizeof(type));                                             \
    return val;                                                                \
  }                                                                            \
  inline std::expected<void, std::string> try_write_##name(type val) const {   \
    return try_write_struct<type>(val);                                        \
  }                                                                            \
  inline void write_##name(type val) const { write_struct<type>(val); }

  BLOOK_READ_WRITE_HELPER(int8_t, s8)
  BLOOK_READ_WRITE_HELPER(int16_t, s16)
  BLOOK_READ_WRITE_HELPER(int32_t, s32)
  BLOOK_READ_WRITE_HELPER(int64_t, s64)
  BLOOK_READ_WRITE_HELPER(uint8_t, u8)
  BLOOK_READ_WRITE_HELPER(uint16_t, u16)
  BLOOK_READ_WRITE_HELPER(uint32_t, u32)
  BLOOK_READ_WRITE_HELPER(uint64_t, u64)
  BLOOK_READ_WRITE_HELPER(short, short)
  BLOOK_READ_WRITE_HELPER(unsigned short, ushort)
  BLOOK_READ_WRITE_HELPER(int, int)
  BLOOK_READ_WRITE_HELPER(unsigned int, uint)
  BLOOK_READ_WRITE_HELPER(float, float)
  BLOOK_READ_WRITE_HELPER(double, double)
#undef BLOOK_READ_WRITE_HELPER

  template <typename T> T read_volatile() const {
    // For now, same as read_struct.
    return read_struct<T>();
  }

  explicit Pointer(std::shared_ptr<Process> proc);

  Pointer(std::shared_ptr<Process> proc, void *offset);

  Pointer(std::shared_ptr<Process> proc, size_t offset);

  // Construct a pointer within current process.
  Pointer(void *offset);

  Pointer() = default;

  operator size_t() const { return (size_t)this->_offset; }

  inline Pointer absolute(const auto &t) const { return {proc, (void *)t}; }

  Function as_function();

  [[nodiscard]] void *data() const;

  [[nodiscard]] inline size_t offset() const { return _offset; }

  // Pointer operations
  inline Pointer add(const auto &t) const {
    return {proc, (void *)(_offset + (size_t)t)};
  }

  inline Pointer sub(const auto &t) const {
    return {proc, (void *)(_offset - (size_t)t)};
  }

  inline auto operator+(const auto &t) { return this->add(t); }

  inline auto operator-(const auto &t) { return this->sub(t); }

  inline auto operator+=(const auto &t) { this->_offset += (size_t)t; };

  inline auto operator-=(const auto &t) { this->_offset -= (size_t)t; };

  inline auto operator<=>(const Pointer &o) const {
    return this->_offset <=> o._offset;
  }

  [[nodiscard]] MemoryPatch
      reassembly(std::function<void(zasm::x86::Assembler)>);

  [[nodiscard]] MemoryPatch reassembly_thread_pause();

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
  Pointer ptr;
  size_t size;
  Process::MemoryProtection old_protect;

  ScopedSetMemoryRWX(Pointer ptr, size_t size);
  ScopedSetMemoryRWX(const ScopedSetMemoryRWX &) = delete;
  ScopedSetMemoryRWX &operator=(const ScopedSetMemoryRWX &) = delete;
  ScopedSetMemoryRWX(const MemoryRange &r);

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

  template <size_t bufSize, size_t step = 1> struct MemoryIteratorBuffered {
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

    MemoryIteratorBuffered(Pointer ptr, size_t size) : ptr(ptr), size(size) {
      this->cache = std::make_shared<CacheBuffer>();
    }
    MemoryIteratorBuffered(Pointer ptr, size_t size,
                           std::shared_ptr<CacheBuffer> cache)
        : ptr(ptr), size(size), cache(cache) {
      if (!this->cache)
        this->cache = std::make_shared<CacheBuffer>();
    }

    inline MemoryIteratorBuffered &operator+=(size_t t) {
      size_t sub = t * step;
      if (sub > size) {
        ptr += size;
        size = 0;
      } else {
        ptr += sub;
        size -= sub;
      }
      return *this;
    }

    inline MemoryIteratorBuffered operator+(size_t t) const {
      size_t sub = t * step;
      size_t new_size = size;
      Pointer new_ptr = ptr;
      if (sub > size) {
        new_ptr += size;
        new_size = 0;
      } else {
        new_ptr += sub;
        new_size -= sub;
      }
      return {new_ptr, new_size, cache};
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

    inline bool is_readable() const { return try_read().has_value(); }

    inline std::optional<uint8_t> try_read() const {
      if (size == 0)
        return {};

      if (cache->buffer
              .empty() || /* !(cache->offset ∈ [ptr, ptr+cache->size]) */
          ptr.offset() < cache->offset ||
          ptr.offset() >= cache->offset + cache->buffer.size()) {
        auto read_size = std::min(bufSize, size);
        cache->buffer.resize(read_size);
        auto res = ptr.try_read_into(cache->buffer.data(), read_size);
        if (!res) {
          cache->buffer.clear();
          return {};
        }
        cache->offset = ptr.offset();
      }

      const size_t internal_offset = ptr.offset() - cache->offset;
      if (internal_offset >= cache->buffer.size())
        return {};

      return cache->buffer[internal_offset];
    }

    inline uint8_t operator*() {
      auto val = try_read();
      if (!val)
        throw std::runtime_error("Failed to read memory through iterator");
      return *val;
    }

    using value_type = uint8_t;
    using difference_type = std::ptrdiff_t;
    using pointer = uint8_t *;
    using reference = uint8_t &;
    using iterator_category = std::input_iterator_tag;
  };

  using MemoryIterator = MemoryIteratorBuffered<1024 * 4>;

  using iterator = MemoryIterator;
  using const_iterator = MemoryIterator;

  bool operator==(const MemoryRange &other) const = default;

  [[nodiscard]] MemoryIterator begin() const {
    return {*static_cast<const Pointer *>(this), _size};
  }

  [[nodiscard]] MemoryIterator end() const {
    return {(*static_cast<const Pointer *>(this)).add(_size), 0};
  }

  template <class Scanner = memory_scanner::mb_kmp>
  inline std::optional<Pointer>
  find_one(const std::vector<uint8_t> pattern) const {
    std::optional<size_t> res =
        Scanner::searchOne((uint8_t *)_offset, _size, pattern);
    return res.and_then([this](const auto val) {
      return std::optional<Pointer>(Pointer(this->proc, this->_offset + val));
    });
  }

  template <class Scanner = memory_scanner::mb_kmp>
  inline std::optional<Pointer>
  find_one(std::initializer_list<uint8_t> pattern) const {
    return find_one<Scanner>(
        std::vector<uint8_t>(std::forward<decltype(pattern)>(pattern)));
  }

  template <class Scanner = memory_scanner::mb_kmp>
  inline std::optional<Pointer> find_one(
      std::initializer_list<std::initializer_list<uint8_t>> pattern) const {
    for (const auto &pat : pattern) {
      const auto res = find_one<Scanner>(
          std::vector<uint8_t>(std::forward<decltype(pat)>(pat)));
      if (res.has_value())
        return res;
    }

    return {};
  }

  template <class Scanner = memory_scanner::mb_kmp, typename I>
  inline std::optional<Pointer>
  find_one(const std::pair<I, size_t> &pattern) const {
    const auto res = find_one<Scanner>(pattern.first);
    return res.and_then(
        [&](const auto val) { return std::optional(val + pattern.second); });
  }

  inline auto find_one(std::string_view sv) const {
    return find_one(std::vector<uint8_t>(sv.begin(), sv.end()));
  }

  std::optional<Pointer> find_one_remote(std::vector<uint8_t> pattern) const;

  inline auto find_one_remote(std::string_view sv) const {
    return find_one_remote(std::vector<uint8_t>(sv.begin(), sv.end()));
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