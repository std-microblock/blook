#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "memory_scanner/mb_kmp.h"
#include "zasm/zasm.hpp"

namespace blook {
class Process;
class Function;
class MemoryRange;
class MemoryPatch;
class Module;
class Pointer {

protected:
  size_t offset = 0;
  std::shared_ptr<Process> proc;
  friend MemoryPatch;

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

  void *malloc(size_t size, void *near,
               MemoryProtection protection = MemoryProtection::rw);

  void *malloc(size_t size, MemoryProtection protection = MemoryProtection::rw);

  std::vector<uint8_t> read(void *ptr, size_t size);

  std::span<uint8_t> read_leaked(void *ptr, size_t size);

  template <typename Struct>
  inline std::optional<Struct *> read(void *ptr = nullptr) {
    const auto val = read_leaked(ptr, sizeof(Struct));
    return reinterpret_cast<Struct *>(val.data());
  }

  template <typename Struct> inline std::optional<Struct> read(size_t ptr) {
    return read<Struct>((void *)ptr);
  }

  std::optional<std::vector<uint8_t>> try_read(void *ptr, size_t size);

  explicit Pointer(std::shared_ptr<Process> proc);

  Pointer(std::shared_ptr<Process> proc, void *offset);

  Pointer(std::shared_ptr<Process> proc, size_t offset);
  // Construct a pointer within current process.
  Pointer(void *offset);

  Function as_function();

  [[nodiscard]] void *data() const;

  // Pointer operations
  inline Pointer add(const auto &t) const {
    return {proc, (void *)(offset + (size_t)t)};
  }

  inline Pointer sub(const auto &t) const {
    return {proc, (void *)(offset - (size_t)t)};
  }

  inline auto operator+(const auto &t) { return this->add(t); }

  inline auto operator-(const auto &t) { return this->sub(t); }

  inline auto operator+=(const auto &t) { this->offset += (size_t)t; };
  inline auto operator-=(const auto &t) { this->offset -= (size_t)t; };

  inline auto operator<=>(const Pointer &o) const {
    return this->offset <=> o.offset;
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
  size_t _size;

public:
  MemoryRange(std::shared_ptr<Process> proc, void *offset, size_t size);

  [[nodiscard]] size_t size() const { return _size; }

  template <class Scanner = memory_scanner::mb_kmp>
  inline std::optional<Pointer>
  find_one(const std::vector<uint8_t> pattern) const {
    const auto span = std::span<uint8_t>((uint8_t *)offset, _size);
    std::optional<size_t> res = Scanner::searchOne(span, pattern);
    return res.and_then([this](const auto val) {
      return std::optional<Pointer>(Pointer(this->proc, this->offset + val));
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

  std::optional<Pointer> find_disassembly(
      std::function<bool(const zasm::InstructionDetail &, size_t)> find_func);

  std::optional<Pointer> find_xref(Pointer p);
};
} // namespace blook