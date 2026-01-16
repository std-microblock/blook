#include "blook/blook.h"

#include "blook/disassembly.h"

#include "blook/memo.h"
#include "blook/process.h"
#include "zasm/formatter/formatter.hpp"
#include <algorithm>
#include <cstdint>
#include <utility>

#include <iostream>

namespace blook {

Pointer::Pointer(std::shared_ptr<Process> proc, void *offset)
    : _offset((size_t)offset), proc(std::move(proc)) {}

Function Pointer::as_function() { return {proc, (void *)_offset}; }

Pointer::Pointer(std::shared_ptr<Process> proc, size_t offset)
    : _offset(offset), proc(std::move(proc)) {}

MemoryPatch
Pointer::reassembly(std::function<void(zasm::x86::Assembler)> func) {
  using namespace zasm;
  Program program(utils::compileMachineMode());
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
  if (ptr.proc->is_self()) {
    ScopedSetMemoryRWX protector(ptr, buffer.size());
    std::vector<uint8_t> tmp(buffer.size());
    std::memcpy(tmp.data(), buffer.data(), buffer.size());
    std::memcpy(buffer.data(), target, buffer.size());
    std::memcpy(target, tmp.data(), tmp.size());
  } else {
    std::vector<uint8_t> tmp(buffer.size());
    ptr.proc->read(tmp.data(), target, buffer.size());
    if (!ptr.proc->write(target, buffer))
      throw std::runtime_error("Failed to write memory");
    buffer = std::move(tmp);
  }

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

void *Pointer::data() const { return (void *)_offset; }

bool Pointer::is_self() const { return proc && proc->is_self(); }

std::optional<Function> Pointer::guess_function(size_t max_scan_size) {
  for (auto p = (size_t)_offset; p > (size_t)_offset - max_scan_size; p -= 1) {
    const auto v = (*(uint8_t *)p);
    const auto v1 = (*((uint8_t *)p - 1));
    const auto v2 = (*((uint8_t *)p - 2));
    const auto v3 = (*((uint8_t *)p - 3));
    if ((v == 0xCC && v1 == 0xCC) || (v == 0xC3 && v1 == 0xCC)) {
      return blook::Function{proc, (void *)(p + 1)};
    }
    // if (v1 == 0 && v2 == 0 && v3 == 0 && v == 0)
    //   return blook::Function{proc, (void *)(p + 1)};
  }

  return {};
}

std::optional<Pointer> Pointer::offsets(const std::vector<size_t> &offsets,
                                        size_t scale) {
  Pointer ptr = *this;
  for (const auto &offset_next :
       std::span(offsets.begin(), offsets.end() - 1)) {
    ptr += offset_next * scale;
    auto res = ptr.try_read_struct<size_t>();
    if (!res)
      return {};
    ptr = Pointer(proc, (void *)*res);
  }

  return ptr.add(offsets.back() * scale);
}

Pointer::Pointer(void *offset) : Pointer(blook::Process::self(), offset) {}

std::optional<Pointer>
Pointer::find_upwards(std::initializer_list<uint8_t> pattern,
                      size_t max_scan_size) {
  Pointer p = *this;

  if (p.proc->is_self())
    for (; p > this - max_scan_size; p -= 1) {
      if (memcmp(pattern.begin(), (unsigned char *)p.data(), pattern.size()) ==
          0) {
        return p;
      }
    }

  else {
    auto data = p.sub(max_scan_size).read_bytearray(max_scan_size);
    for (size_t i = max_scan_size - pattern.size(); i > 0; i--) {
      if (memcmp(pattern.begin(), data.data() + i, pattern.size()) == 0) {
        return p.sub(max_scan_size - i);
      }
    }
  }

  return {};
}

MemoryRange Pointer::range_to(Pointer ptr) {
  if (ptr <= (*this))
    return MemoryRange{*this, 0};
  return MemoryRange{*this, (size_t)ptr.data() - (size_t)this->data()};
}

MemoryRange Pointer::range_size(std::size_t size) {
  return MemoryRange{*this, size};
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
  if (proc->is_self()) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < _size; i++) {
      crc = crc32_table[(crc ^ *((uint8_t *)_offset)) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
  } else {
    auto iter = this->begin();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < _size; i++) {
      crc = crc32_table[(crc ^ *iter) & 0xFF] ^ (crc >> 8);
      iter++;
    }
    return crc ^ 0xFFFFFFFF;
  }
}

std::optional<Pointer>
MemoryRange::find_one_remote(std::vector<uint8_t> pattern) const {
  auto res =
      std::search(this->begin(), this->end(), pattern.begin(), pattern.end());
  if (res == this->end())
    return {};
  return res.ptr;
}
MemoryPatch Pointer::reassembly_thread_pause() {
  return reassembly([](zasm::x86::Assembler a) {
#if defined(BLOOK_ARCHITECTURE_X86_64) || defined(BLOOK_ARCHITECTURE_X86_32)
    // EB FE: jmp $0
    a.db(0xeb);
    a.db(0xfe);
#else
#error "Unsupported architecture"
#endif
  });
}
} // namespace blook