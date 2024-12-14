#ifndef BLOOK_DISASSEMBLY_H
#define BLOOK_DISASSEMBLY_H

#include "concepts.h"
#include "memo.h"
#include "utils.h"
#include <utility>
#include <vector>
#include <zasm/zasm.hpp>

namespace blook {
namespace disasm {

class InstructionCtx {
  zasm::InstructionDetail instr;
  Pointer _ptr;

public:
  explicit InstructionCtx(zasm::InstructionDetail instr, Pointer ptr)
      : instr(std::move(instr)), _ptr(std::move(ptr)) {}

  auto ptr() const { return _ptr; }

  auto operator*() const { return instr; }

  auto operator->() const { return &instr; }

  [[nodiscard]] std::vector<Pointer> xrefs() const;
};

template <typename Range> class DisassembleRange {
public:
  template <typename Range> class DisassembleIteratorR;

private:
  using Iterator = DisassembleIteratorR<Range>;
  Pointer address_begin;
  Range range;
  zasm::MachineMode machine_mode;

public:
  using iterator = Iterator;
  using const_iterator = Iterator;
  using value_type = InstructionCtx;
  using difference_type = std::ptrdiff_t;
  using reference = value_type &;
  using const_reference = const value_type &;

  DisassembleRange(Range range, const Pointer &address,
                   zasm::MachineMode machine_mode = utils::compileMachineMode())
      : address_begin(address), range(range), machine_mode(machine_mode) {}

  [[nodiscard]] iterator begin() const {
    return iterator{range, address_begin, machine_mode};
  }

  [[nodiscard]] iterator end() const {
    return iterator{range, address_begin, machine_mode, true};
  }
  template <typename Range> class DisassembleIteratorR {
    static constexpr int BufferSize = 30;
    Pointer address = 0;
    Range range;
    using Iter = decltype(std::declval<Range>().begin());
    Iter ptr;
    std::optional<InstructionCtx> current_value;
    zasm::MachineMode machine_mode;
    bool over = false;
    std::vector<uint8_t> buffer{BufferSize};
    Iter range_end;

  public:
    using iterator_category = std::input_iterator_tag;
    using value_type = InstructionCtx;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    DisassembleIteratorR() = default;
    DisassembleIteratorR(const DisassembleIteratorR &) = default;
    DisassembleIteratorR(DisassembleIteratorR &&) = default;
    DisassembleIteratorR &operator=(const DisassembleIteratorR &) = default;
    DisassembleIteratorR &operator=(DisassembleIteratorR &&) = default;
    

    explicit DisassembleIteratorR(Range range, const Pointer &address,
                                  zasm::MachineMode machine_mode,
                                  bool is_end = false)
        : address(address), range(range), machine_mode(machine_mode),
          over(is_end) {
      ptr = range.begin();
      range_end = range.end();
      if (!over) {
        decode_next();
      }
    }

    DisassembleIteratorR &operator++() {
      decode_next();
      return *this;
    }

    DisassembleIteratorR operator++(int) {
      auto tmp = *this;
      ++(*this);
      return tmp;
    }

    value_type const &operator*() const { return *current_value; }

    bool operator==(const DisassembleIteratorR &other) const {
      return ((other.over && this->over) ||
              (other.address == this->address && other.over == this->over));
    }

  private:
    void decode_next() {
      using namespace zasm;
      Decoder d(machine_mode);

      if (ptr == range_end) {
        over = true;
        return;
      }

      if (over) {
        current_value = {};
        return;
      }

      auto maxSize = (size_t)30;
      buffer.resize(std::min(maxSize, (size_t)BufferSize));
      std::copy(ptr, ptr + buffer.size(), buffer.begin());
      const auto r = d.decode(buffer.data(), BufferSize, address);
      if (!r.hasValue()) {
        d = Decoder(machine_mode);
        ptr += 4;
        address += 4;
        return decode_next();
      }

      const auto size = r->getLength();
      ptr += size;
      address += size;
      current_value = InstructionCtx{r.value(), address};

      if (ptr == range_end) {
        over = true;
        return;
      }
    }
  };
};

using DisassembleIterator = DisassembleRange<std::span<uint8_t>>;
static_assert(std::ranges::range<DisassembleIterator>);

static_assert(
    std::sentinel_for<decltype(std::declval<DisassembleIterator>().begin()),
                      decltype(std::declval<DisassembleIterator>().end())>);
static_assert(std::ranges::range<disasm::DisassembleIterator>);
static_assert(
    std::sentinel_for<
        decltype(std::declval<disasm::DisassembleRange<MemoryRange>>().begin()),
        decltype(std::declval<disasm::DisassembleRange<MemoryRange>>().end())>);
} // namespace disasm

} // namespace blook

#endif // BLOOK_DISASSEMBLY_H
