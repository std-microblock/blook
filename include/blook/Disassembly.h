#ifndef BLOOK_DISASSEMBLY_H
#define BLOOK_DISASSEMBLY_H

#include "Concepts.h"
#include "Memo.h"
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

            [[nodiscard]] std::vector<Pointer> xrefs() const {
                using namespace zasm;
                std::vector<Pointer> ptrs;
                for (std::size_t i = 0; i < instr.getOperandCount(); i++) {
                    const auto &op = instr.getOperand(i);

                    if (const Mem *opMem = op.getIf<Mem>(); opMem != nullptr) {
                        if (opMem->getBase() == x86::rip) {
                            auto ptr = (void *) opMem->getDisplacement();
                            ptrs.emplace_back(ptr);
                        }
                    }

                    if (const Imm *opImm = op.getIf<Imm>(); opImm != nullptr) {
                        const auto data = opImm->value<size_t>();
                        ptrs.emplace_back((void *) data);
                    }
                }

                return ptrs;
            }
        };

        template<typename Range>
        class DisassembleRange {
            static constexpr int BufferSize = 30;
            Pointer address = 0;
            Pointer address_begin = 0;
            Range range;
            using Iter = decltype(range.begin());
            Iter ptr;
            std::optional<InstructionCtx> current_value;
            zasm::MachineMode machine_mode = zasm::MachineMode::AMD64;
            bool over = false;
            std::vector<uint8_t> buffer{BufferSize};


        public:
            using iterator = DisassembleRange<Range>;
            using const_iterator = iterator;
            using iterator_tag = std::input_iterator_tag;
            using value_type = InstructionCtx;
            using difference_type = std::ptrdiff_t;
            using pointer = value_type *;
            using reference = value_type &;

            DisassembleRange() = default;

            DisassembleRange(const DisassembleRange &) = default;

            DisassembleRange(DisassembleRange &&) = default;

            DisassembleRange &operator=(const DisassembleRange &) = default;

            DisassembleRange &operator=(DisassembleRange &&) = default;

            explicit DisassembleRange(
                    Range range, const Pointer &address,
                    zasm::MachineMode machine_mode = utils::compileMachineMode())
                    : range(range), address(address), address_begin(address),
                      machine_mode(machine_mode) {
                ptr = range.begin();
                decode_next();
            }

            iterator &operator++() {
                decode_next();
                return (*this);
            }

            iterator operator++(int) {
                iterator retval = *this;
                ++(*this);
                return retval;
            }

            value_type const &operator*() const { return *current_value; }

            [[nodiscard]] iterator begin() const {
                return iterator{range, address_begin, machine_mode};
            }

            [[nodiscard]] iterator end() const {
                auto th = *this;
                th.over = true;
                th.current_value = {};
                return th;
            }

            bool operator==(const iterator &other) const {
                return ((other.over && this->over) ||
                        (other.address == this->address && other.over == this->over));
            }

        private:
            void decode_next() {
                using namespace zasm;
                Decoder d(machine_mode);

                if (ptr == range.end()) {
                    over = true;
                    return;
                }

                if (over) {
                    current_value = {};
                    return;
                }

                // Copy the buffer
                auto maxSize = (size_t) 30; // (size_t)std::distance(ptr, range.end());
                buffer.resize(std::min(maxSize, (size_t) BufferSize));
                std::copy(ptr, ptr + buffer.size(), buffer.begin());
                const auto r = d.decode(buffer.data(), BufferSize, address);
                if (!r.hasValue()) {
                    d = Decoder(machine_mode);
                    ptr += 1;
                    address += 1;
                    return decode_next();
                }

                const auto size = r->getLength();
                ptr += size;
                address += size;
                current_value = InstructionCtx{r.value(), address};

                if (ptr == range.end()) {
                    over = true;
                    return;
                }
            }
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
