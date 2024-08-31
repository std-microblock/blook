#ifndef BLOOK_DISASSEMBLY_H
#define BLOOK_DISASSEMBLY_H

#include <utility>
#include <zasm/zasm.hpp>
#include "utils.h"
#include "Memo.h"
#include <vector>

namespace blook {
    namespace disasm {
        class DisassembleIterator;

        class InstructionCtx {
            zasm::InstructionDetail instr;
            Pointer _ptr;
        protected:
            explicit InstructionCtx(zasm::InstructionDetail instr, Pointer ptr) : instr(std::move(instr)),
                                                                                  _ptr(std::move(ptr)) {}

        public:
            friend DisassembleIterator;

            auto ptr() const {
                return _ptr;
            }

            auto operator*() const {
                return instr;
            }

            auto operator->() const {
                return &instr;
            }

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

        class DisassembleIterator
                : public std::iterator<std::input_iterator_tag, InstructionCtx> {
            MemoryRange range{nullptr, 0};
            Pointer ptr = nullptr;
            std::optional<InstructionCtx> current_value;
            zasm::MachineMode machine_mode = zasm::MachineMode::AMD64;
            bool over = false;

        public:
            using iterator = DisassembleIterator;
            using const_iterator = iterator;

            DisassembleIterator() = default;

            DisassembleIterator(const DisassembleIterator &) = default;

            explicit DisassembleIterator(MemoryRange range) : range(std::move(range)), ptr(std::move(range)) {
                decode_next();
            };

            iterator &operator++() {
                decode_next();
                return (*this);
            }

            DisassembleIterator operator++(int) {
                DisassembleIterator retval = *this;
                ++(*this);
                return retval;
            }

            value_type const &operator*() const {
                return *current_value;
            }

            [[nodiscard]] DisassembleIterator begin() const {
                return DisassembleIterator{range};
            }

            [[nodiscard]] DisassembleIterator end() const {
                auto th = *this;
                th.over = true;
                th.current_value = {};
                return th;
            }

            bool operator==(const DisassembleIterator &other) const {
                return other.range == this->range && (
                        (other.over && this->over) || (other.ptr == this->ptr && other.over == this->over)
                );
            }

        private:
            void decode_next() {
                using namespace zasm;
                Decoder d(machine_mode);

                for (; (size_t) ((ptr - range.data()).data()) < range.size();) {
                    const auto r = d.decode(ptr.data(), 30, (size_t) ptr.data());
                    if (!r.hasValue()) {
                        d = Decoder(machine_mode);
                        ptr += 1;
                        continue;
                    }
                    const auto size = r->getLength();
                    ptr += size;
                    current_value = InstructionCtx{r.value(), ptr};
                    break;
                }

                if ((size_t) ((ptr - range.data()).data()) >= range.size()) {
                    current_value = {};
                    over = true;
                }
            }
        };

        static_assert(std::sentinel_for<decltype(std::declval<DisassembleIterator>().begin()),
                decltype(std::declval<DisassembleIterator>().end())>);
        static_assert(std::ranges::range<disasm::DisassembleIterator>);
    }

} // blook

#endif //BLOOK_DISASSEMBLY_H
