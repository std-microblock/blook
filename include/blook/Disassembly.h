#ifndef BLOOK_DISASSEMBLY_H
#define BLOOK_DISASSEMBLY_H

#include <zasm/zasm.hpp>
#include "utils.h"
#include "Memo.h"
#include <vector>

namespace blook {
    namespace disasm {
        class InstructionCtx {
            zasm::Instruction instr;
        public:
            CLASS_MOVE_ONLY(InstructionCtx);

            zasm::Instruction operator*() const {
                return instr;
            }

            std::vector<Pointer> xrefs() {
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

        class DisassembleIterator {

        public:

            InstructionCtx begin() {

            }

            InstructionCtx end() {
                
            }
        };
    }

} // blook

#endif //BLOOK_DISASSEMBLY_H
