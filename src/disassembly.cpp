//
// Created by MicroBlock on 2024/8/30.
//

#include "blook/disassembly.h"
#include <iostream>

namespace blook::disasm {
std::vector<Pointer> InstructionCtx::xrefs() const {
  using namespace zasm;
  std::vector<Pointer> ptrs{};
  for (std::size_t i = 0; i < instr.getOperandCount(); i++) {
    const auto &op = instr.getOperand(i);

    if (const Mem *opMem = op.getIf<Mem>(); opMem != nullptr) {
      if (opMem->getBase() == x86::rip || opMem->getBase() == x86::eip) {
        auto ptr = (void *)opMem->getDisplacement();
        std::cout << "RIP/EIP: " << ptr << std::endl;
        ptrs.emplace_back(ptr);
      }
    }

    if (const Imm *opImm = op.getIf<Imm>(); opImm != nullptr) {
      const auto data = opImm->value<size_t>();
      ptrs.emplace_back((void *)data);
    }
  }

  return ptrs;
}
} // namespace blook::disasm