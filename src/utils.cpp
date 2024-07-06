#include "blook/utils.h"
#include <stdexcept>
namespace blook {
std::size_t utils::estimateCodeSize(const zasm::Program &program) {
  std::size_t size = 0;
  for (auto *node = program.getHead(); node != nullptr;
       node = node->getNext()) {
    if (auto *nodeData = node->getIf<zasm::Data>(); nodeData != nullptr) {
      size += nodeData->getTotalSize();
    } else if (auto *nodeInstr = node->getIf<zasm::Instruction>();
               nodeInstr != nullptr) {
      const auto &instrInfo = nodeInstr->getDetail(program.getMode());
      if (instrInfo.hasValue()) {
        size += instrInfo->getLength();
      } else {
        throw std::runtime_error("Error: Unable to get instruction info");
      }
    } else if (auto *nodeEmbeddedLabel = node->getIf<zasm::EmbeddedLabel>();
               nodeEmbeddedLabel != nullptr) {
      const auto bitSize = nodeEmbeddedLabel->getSize();
      if (bitSize == zasm::BitSize::_32)
        size += 4;
      if (bitSize == zasm::BitSize::_64)
        size += 8;
    }
  }
  return size;
}
} // namespace blook