#include "blook/utils.h"
#include "blook/misc.h"
#include <stdexcept>
namespace blook {

namespace utils {
std::size_t estimateCodeSize(const zasm::Program &program) {
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

#ifdef __x86_64__
BLOOK_TEXT_SECTION uint8_t _getR11[] = {
    // mov rax, r11
    0x4C, 0x89, 0xD8,
    // ret
    0xC3};

getreg_fn_t getR11 = (getreg_fn_t)_getR11;

#elif defined(__i386__)
BLOOK_TEXT_SECTION uint8_t _getECX[] = {
    // mov eax, ecx
    0x89, 0xC8,
    // ret
    0xC3};

getreg_fn_t getECX = (getreg_fn_t)_getECX;
#endif

} // namespace utils
} // namespace blook