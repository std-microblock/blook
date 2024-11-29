#include "blook/utils.h"
#include "blook/misc.h"
#include <format>
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
        throw std::runtime_error(
            std::format("Failed to estimate code size, error: {} {}",
                        instrInfo.error().getErrorName(),
                        instrInfo.error().getErrorMessage()
                        ));
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

BLOOK_TEXT_SECTION uint8_t _getStackPointer[] = {
    // mov rax, rsp
    0x48, 0x89, 0xE0,
    // ret
    0xC3};

#elif defined(__i386__)
BLOOK_TEXT_SECTION uint8_t _getEDX[] = {
    // mov eax, edx
    0x89, 0xD0,
    // ret
    0xC3};

getreg_fn_t getEDX = (getreg_fn_t)_getEDX;
BLOOK_TEXT_SECTION uint8_t _getStackPointer[] = {
    // mov eax, esp
    0x89, 0xE0,
    // ret
    0xC3};

#endif

getreg_fn_t getStackPointer = (getreg_fn_t)_getStackPointer;

} // namespace utils
} // namespace blook