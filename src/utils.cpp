#include "blook/utils.h"
#include "blook/misc.h"
#include <format>
#include <stdexcept>
#include <zasm/formatter/formatter.hpp>

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
        size += 15; // worst case size for an instruction
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

#ifdef BLOOK_ARCHITECTURE_X86_64
BLOOK_TEXT_SECTION uint8_t _getR11[] = {
    // mov rax, r11
    0x4C, 0x89, 0xD8,
    // ret
    0xC3};

getreg_fn_t getR11 = (getreg_fn_t)(void *)_getR11;

BLOOK_TEXT_SECTION uint8_t _getStackPointer[] = {
    // mov rax, rsp
    0x48, 0x89, 0xE0,
    // ret
    0xC3};

#elif defined(BLOOK_ARCHITECTURE_X86_32)
BLOOK_TEXT_SECTION uint8_t _getEDX[] = {
    // mov eax, edx
    0x89, 0xD0,
    // ret
    0xC3};

getreg_fn_t getEDX = (getreg_fn_t)(void *)_getEDX;
BLOOK_TEXT_SECTION uint8_t _getStackPointer[] = {
    // mov eax, esp
    0x89, 0xE0,
    // ret
    0xC3};

#endif

#ifdef _WIN32
#ifdef BLOOK_ARCHITECTURE_X86_64
BLOOK_TEXT_SECTION uint8_t get_peb_fn_buf[] = {
    // mov rax, gs:[0x60];
    // ret;
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3};
#elif defined(BLOOK_ARCHITECTURE_X86_32)
BLOOK_TEXT_SECTION uint8_t get_peb_fn_buf[] = {
    // mov eax, fs:[0x30];
    // ret;
    0x64, 0x8B, 0x40, 0x30, 0xC3};
#endif
#endif
getreg_fn_t getPEB = (getreg_fn_t)(void *)get_peb_fn_buf;

getreg_fn_t getStackPointer = (getreg_fn_t)(void *)_getStackPointer;

} // namespace utils
} // namespace blook