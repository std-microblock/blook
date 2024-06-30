
#include "include/Hook.h"
#include "include/Memo.h"
#include <format>

namespace blook {
InlineHook::InlineHook(void *target, void *hook_func)
    : target(target), hook_func(hook_func) {}
void InlineHook::install(bool try_trampoline) {
  if (installed)
    throw std::runtime_error("The hook was already installed.");

  using namespace zasm;
  Program programRewrite(MachineMode::AMD64);
  x86::Assembler a(programRewrite);

  a.mov(x86::r11, Imm((int64_t)hook_func));
  a.jmp(x86::r11);

  Serializer serializer;
  void *pCodePage = target;
  if (auto err = serializer.serialize(programRewrite,
                                      reinterpret_cast<int64_t>(pCodePage));
      err != zasm::ErrorCode::None)
    throw std::runtime_error(std::format("JIT Serialization failure: {} {}",
                                         err.getErrorName(),
                                         err.getErrorMessage()));

  const auto hookSize = serializer.getCodeSize();
  Decoder decoder(programRewrite.getMode());

  Program programTrampoline(MachineMode::AMD64);
  x86::Assembler b(programTrampoline);
  size_t realOccupiedBytes = 0;
  while (realOccupiedBytes < hookSize) {
    const auto curAddress = (size_t)target + realOccupiedBytes;

    const auto decoderRes =
        decoder.decode((char *)target + realOccupiedBytes, 30, curAddress);
    if (!decoderRes)
      throw std::runtime_error(
          std::format("Failed to decode at {} {} {}", curAddress,
                      decoderRes.error().getErrorName(),
                      decoderRes.error().getErrorMessage()));

    const auto &instrInfo = *decoderRes;
    const auto instr = instrInfo.getInstruction();
    if (auto res = b.emit(instr); res != zasm::ErrorCode::None)
      throw std::runtime_error(
          std::format("Failed to emit instruction at {} {}", curAddress,
                      res.getErrorName()));

    realOccupiedBytes += instrInfo.getLength();
  }
  if (try_trampoline) {
    b.jmp(Imm((size_t)target + realOccupiedBytes));
  } else {
    b.mov(x86::r11, Imm((size_t)target + realOccupiedBytes));
    b.jmp(x86::r11);
  }

  if (try_trampoline) {
    const auto trampoline_code_size =
        utils::estimateCodeSize(programTrampoline);
    trampoline_size = trampoline_code_size;
    const auto trampolineCode = Memo::malloc_near_rwx(target, trampoline_size);

    Serializer serializer2;
    if (auto err = serializer2.serialize(
            programTrampoline, reinterpret_cast<int64_t>(trampolineCode));
        err != zasm::ErrorCode::None)
      throw std::runtime_error(std::format("JIT Serialization failure: {} {}",
                                           err.getErrorName(),
                                           err.getErrorMessage()));
    std::memcpy(trampolineCode, serializer2.getCode(), trampoline_code_size);
    p_trampoline = trampolineCode;
  }

  Memo::protect_rwx(pCodePage, hookSize);
  std::memcpy(pCodePage, serializer.getCode(), hookSize);

  installed = true;
}
void *InlineHook::trampoline_raw() { return p_trampoline; }
InlineHook::InlineHook(void *target) : target(target) {}

} // namespace blook