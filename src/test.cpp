#include "../blook.h"
#include "Windows.h"
#include <format>

void test_wrap_function() {
  int evilNum = 1919810;
  const auto wrapped = blook::Function::into_function_pointer(
      [=](int64_t a, int64_t b) { return a + b + evilNum; });

  const auto non_wrapped =
      std::function([=](int64_t a, int64_t b) { return a + b + evilNum; });

  constexpr auto num = 100000000;
  const auto clock = std::chrono::high_resolution_clock();

  const auto s2 = clock.now();
  for (int a = 0; a < num; a++)
    non_wrapped(114, 514);
  const auto x = clock.now() - s2;
  std::cout << std::format("non-wrapped version took {} for {} calls\n", x,
                           num);

  const auto s1 = clock.now();
  for (int a = 0; a < num; a++)
    wrapped(114, 514);
  const auto b = clock.now() - s1;
  std::cout << std::format("wrapped version took {} for {} calls\n", b, num);

  std::cout << std::format("delta: {}, radio: {}\n", b - x,
                           b.count() / (double)x.count());
}

void test_inline_hook() {
  auto process = blook::Process::self();
  auto hook =
      process->module("USER32.DLL")
          .value()
          ->exports("MessageBoxA")
          ->make_inline_hook(
              [](auto hook)
                  -> std::function<int64_t(int64_t, char *, char *, int64_t)> {
                return [&](int64_t a, char *text, char *title, int64_t b) {
                  return hook->trampoline()(a, "oh fuck", text, b);
                };
              });

  MessageBoxA(nullptr, "hi", "hi", 0);
}

int main() {
  try {
    test_inline_hook();
  } catch (std::exception &e) {
    std::cerr << e.what();
    abort();
  }
}