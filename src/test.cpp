

#include <algorithm>
#include <format>
#include <ostream>
#include <print>

#include "blook/blook.h"
#include <winuser.h>
#include "Windows.h"

void test_wrap_function() {
  const auto wrappedPlain = blook::Function::into_function_pointer(
      +[](int64_t a, int64_t b) { return a + b; });

  wrappedPlain(1, 2);
  std::println("Wrapped plain function");

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
  std::cout << std::format("non-wrapped version took {} for {} calls\n",
                           x.count(), num);

  const auto s1 = clock.now();
  for (int a = 0; a < num; a++)
    wrapped(114, 514);
  const auto b = clock.now() - s1;
  std::cout << std::format("wrapped version took {} for {} calls\n", b.count(),
                           num);

  std::cout << std::format("delta: {}, radio: {}\n", (b - x).count(),
                           b.count() / (double)x.count());
}

void test_inline_hook() {
  auto process = blook::Process::self();
  static auto hook = process->module("USER32.DLL")
                         .value()
                         ->exports("MessageBoxA")
                         ->inline_hook();
  hook->install(+[](size_t a, char *text, char *title, size_t b) -> int {
    std::cout << "Hooked MessageBoxA called" << std::endl;
    return hook->trampoline_t<int __stdcall(size_t, char *, char *, size_t)>()(
        a, (char *)"hooked MessageBoxA", text, b);
  });
  std::println("Hooked MessageBoxA");

  MessageBoxA(nullptr, "hi", "hi", 0);
  std::println("Hooked MessageBoxA return");
  hook->uninstall();
  std::println("Unhooked MessageBoxA");
  MessageBoxA(nullptr, "hi", "hi", 0);
}

void test_xref() {
  auto process = blook::Process::self();
  auto mod = process->module().value();
  auto rdata = mod->section(".rdata").value();
  auto text = mod->section(".text").value();

  const char *xchar =
      "this_is_some_special_string_that_represents_a_damn_vip_proc";
  auto a_special_variable = xchar;
  std::cout << a_special_variable << std::endl;
  const auto p = rdata.find_one("this_is_some_special_string_").value();
  std::cout << "Found target special string at: " << std::hex << " " << p.data()
            << std::endl;

  auto xref = text.find_xref(p).value();
  std::cout << "Found target usage at: " << std::hex << " " << xref.data()
            << std::endl;

  auto guess_func = xref.guess_function().value().data();
  std::cout << "Target function guessed: " << std::hex << guess_func
            << ", actual: " << &test_xref << std::endl;
}

struct TestStruct {
  union U {
    TestStruct *s;
    size_t data;
  } slot[100];
};

void test_memory_offsets() {
  TestStruct s{};
  s.slot[0x23].s = new TestStruct();
  s.slot[0x23].s->slot[0x12].s = new TestStruct();
  s.slot[0x23].s->slot[0x12].s->slot[0x4].data = 114514;

  auto ptr = (size_t ***)&s;
  blook::Pointer ptr2 = (void *)&s;

  auto val = *(*(*(ptr + 0x23) + 0x12) + 0x4);
  auto val2 = **ptr2.offsets({0x23, 0x12, 0x4}).value().read_leaked<size_t>();

  std::cout << "Normal:" << val << " Blook:" << val2;

  assert(val == val2);
}

void test_disassembly_iterator() {
  using namespace blook;
  MemoryRange range =
      ((Pointer)(void *)(&test_disassembly_iterator)).range_size(0x512);
  auto iter = range.disassembly();

  int cnt = 0;
  for (const auto &data : iter) {
    if (cnt++ > 5) {
      std::cout << "The fifth instruction mnemonic: " << data->getMnemonic()
                << std::endl;
      break;
    }
  }

  const char *special_str = "Some other special string...\n";
  std::cout << special_str;

  auto self = Process::self();
  auto mod = self->module().value();
  auto p_special_str = mod->section(".rdata")->find_one(special_str).value();

  auto res = std::ranges::find_if(iter, [=](const auto &c) {
    return std::ranges::contains(c.xrefs(), p_special_str);
  });

  std::cout << "Usage found at: " << (*res).ptr();
}

void test_dwm_big_round_corner() {
  using namespace blook;
  auto proc = Process::attach("dwm.exe");

  auto mod = proc->modules()["udwm.dll"];
  auto text = mod->section(".text").value();

  auto iter = text.disassembly();

  int cnt = 0;
  for (const auto &data : iter) {
    cnt += data->getLength();
    auto off = data.ptr() - mod->base();
    if (data->getMnemonic() == zasm::x86::Mnemonic::Movss &&
        data->getOperands()[0].holds<zasm::Reg>() &&
        data->getOperands()[1].holds<zasm::Mem>()) {
      auto &mem = data->getOperands()[1].get<zasm::Mem>();

      if (mem.getBase() == zasm::x86::rip) {
        auto val = proc->memo() + mem.getDisplacement();
        auto data2 = val.try_read<uint32_t>();
        constexpr const auto smallVar = 0x07210721;

        if (data2 &&
            (data2 == 0x40800000 || data2 == 0x41000000 ||
             data2 == 0x41f00000 || data2 == 0x40800000 || data2 == smallVar)) {
          std::cout << "Found target instruction at: " << data.ptr()
                    << std::endl;
          std::cout << "Writing new val to target addr" << std::endl;
          if (auto res = val.write(16.f); !res) {
            std::cerr << res.error() << std::endl;
          }
        }
      }
    }
  }

  std::cout << "Total bytes disassembled: " << cnt << std::endl;
}

void test_qq_iter() {
  using namespace blook;
  auto proc = Process::attach("QQ.exe");

  auto mod = proc->modules()["wrapper.node"];
  auto text = mod->section(".text").value();

  auto iter = text.disassembly();

  int cnt = 0;
  int lastProgressReport = 0;
  for (const auto &data : iter) {
    cnt += data->getLength();

    if (cnt - lastProgressReport > 0x10000) {
      std::cout << "Percent: " << (cnt / (float)text.size()) * 100 << std::endl;
      lastProgressReport = cnt;
    }

    auto off = data.ptr() - mod->base();
  }

  std::cout << "Total bytes disassembled: " << cnt << std::endl;
}

int main() {

  //   MessageBoxA(nullptr, "hi", "hi", 0);

  try {
    std::println("Hello, World!");

    test_inline_hook();
    test_wrap_function();
  } catch (std::exception &e) {
    std::cerr << e.what();
    abort();
  }
  //   test_xref();
  //    try {
  //    test_disassembly_iterator();
  //        test_xref();
  //    test_qq_iter();
  //    } catch (std::exception &e) {
  //        std::cerr << e.what();
  //        abort();
  //    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, // handle to DLL module
                    DWORD fdwReason,    // reason for calling function
                    LPVOID lpvReserved) // reserved
{
  // Perform actions based on the reason for calling.
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    MessageBoxA(nullptr, "hi", "hi", 0);

    break;

  case DLL_THREAD_ATTACH:
    // Do thread-specific initialization.
    break;

  case DLL_THREAD_DETACH:
    // Do thread-specific cleanup.
    break;

  case DLL_PROCESS_DETACH:

    if (lpvReserved != nullptr) {
      break; // do not do cleanup if process termination scenario
    }

    // Perform any necessary cleanup.
    break;
  }
  return TRUE; // Successful DLL_PROCESS_ATTACH.
}