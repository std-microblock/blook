
#include "blook/blook.h"

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
  auto hook = process->module("USER32.DLL")
                  .value()
                  ->exports("MessageBoxA")
                  ->inline_hook();
  hook->install([=](int64_t a, char *text, char *title, int64_t b) -> int64_t {
    return hook->trampoline_t<int64_t(int64_t, char *, char *, int64_t)>()(
        a, (char *)"oh fuck", text, b);
  });

  MessageBoxA(nullptr, "hi", "hi", 0);

  hook->uninstall();
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

int main() {
  //    try {
  //    test_disassembly_iterator();
  //        test_xref();
  test_dwm_big_round_corner();
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
// This file is generated by blook
// Neither touch/modify nor include this file in your project!

#include "Windows.h"
#include <cstdlib>

// blook: USE_STATIC_INITIALIZATION_TO_INIT_EXPORTS
void (*blookHijackFuncs[17])() = {};

const char *blookHijackFuncNames[] = {
    "GetFileVersionInfoA",
    "GetFileVersionInfoByHandle",
    "GetFileVersionInfoExA",
    "GetFileVersionInfoExW",
    "GetFileVersionInfoSizeA",
    "GetFileVersionInfoSizeExA",
    "GetFileVersionInfoSizeExW",
    "GetFileVersionInfoSizeW",
    "GetFileVersionInfoW",
    "VerFindFileA",
    "VerFindFileW",
    "VerInstallFileA",
    "VerInstallFileW",
    "VerLanguageNameA",
    "VerLanguageNameW",
    "VerQueryValueA",
    "VerQueryValueW",

};

int blookInit = ([]() {
  char system_dir_path[MAX_PATH];
  GetSystemDirectoryA(system_dir_path, MAX_PATH);
  strcat_s(system_dir_path, "\\version.dll");
  HMODULE lib = LoadLibraryA(system_dir_path);

  for (int i = 0; i < sizeof(blookHijackFuncs) / sizeof(blookHijackFuncs[0]);
       i++) {
    blookHijackFuncs[i] =
        (void (*)())GetProcAddress(lib, blookHijackFuncNames[i]);
  }

  return 0;
})();

// blook: GENERATED_PLACEHOLDER_FUNCTION_EXPORTS
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=BLOOK_PLACEHOLDER_1")
extern "C" void BLOOK_PLACEHOLDER_1() { return (blookHijackFuncs[1])(); }

#pragma comment(linker,                                                        \
                "/EXPORT:GetFileVersionInfoByHandle=BLOOK_PLACEHOLDER_2")
extern "C" void BLOOK_PLACEHOLDER_2() { return (blookHijackFuncs[2])(); }

#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=BLOOK_PLACEHOLDER_3")
extern "C" void BLOOK_PLACEHOLDER_3() { return (blookHijackFuncs[3])(); }

#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=BLOOK_PLACEHOLDER_4")
extern "C" void BLOOK_PLACEHOLDER_4() { return (blookHijackFuncs[4])(); }

#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=BLOOK_PLACEHOLDER_5")
extern "C" void BLOOK_PLACEHOLDER_5() { return (blookHijackFuncs[5])(); }

#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=BLOOK_PLACEHOLDER_6")
extern "C" void BLOOK_PLACEHOLDER_6() { return (blookHijackFuncs[6])(); }

#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=BLOOK_PLACEHOLDER_7")
extern "C" void BLOOK_PLACEHOLDER_7() { return (blookHijackFuncs[7])(); }

#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=BLOOK_PLACEHOLDER_8")
extern "C" void BLOOK_PLACEHOLDER_8() { return (blookHijackFuncs[8])(); }

#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=BLOOK_PLACEHOLDER_9")
extern "C" void BLOOK_PLACEHOLDER_9() { return (blookHijackFuncs[9])(); }

#pragma comment(linker, "/EXPORT:VerFindFileA=BLOOK_PLACEHOLDER_10")
extern "C" void BLOOK_PLACEHOLDER_10() { return (blookHijackFuncs[10])(); }

#pragma comment(linker, "/EXPORT:VerFindFileW=BLOOK_PLACEHOLDER_11")
extern "C" void BLOOK_PLACEHOLDER_11() { return (blookHijackFuncs[11])(); }

#pragma comment(linker, "/EXPORT:VerInstallFileA=BLOOK_PLACEHOLDER_12")
extern "C" void BLOOK_PLACEHOLDER_12() { return (blookHijackFuncs[12])(); }

#pragma comment(linker, "/EXPORT:VerInstallFileW=BLOOK_PLACEHOLDER_13")
extern "C" void BLOOK_PLACEHOLDER_13() { return (blookHijackFuncs[13])(); }

#pragma comment(linker, "/EXPORT:VerLanguageNameA=BLOOK_PLACEHOLDER_14")
extern "C" void BLOOK_PLACEHOLDER_14() { return (blookHijackFuncs[14])(); }

#pragma comment(linker, "/EXPORT:VerLanguageNameW=BLOOK_PLACEHOLDER_15")
extern "C" void BLOOK_PLACEHOLDER_15() { return (blookHijackFuncs[15])(); }

#pragma comment(linker, "/EXPORT:VerQueryValueA=BLOOK_PLACEHOLDER_16")
extern "C" void BLOOK_PLACEHOLDER_16() { return (blookHijackFuncs[16])(); }

#pragma comment(linker, "/EXPORT:VerQueryValueW=BLOOK_PLACEHOLDER_17")
extern "C" void BLOOK_PLACEHOLDER_17() { return (blookHijackFuncs[17])(); }
