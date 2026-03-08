#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "blook/blook.h"
#include "blook/hook.h"
#include "blook/memo.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include <Windows.h>
#include <winuser.h>

#pragma optimize("", off)

static int g_safe_wrapper_result = 0;
void safe_wrapper_target_func(int a, int b) { g_safe_wrapper_result = a + b; }

[[clang::noinline]] [[gnu::noinline]] [[msvc::noinline]]
int32_t AplusB(int32_t a, int32_t b) {
  return a + b;
}

[[clang::noinline]] [[gnu::noinline]] [[msvc::noinline]]
void *XrefTargetFunction() {

  const char *unique_string_for_xref =
      "this_is_some_special_string_that_represents_a_damn_vip_proc";

  return (void *)unique_string_for_xref;
}

[[clang::noinline]] [[gnu::noinline]] [[msvc::noinline]]
const char *DisassemblyTargetFunction() {
  const char *special_str =
      "Some other special string for disassembly test...\n";

  return special_str;
}

extern "C" __declspec(dllexport) void f_test_exports() {}
#pragma optimize("", on)

TEST(BlookProcessTests, SelfAndModules) {
  ASSERT_NO_THROW({
    auto process = blook::Process::self();
    ASSERT_TRUE(process);
    ASSERT_NE(process->pid, 0);

    auto main_module = process->module();
    ASSERT_TRUE(main_module.has_value());
    ASSERT_NE(main_module.value()->base(), nullptr);

    auto modules = process->modules();
    ASSERT_TRUE(modules.count("KERNEL32.DLL") > 0 ||
                modules.count("kernel32.dll") > 0);
  });
}

TEST(BlookThreadTests, ListAndContext) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto threads = proc->threads();
  ASSERT_FALSE(threads.empty());

  bool current_thread_found = false;
  for (auto &thread : threads) {
    if (thread.id != GetCurrentThreadId()) {
      current_thread_found = true;
      ASSERT_TRUE(thread.capture_context().has_value());
      break;
    }
  }
  ASSERT_TRUE(current_thread_found);
}

TEST(BlookFunctionWrapperTests, IntoFunctionPointer) {

  const auto wrappedPlain = blook::Function::into_function_pointer(
      +[](int64_t a, int64_t b) { return a + b; });
  ASSERT_NE(wrappedPlain, nullptr);
  EXPECT_EQ(wrappedPlain(10, 20), 30);

  int evilNum = 100;
  const auto wrappedCapture = blook::Function::into_function_pointer(
      [=](int64_t a, int64_t b) { return a + b + evilNum; });
  ASSERT_NE(wrappedCapture, nullptr);
  EXPECT_EQ(wrappedCapture(10, 20), 130);
}

TEST(BlookFunctionWrapperTests, IntoSafeFunctionPointer) {

  g_safe_wrapper_result = 0;
  auto safe_func = blook::Function::into_safe_function_pointer(
      safe_wrapper_target_func, false);
  ASSERT_NE(safe_func, nullptr);
  safe_func(5, 8);
  EXPECT_EQ(g_safe_wrapper_result, 13);

  g_safe_wrapper_result = 0;
  auto safe_func_ts = blook::Function::into_safe_function_pointer(
      safe_wrapper_target_func, true);
  ASSERT_NE(safe_func_ts, nullptr);
  safe_func_ts(10, 20);
  EXPECT_EQ(g_safe_wrapper_result, 30);
}

class InlineHookTest : public ::testing::Test {
protected:
  std::shared_ptr<blook::InlineHook> hook_AplusB;
  std::shared_ptr<blook::InlineHook> hook_GetTickCount;

  void TearDown() override {

    if (hook_AplusB && hook_AplusB->is_installed()) {
      hook_AplusB->uninstall();
    }
    if (hook_GetTickCount && hook_GetTickCount->is_installed()) {
      hook_GetTickCount->uninstall();
    }
  }
};

TEST_F(InlineHookTest, HookLocalFunction) {

  ASSERT_NO_THROW({
    hook_AplusB = blook::Pointer((void *)AplusB).as_function().inline_hook();
    ASSERT_TRUE(hook_AplusB);
  });

  hook_AplusB->install([=](int32_t a, int32_t b) { return a * b; });
  ASSERT_TRUE(hook_AplusB->is_installed());

  EXPECT_EQ(AplusB(10, 5), 50);
  EXPECT_EQ(hook_AplusB->call_trampoline<int32_t>(10, 5), 15);

  hook_AplusB->uninstall();
  ASSERT_FALSE(hook_AplusB->is_installed());

  EXPECT_EQ(AplusB(10, 5), 15);
}

TEST_F(InlineHookTest, HookWinApiFunction_NonInteractive) {

  auto process = blook::Process::self();
  auto kernel32 = process->module("KERNEL32.DLL").value();
  auto pGetTickCount64 = kernel32->exports("GetTickCount64");
  ASSERT_TRUE(pGetTickCount64.has_value());

  hook_GetTickCount = pGetTickCount64->inline_hook();
  ASSERT_TRUE(hook_GetTickCount);

  ULONGLONG original_tick = GetTickCount64();

  const ULONGLONG FAKE_TICK_VALUE = 114514;
  hook_GetTickCount->install([=]() -> ULONGLONG { return FAKE_TICK_VALUE; });
  ASSERT_TRUE(hook_GetTickCount->is_installed());

  EXPECT_EQ(GetTickCount64(), FAKE_TICK_VALUE);

  hook_GetTickCount->uninstall();
  ASSERT_FALSE(hook_GetTickCount->is_installed());

  ULONGLONG restored_tick = GetTickCount64();
  EXPECT_NE(restored_tick, FAKE_TICK_VALUE);
  EXPECT_GE(restored_tick, original_tick);
}

TEST(BlookMemoryTests, PointerOffsets) {
  struct TestStruct {
    union U {
      TestStruct *s;
      size_t data;
    } slot[100];
  };

  TestStruct s{};
  s.slot[0x23].s = new TestStruct();
  s.slot[0x23].s->slot[0x12].s = new TestStruct();
  s.slot[0x23].s->slot[0x12].s->slot[0x4].data = 114514;

  blook::Pointer ptr = (void *)&s;
  auto final_ptr_opt = ptr.offsets(
      {0x23 * sizeof(void *), 0x12 * sizeof(void *), 0x4 * sizeof(void *)}, 1);

  ASSERT_TRUE(final_ptr_opt.has_value());
  auto value_res = final_ptr_opt.value().try_read_u64();

  ASSERT_TRUE(value_res.has_value());
  EXPECT_EQ(value_res.value(), 114514);

  delete s.slot[0x23].s->slot[0x12].s;
  delete s.slot[0x23].s;
}

TEST(BlookMemoryTests, ProcessMemoryAPI) {
  using namespace blook;
  auto proc = Process::self();

  // Test malloc/free
  auto ptr = proc->malloc(1024, Protect::rw);
  ASSERT_NE((void*)ptr, nullptr);
  EXPECT_TRUE(proc->check_valid(ptr));
  EXPECT_TRUE(proc->check_readable(ptr, 1024));
  EXPECT_TRUE(proc->check_writable(ptr, 1024));

  int val = 123456;
  proc->write(ptr, &val, sizeof(val));
  int val2 = 0;
  proc->read(&val2, ptr, sizeof(val2));
  EXPECT_EQ(val, val2);

  proc->set_memory_protect(ptr, 1024, Protect::Read);
  EXPECT_FALSE(proc->check_writable(ptr, 1024));

  proc->free(ptr);
  EXPECT_FALSE(proc->check_valid(ptr));

  // Test near malloc
  auto near_ptr = proc->malloc(1024, Protect::rw, (void *)0x10000);
  ASSERT_NE((void*)near_ptr, nullptr);
  proc->free(near_ptr);
}

TEST(BlookMemoryTests, NewReadWriteAPI) {
  using namespace blook;
  auto proc = Process::self();

  // Test basic types
  int32_t val32 = 0x12345678;
  Pointer p32 = (void *)&val32;
  EXPECT_EQ(p32.read_s32(), 0x12345678);
  p32.write_s32(0x7fffffff);
  EXPECT_EQ(val32, 0x7fffffff);

  // Test struct
  struct MyStruct {
    int a;
    float b;
    char c[4];
  };
  MyStruct s{1, 2.0f, {'a', 'b', 'c', '\0'}};
  Pointer ps = (void *)&s;
  auto s2 = ps.read_struct<MyStruct>();
  EXPECT_EQ(s2.a, 1);
  EXPECT_EQ(s2.b, 2.0f);
  EXPECT_STREQ(s2.c, "abc");

  s2.a = 10;
  ps.write_struct(s2);
  EXPECT_EQ(s.a, 10);

  // Test bytearray
  std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
  Pointer pb = (void *)bytes.data();
  auto bytes2 = pb.read_bytearray(4);
  EXPECT_EQ(bytes2, bytes);

  // Test strings
  const char *utf8_str = "hello utf8";
  Pointer p_utf8 = (void *)utf8_str;
  EXPECT_EQ(p_utf8.read_utf8_string(), "hello utf8");

  const wchar_t *utf16_str = L"hello utf16";
  Pointer p_utf16 = (void *)utf16_str;
  EXPECT_TRUE(p_utf16.read_utf16_string() == std::wstring(L"hello utf16"));

  // Test try_read/try_write
  auto res = p32.try_read_s32();
  ASSERT_TRUE(res.has_value()) << res.error();
  EXPECT_EQ(*res, 0x7fffffff);

  Pointer invalid_ptr = (void *)0x1234; // Likely invalid
  auto res_invalid = invalid_ptr.try_read_s32();
  EXPECT_FALSE(res_invalid.has_value());

  // Test read/write pointer
  int target_val = 123;
  void *target_ptr = &target_val;
  void *storage = nullptr;
  Pointer p_storage = (void *)&storage;
  p_storage.write_pointer(Pointer(target_ptr));
  EXPECT_EQ(storage, target_ptr);
  Pointer read_ptr = p_storage.read_pointer();
  EXPECT_EQ(read_ptr.data(), target_ptr);
  EXPECT_EQ(read_ptr.read_s32(), 123);

  // Test string writing
  char str_buf[20];
  Pointer p_str_buf = (void *)str_buf;
  p_str_buf.write_utf8_string("test string");
  EXPECT_STREQ(str_buf, "test string");
  EXPECT_EQ(p_str_buf.read_utf8_string(), "test string");

  wchar_t wstr_buf[20];
  Pointer p_wstr_buf = (void *)wstr_buf;
  p_wstr_buf.write_utf16_string(L"test wstring");
  EXPECT_TRUE(p_wstr_buf.read_utf16_string() == std::wstring(L"test wstring"));

  // Test write_bytearray overloads
  std::string s_data = "abcd";
  p_str_buf.write_bytearray(s_data);
  EXPECT_EQ(p_str_buf.read_bytearray(4),
            (std::vector<uint8_t>{'a', 'b', 'c', 'd'}));

  std::wstring ws_data = L"efgh";
  p_wstr_buf.write_bytearray(ws_data);
  EXPECT_EQ(p_wstr_buf.read_bytearray(8),
            (std::vector<uint8_t>{(uint8_t)'e', 0, (uint8_t)'f', 0,
                                  (uint8_t)'g', 0, (uint8_t)'h', 0}));
}

TEST(BlookMemoryTests, ScopedSetMemoryRWX) {
  using namespace blook;
  int val = 123;
  Pointer p = &val;
  {
    ScopedSetMemoryRWX scoped(p, sizeof(val));
    p.write_s32(456);
  }
  EXPECT_EQ(val, 456);
}

TEST(BlookMemoryTests, MemoryIterator) {
  using namespace blook;
  std::vector<uint8_t> data = {0x11, 0x22, 0x33, 0x44, 0x55};
  Pointer p = (void *)data.data();
  MemoryRange range(p, data.size());

  auto it = range.begin();
  EXPECT_EQ(*it, 0x11);
  ++it;
  EXPECT_EQ(*it, 0x22);

  std::vector<uint8_t> collected;
  for (auto b : range) {
    collected.push_back(b);
  }
  EXPECT_EQ(collected, data);

  // Test buffered reading
  using SmallIterator = MemoryRange::MemoryIteratorBuffered<2>;
  SmallIterator sit(p, data.size());
  EXPECT_EQ(*sit, 0x11);
  sit++;
  EXPECT_EQ(*sit, 0x22);
  sit++;
  EXPECT_EQ(*sit, 0x33);
}

TEST(BlookAnalysisTests, XRef) {
  auto process = blook::Process::self();
  auto mod = process->module().value();
  auto rdata = mod->section(".rdata").value();
  auto text = mod->section(".text").value();

  void *target_string_addr = XrefTargetFunction();

  auto xref = text.find_xref(target_string_addr);
  ASSERT_TRUE(xref.has_value())
      << "Cross-reference to the test string not found.";

  auto guess_func = xref->guess_function();
  ASSERT_TRUE(guess_func.has_value()) << "Failed to guess function from XRef.";

  EXPECT_EQ(guess_func->data(), (void *)XrefTargetFunction);
}

TEST(BlookAnalysisTests, DisassemblyAndXRef) {
  using namespace blook;

  const char *str_in_func = DisassemblyTargetFunction();
  Pointer target_func_ptr = (void *)DisassemblyTargetFunction;

  auto self = Process::self();
  auto mod = self->module().value();
  auto p_special_str = mod->section(".rdata")->find_one(str_in_func);
  ASSERT_TRUE(p_special_str.has_value())
      << "Could not find the special string in the module.";

  auto disassembly_range = target_func_ptr.range_size(0x100);
  auto iter = disassembly_range.disassembly();

  auto result_iter = std::ranges::find_if(iter, [&](const auto &instruction) {
    return std::ranges::contains(instruction.xrefs(), p_special_str.value());
  });

  ASSERT_NE(result_iter, iter.end())
      << "Could not find an instruction that references the special string.";

  uintptr_t instr_addr = (uintptr_t)(*result_iter).ptr().data();
  uintptr_t func_start = (uintptr_t)target_func_ptr.data();
  uintptr_t func_end = func_start + 0x100;

  EXPECT_GE(instr_addr, func_start);
  EXPECT_LT(instr_addr, func_end);
}

TEST(BlookModuleTests, ExportParsing) {
  auto proc = blook::Process::self();
  auto mod = proc->process_module().value();
  auto exported_func = mod->exports("f_test_exports");

  ASSERT_TRUE(exported_func.has_value());
  EXPECT_EQ(exported_func->data<void *>(), (void *)&f_test_exports);
}

#pragma optimize("", off)
int veh_test_target_func(int a, int b) { return a * b + 42; }
int veh_test_target_func2(int a, int b) { return a * b + 423; }
int veh_test_target_func3(int a, int b) { return a * b + 412; }
int veh_test_target_func4(int a, int b) { return a * b + 426; }
#pragma optimize("", on)

TEST(VEHHookTest, HookFunction) {
  bool called = false;
  auto handler = blook::VEHHookManager::instance().add_breakpoint(
      blook::VEHHookManager::HardwareBreakpoint{
          .address = (void *)veh_test_target_func},
      [&](blook::VEHHookManager::VEHHookContext &ctx) { called = true; });

  ASSERT_TRUE(
      std::holds_alternative<blook::VEHHookManager::HardwareBreakpointHandler>(
          handler));

  veh_test_target_func(3, 5);

  ASSERT_TRUE(called);

  blook::VEHHookManager::instance().remove_breakpoint(handler);

  auto result = veh_test_target_func(2, 4);
  EXPECT_EQ(result, 2 * 4 + 42);
}

TEST(VEHHookTest, HookFunctionInAnotherThread) {
  bool called = false;
  auto handler = blook::VEHHookManager::instance().add_breakpoint(
      blook::VEHHookManager::HardwareBreakpoint{
          .address = (void *)veh_test_target_func},
      [&](blook::VEHHookManager::VEHHookContext &ctx) {
        called = true;
        ExitThread(0);
      });

  ASSERT_TRUE(
      std::holds_alternative<blook::VEHHookManager::HardwareBreakpointHandler>(
          handler));

  std::thread t([]() {
    while (true) {
      veh_test_target_func(7, 8);
    }
  });
  blook::VEHHookManager::instance().sync_hw_breakpoints();
  t.join();

  ASSERT_TRUE(called);

  blook::VEHHookManager::instance().remove_breakpoint(handler);
}

TEST(VEHHookTest, HookMultipleFunctions) {
  bool called1 = false;
  bool called2 = false;
  bool called3 = false;
  bool called4 = false;

  auto handler1 = blook::VEHHookManager::instance().add_breakpoint(
      blook::VEHHookManager::HardwareBreakpoint{
          .address = (void *)veh_test_target_func},
      [&](blook::VEHHookManager::VEHHookContext &ctx) { called1 = true; });

  auto handler2 = blook::VEHHookManager::instance().add_breakpoint(
      blook::VEHHookManager::HardwareBreakpoint{
          .address = (void *)veh_test_target_func2},
      [&](blook::VEHHookManager::VEHHookContext &ctx) { called2 = true; });

  auto handler3 = blook::VEHHookManager::instance().add_breakpoint(
      blook::VEHHookManager::HardwareBreakpoint{
          .address = (void *)veh_test_target_func3},
      [&](blook::VEHHookManager::VEHHookContext &ctx) { called3 = true; });

  auto handler4 = blook::VEHHookManager::instance().add_breakpoint(
      blook::VEHHookManager::HardwareBreakpoint{
          .address = (void *)veh_test_target_func4},
      [&](blook::VEHHookManager::VEHHookContext &ctx) { called4 = true; });

  ASSERT_TRUE(
      std::holds_alternative<blook::VEHHookManager::HardwareBreakpointHandler>(
          handler1));
  ASSERT_TRUE(
      std::holds_alternative<blook::VEHHookManager::HardwareBreakpointHandler>(
          handler2));
  ASSERT_TRUE(
      std::holds_alternative<blook::VEHHookManager::HardwareBreakpointHandler>(
          handler3));
  ASSERT_TRUE(
      std::holds_alternative<blook::VEHHookManager::HardwareBreakpointHandler>(
          handler4));

  veh_test_target_func(3, 5);
  veh_test_target_func2(6, 7);
  veh_test_target_func3(8, 9);
  veh_test_target_func4(10, 11);

  ASSERT_TRUE(called1);
  ASSERT_TRUE(called2);
  ASSERT_TRUE(called3);
  ASSERT_TRUE(called4);

  blook::VEHHookManager::instance().remove_breakpoint(handler1);
  blook::VEHHookManager::instance().remove_breakpoint(handler2);
  blook::VEHHookManager::instance().remove_breakpoint(handler3);
  blook::VEHHookManager::instance().remove_breakpoint(handler4);
  called1 = called2 = called3 = called4 = false;
  veh_test_target_func(2, 4);
  veh_test_target_func2(3, 5);
  veh_test_target_func3(4, 6);
  veh_test_target_func4(5, 7);
  EXPECT_EQ(veh_test_target_func(2, 4), 2 * 4 + 42);
  EXPECT_EQ(veh_test_target_func2(3, 5), 3 * 5 + 423);
  EXPECT_EQ(veh_test_target_func3(4, 6), 4 * 6 + 412);
  EXPECT_EQ(veh_test_target_func4(5, 7), 5 * 7 + 426);
  ASSERT_FALSE(called1);
  ASSERT_FALSE(called2);
  ASSERT_FALSE(called3);
  ASSERT_FALSE(called4);
}

TEST(VEHHookTest, SoftwareBreakpoint) {
  bool called = false;
  auto handler = blook::VEHHookManager::instance().add_breakpoint(
      blook::VEHHookManager::SoftwareBreakpoint{
          .address = (void *)veh_test_target_func},
      [&](blook::VEHHookManager::VEHHookContext &ctx) { called = true; });

  ASSERT_TRUE(
      std::holds_alternative<blook::VEHHookManager::SoftwareBreakpointHandler>(
          handler));

  veh_test_target_func(3, 5);

  ASSERT_TRUE(called);

  blook::VEHHookManager::instance().remove_breakpoint(handler);

  called = false;
  auto result = veh_test_target_func(2, 4);
  EXPECT_EQ(result, 2 * 4 + 42);
  ASSERT_FALSE(called);
}

// TEST(VEHHookTest, PagefaultBreakpoint) {
//     bool called = false;
//     auto handler = blook::VEHHookManager::instance().add_breakpoint(
//         blook::VEHHookManager::PagefaultBreakpoint{
//             .address = (void *)veh_test_target_func},
//         [&](blook::VEHHookManager::VEHHookContext &ctx) { called = true; });

//     ASSERT_TRUE(
//         std::holds_alternative<blook::VEHHookManager::PagefaultBreakpointHandler>(
//             handler));

//     veh_test_target_func(3, 5);

//     ASSERT_TRUE(called);

//     blook::VEHHookManager::instance().remove_breakpoint(handler);

//     called = false;
//     auto result = veh_test_target_func(2, 4);
//     EXPECT_EQ(result, 2 * 4 + 42);
//     ASSERT_FALSE(called);
// }

#pragma optimize("", off)
[[clang::noinline]] [[gnu::noinline]] [[msvc::noinline]]
int test_reassembly_target(int a, int b) {
  return a + b;
}

// External assembly functions for testing
extern "C" {
int asm_add_function(int a, int b);
void asm_counter_function(int increment_by);
extern volatile int g_trampoline_counter;
}

// Define the global counter
volatile int g_trampoline_counter = 0;

#pragma optimize("", on)

TEST(BlookReassemblyTests, RangeNextInstr) {
  using namespace blook;

  // Test range_next_instr with a simple function
  Pointer func_ptr = (void *)test_reassembly_target;

  // Test try_range_next_instr
  auto range1_result = func_ptr.try_range_next_instr(1);
  ASSERT_TRUE(range1_result.has_value()) << range1_result.error();
  auto range1 = *range1_result;
  EXPECT_GT(range1.size(), 0);

  // Test range_next_instr (throwing version)
  auto range1_throw = func_ptr.range_next_instr(1);
  EXPECT_EQ(range1.size(), range1_throw.size());

  // Get the first 3 instructions
  auto range3_result = func_ptr.try_range_next_instr(3);
  ASSERT_TRUE(range3_result.has_value()) << range3_result.error();
  auto range3 = *range3_result;
  EXPECT_GT(range3.size(), range1.size());

  // Verify we can disassemble the range
  auto disasm = range3.disassembly();
  int count = 0;
  for (const auto &instr : disasm) {
    count++;
  }
  EXPECT_GE(count, 3);

  // Test with 0 instructions
  auto range0_result = func_ptr.try_range_next_instr(0);
  ASSERT_TRUE(range0_result.has_value());
  EXPECT_EQ(range0_result->size(), 0);

  // Test that range_next_instr works correctly for basic usage
  auto range2 = func_ptr.range_next_instr(2);
  EXPECT_GT(range2.size(), 0);
  EXPECT_LT(range2.size(), range3.size());

  // Test error case - try to get too many instructions
  auto invalid_ptr = Pointer((void *)0x1000);
  auto range_invalid = invalid_ptr.try_range_next_instr(100);
  EXPECT_FALSE(range_invalid.has_value());
}

TEST(BlookReassemblyTests, ReassemblyWithPadding) {
  using namespace blook;

  // Allocate executable memory for testing
  auto proc = Process::self();
  auto mem = proc->malloc(64, Protect::rwx);
  ASSERT_NE((void*)mem, nullptr);

  // Write some original code (just NOPs for testing)
  Pointer ptr = mem;
  std::vector<uint8_t> original_code(64, 0x90); // Fill with NOPs
  ptr.write_bytearray(original_code);

  // Create a range and reassemble with smaller code
  MemoryRange range(ptr, 20);
  auto patch_result =
      range.try_reassembly_with_padding([](zasm::x86::Assembler& a) {
        // Generate a small piece of code (2 bytes: ret)
        a.ret();
      });

  ASSERT_TRUE(patch_result.has_value()) << patch_result.error();

  // Apply the patch
  auto &patch = *patch_result;
  ASSERT_TRUE(patch.patch());

  // Verify the first byte is 0xC3 (ret)
  EXPECT_EQ(ptr.read_u8(), 0xC3);

  // Verify the rest is padded with NOPs (0x90)
  for (size_t i = 1; i < 20; i++) {
    EXPECT_EQ(ptr.add(i).read_u8(), 0x90)
        << "Byte at offset " << i << " should be NOP";
  }

  // Restore and cleanup
  patch.restore();
  proc->free(mem);
}

TEST(BlookReassemblyTests, ReassemblyWithPaddingTooLarge) {
  using namespace blook;

  // Allocate executable memory
  auto proc = Process::self();
  auto mem = proc->malloc(64, Protect::rwx);
  ASSERT_NE((void*)mem, nullptr);

  Pointer ptr = mem;

  // Create a small range and try to fit too much code
  MemoryRange range(ptr, 5);
  auto patch_result =
      range.try_reassembly_with_padding([](zasm::x86::Assembler& a) {
        // Generate code that's definitely larger than 5 bytes
        if constexpr (blook::utils::compileArchitecture() ==
                      blook::utils::Architecture::x86_64) {
          a.push(zasm::x86::rax);
          a.push(zasm::x86::rbx);
          a.push(zasm::x86::rcx);
          a.push(zasm::x86::rdx);
          a.pop(zasm::x86::rdx);
          a.pop(zasm::x86::rcx);
          a.pop(zasm::x86::rbx);
          a.pop(zasm::x86::rax);
        } else {
          a.push(zasm::x86::eax);
          a.push(zasm::x86::ebx);
          a.push(zasm::x86::ecx);
          a.push(zasm::x86::edx);
          a.pop(zasm::x86::edx);
          a.pop(zasm::x86::ecx);
          a.pop(zasm::x86::ebx);
          a.pop(zasm::x86::eax);
        }
      });

  // Should fail because code is too large
  EXPECT_FALSE(patch_result.has_value());

  proc->free(mem);
}

TEST(BlookReassemblyTests, ReassemblyWithTrampoline) {
  using namespace blook;

  // Test 1: Verify asm_add_function works correctly before patching
  EXPECT_EQ(asm_add_function(10, 20), 30);
  EXPECT_EQ(asm_add_function(5, 7), 12);

  // Test 2: Disassemble the original function to understand its structure
  Pointer func_ptr = (void *)asm_add_function;
  auto original_bytes = func_ptr.read_bytearray(20);

  // Test 3: Apply trampoline with user code that sets eax before original code
  auto patch_result =
      func_ptr.try_reassembly_with_trampoline([](zasm::x86::Assembler& a) {
        a.mov(zasm::x86::ecx, zasm::Imm(999));
      });
  ASSERT_TRUE(patch_result.has_value()) << patch_result.error();
  ASSERT_TRUE(patch_result->patch());

  EXPECT_EQ(asm_add_function(10, 20), 999 + 20)
      << "Trampoline should execute user code and return 999";
  EXPECT_EQ(asm_add_function(5, 7), 999 + 7);

  // Test 6: Verify the original location has been modified (should have a jump)
  auto patched_bytes = func_ptr.read_bytearray(20);
  EXPECT_NE(original_bytes, patched_bytes)
      << "Original code should be modified";

  // Test 7: Restore and verify
  patch_result->restore();

  EXPECT_EQ(asm_add_function(10, 20), 30);

  // Test 8: Verify bytes are restored
  auto restored_bytes = func_ptr.read_bytearray(20);
  EXPECT_EQ(original_bytes, restored_bytes)
      << "Original code should be restored";
}

TEST(BlookReassemblyTests, ReassemblyWithTrampolineCounterFunction) {
  using namespace blook;

  // Test 1: Verify asm_counter_function works correctly before patching
  Pointer counter_ptr = (void *)asm_counter_function;

  g_trampoline_counter = 100;
  asm_counter_function(5);
  EXPECT_EQ(g_trampoline_counter, 105);

  g_trampoline_counter = 200;
  asm_counter_function(10);
  EXPECT_EQ(g_trampoline_counter, 210);

  // Test 2: Read original bytes
  auto original_bytes = counter_ptr.read_bytearray(20);

  // Test 3: Apply trampoline that modifies the increment_by parameter
  auto patch_result =
      counter_ptr.try_reassembly_with_trampoline([](zasm::x86::Assembler& a) {
        // Modify the first parameter (increment_by) to 999
        a.mov(zasm::x86::ecx, zasm::Imm(999));
      });

  ASSERT_TRUE(patch_result.has_value()) << patch_result.error();
  ASSERT_TRUE(patch_result->patch());

  // Test 4: Verify trampoline modifies parameter
  g_trampoline_counter = 100;
  asm_counter_function(5);  // Pass 5, but trampoline changes it to 999
  EXPECT_EQ(g_trampoline_counter, 1099)
      << "Trampoline should change increment to 999";

  g_trampoline_counter = 200;
  asm_counter_function(10);  // Pass 10, but trampoline changes it to 999
  EXPECT_EQ(g_trampoline_counter, 1199);

  // Test 5: Verify bytes were modified
  auto patched_bytes = counter_ptr.read_bytearray(20);
  EXPECT_NE(original_bytes, patched_bytes)
      << "Original code should be modified";

  // Test 6: Restore and verify
  patch_result->restore();

  g_trampoline_counter = 100;
  asm_counter_function(5);
  EXPECT_EQ(g_trampoline_counter, 105);

  // Test 7: Verify bytes are restored
  auto restored_bytes = counter_ptr.read_bytearray(20);
  EXPECT_EQ(original_bytes, restored_bytes)
      << "Original code should be restored";
}

TEST(BlookMemoryTests, PatternParsing) {
  auto process = blook::Process::self();
  ASSERT_NE(process, nullptr);

  const uint8_t test_data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
  auto range = blook::MemoryRange(process, (void*)test_data, sizeof(test_data));

  EXPECT_TRUE(range.find_one_pattern("aabbcc").has_value());
  EXPECT_TRUE(range.find_one_pattern("aa bb cc").has_value());
  EXPECT_TRUE(range.find_one_pattern("aa,bb,cc").has_value());
  EXPECT_TRUE(range.find_one_pattern("0xaa, 0xbb, 0xcc").has_value());
  EXPECT_TRUE(range.find_one_pattern("AABBCC").has_value());
  EXPECT_TRUE(range.find_one_pattern("AA BB CC DD").has_value());

  EXPECT_FALSE(range.find_one_pattern("12 34 56").has_value());

  EXPECT_TRUE(range.find_one_pattern("eeff").has_value());
  EXPECT_TRUE(range.find_one_pattern("ff1122").has_value());
  EXPECT_TRUE(range.find_one_pattern("aa??cc").has_value());
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}