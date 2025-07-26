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
  auto final_ptr_opt = ptr.offsets({0x23, 0x12, 0x4});

  ASSERT_TRUE(final_ptr_opt.has_value());
  auto value_opt = final_ptr_opt.value().try_read<size_t>();

  ASSERT_TRUE(value_opt.has_value());
  EXPECT_EQ(value_opt.value(), 114514);

  delete s.slot[0x23].s->slot[0x12].s;
  delete s.slot[0x23].s;
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

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}