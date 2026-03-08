# blook 中文文档

## 目录

- [简介](#简介)
- [快速开始](#快速开始)
- [核心概念](#核心概念)
- [API 参考](#api-参考)
  - [Process - 进程管理](#process---进程管理)
  - [Module - 模块管理](#module---模块管理)
  - [Pointer - 指针操作](#pointer---指针操作)
  - [MemoryRange - 内存范围](#memoryrange---内存范围)
  - [Function - 函数转换](#function---函数转换)
  - [InlineHook - 内联钩子](#inlinehook---内联钩子)
  - [VEHHookManager - VEH 钩子](#vehhookmanager---veh-钩子)
  - [ProcessAllocator - 内存分配器](#processallocator---内存分配器)
  - [Disassembly - 反汇编](#disassembly---反汇编)
  - [Thread - 线程管理](#thread---线程管理)
- [高级用法](#高级用法)
- [示例](#示例)

## 简介

blook 是一个现代化的 C++ 库，用于 Windows 平台上的内存操作、函数钩子和进程分析。它提供了简洁的 API 来完成复杂的底层操作。

### 主要特性

- **内联钩子 (Inline Hook)**: 轻松钩住任意函数，支持 trampoline
- **VEH 钩子**: 硬件断点、软件断点、页面错误断点
- **内存扫描**: 支持 AOB (Array of Bytes) 模式匹配，包括通配符
- **反汇编**: 基于 Zydis 的指令反汇编和分析
- **交叉引用 (XRef)**: 查找代码中的引用关系
- **代码重组装 (Reassembly)**: 动态修改代码，支持 padding 和 trampoline
- **进程/模块管理**: 枚举模块、导出函数、节区等
- **线程操作**: 线程枚举、上下文捕获和修改
- **类型安全的内存读写**: 支持各种基本类型和结构体
- **智能内存分配器**: 高效的内存分配和管理

### 支持平台

- Windows x86/x64 ✅
- Linux (开发中) 🚧

## 快速开始

### 安装

#### 方式 1: CMake 子模块

```bash
git submodule add https://github.com/MicroCBer/blook
git submodule update --init --recursive
```

在 `CMakeLists.txt` 中添加:

```cmake
add_subdirectory(external/blook)
target_link_libraries(your_target blook)
```

#### 方式 2: CMake FetchContent

```cmake
include(FetchContent)

FetchContent_Declare(
    blook
    GIT_REPOSITORY https://github.com/MicroCBer/blook
    GIT_TAG origin/main
)
FetchContent_MakeAvailable(blook)

target_link_libraries(your_target blook)
```

#### 方式 3: xmake

```lua
add_requires("blook")
target("your_target")
    add_packages("blook")
```

### 第一个示例

```cpp
#include <blook/blook.h>

int main() {
    // 获取当前进程
    auto process = blook::Process::self();

    // 获取 user32.dll 模块
    auto user32 = process->module("user32.dll").value();

    // 获取 MessageBoxA 函数
    auto msgbox = user32->exports("MessageBoxA").value();

    // 创建内联钩子
    auto hook = msgbox->inline_hook();

    // 安装钩子，修改消息内容
    hook->install([=](int64_t a, char* text, char* title, int64_t b) {
        return hook->call_trampoline<int64_t>(a, "被钩住了!", title, b);
    });

    // 调用 MessageBoxA，会显示修改后的内容
    MessageBoxA(nullptr, "原始消息", "标题", 0);

    // 卸载钩子
    hook->uninstall();

    return 0;
}
```

## 核心概念

### 进程 (Process)

`Process` 类代表一个进程，可以是当前进程或远程进程。它提供了内存操作、模块枚举等功能。

### 模块 (Module)

`Module` 类代表一个加载的 DLL 或可执行文件，可以访问其导出函数、节区等。

### 指针 (Pointer)

`Pointer` 类是对内存地址的封装，提供了类型安全的读写操作。

### 内存范围 (MemoryRange)

`MemoryRange` 继承自 `Pointer`，表示一段连续的内存区域，支持迭代、搜索等操作。

### 函数 (Function)

`Function` 类封装了函数指针，提供了将 lambda、std::function 转换为函数指针的能力。

## API 参考

### Process - 进程管理

#### 创建进程对象

```cpp
// 获取当前进程
auto proc = blook::Process::self();

// 通过进程 ID 附加
auto proc = blook::Process::attach(1234);

// 通过进程名附加
auto proc = blook::Process::attach("notepad.exe");

// 通过进程名附加，跳过前 N 个匹配
auto proc = blook::Process::attach("chrome.exe", 2); // 跳过前 2 个
```

#### 内存操作

```cpp
auto proc = blook::Process::self();

// 分配内存
auto ptr = proc->malloc(1024, blook::Protect::rw);

// 分配可执行内存
auto code_ptr = proc->malloc(1024, blook::Protect::rwx);

// 在指定地址附近分配内存（用于相对跳转）
auto near_ptr = proc->malloc(1024, blook::Protect::rwx, (void*)0x10000000);

// 释放内存
proc->free(ptr);

// 读取内存
int value;
proc->read(&value, some_address, sizeof(int));

// 写入内存
int new_value = 42;
proc->write(some_address, &new_value, sizeof(int));

// 检查内存是否可读
bool readable = proc->check_readable(some_address, 100);

// 检查内存是否可写
bool writable = proc->check_writable(some_address, 100);

// 检查地址是否有效
bool valid = proc->check_valid(some_address);

// 修改内存保护属性
auto old_protect = proc->set_memory_protect(
    some_address,
    100,
    blook::Protect::rwx
);
```

#### 模块枚举

```cpp
auto proc = blook::Process::self();

// 获取主模块（当前 DLL 或 EXE）
auto main_mod = proc->module().value();

// 获取进程模块（EXE）
auto exe_mod = proc->process_module().value();

// 通过名称获取模块（大小写不敏感）
auto kernel32 = proc->module("kernel32.dll").value();
auto user32 = proc->module("USER32.DLL").value();

// 枚举所有模块
auto modules = proc->modules();
for (auto& [name, mod] : modules) {
    std::cout << "模块: " << name << std::endl;
}
```

#### 线程操作

```cpp
auto proc = blook::Process::self();

// 获取所有线程
auto threads = proc->threads();
for (auto& thread : threads) {
    std::cout << "线程 ID: " << thread.id << std::endl;
}
```

#### 内存分配器

```cpp
auto proc = blook::Process::self();

// 获取进程的内存分配器
auto& allocator = proc->allocator();

// 分配内存
auto ptr = allocator.allocate(1024);

// 在指定地址附近分配
auto near_ptr = allocator.allocate(512, some_address);

// 释放内存
allocator.deallocate(ptr);

// 获取统计信息
size_t count = allocator.allocated_count();
size_t bytes = allocator.total_allocated_bytes();
size_t reserved = allocator.total_reserved_bytes();
```

### Module - 模块管理

#### 获取模块信息

```cpp
auto proc = blook::Process::self();
auto mod = proc->module("kernel32.dll").value();

// 获取模块基址
auto base = mod->base();

// 获取模块大小
size_t size = mod->size();

// 获取模块内存范围
auto range = mod->memo();
```

#### 导出函数

```cpp
auto mod = proc->module("user32.dll").value();

// 获取单个导出函数
auto msgbox = mod->exports("MessageBoxA");
if (msgbox.has_value()) {
    void* func_ptr = msgbox->data();
}

// 尝试多个名称（返回第一个找到的）
auto func = mod->exports("FuncName1", "FuncName2", "FuncName3");

// 枚举所有导出函数
auto exports = mod->obtain_exports();
for (auto& [name, func] : *exports) {
    std::cout << "导出: " << name << std::endl;
}
```

#### 节区 (Section)

```cpp
auto mod = proc->module().value();

// 获取代码段
auto text = mod->section(".text").value();

// 获取只读数据段
auto rdata = mod->section(".rdata").value();

// 获取数据段
auto data = mod->section(".data").value();

// 在节区中搜索
auto result = text.find_one({0x48, 0x89, 0x5C, 0x24});
```

#### 入口点

```cpp
auto mod = proc->module().value();

// 获取模块入口点
auto entry = mod->entry_point();
if (entry.has_value()) {
    void* entry_addr = entry->data();
}
```

### Pointer - 指针操作

#### 创建指针

```cpp
// 从地址创建
blook::Pointer ptr = (void*)0x12345678;

// 从进程和地址创建
auto proc = blook::Process::self();
blook::Pointer ptr(proc, (void*)0x12345678);

// 从 size_t 创建
blook::Pointer ptr(proc, 0x12345678);
```

#### 基本读写操作

```cpp
blook::Pointer ptr = some_address;

// 读取基本类型
int8_t   v1 = ptr.read_s8();
int16_t  v2 = ptr.read_s16();
int32_t  v3 = ptr.read_s32();
int64_t  v4 = ptr.read_s64();
uint8_t  v5 = ptr.read_u8();
uint16_t v6 = ptr.read_u16();
uint32_t v7 = ptr.read_u32();
uint64_t v8 = ptr.read_u64();
float    v9 = ptr.read_float();
double   v10 = ptr.read_double();

// 写入基本类型
ptr.write_s32(42);
ptr.write_float(3.14f);
ptr.write_u64(0xDEADBEEF);

// 读取指针
blook::Pointer target = ptr.read_pointer();

// 写入指针
ptr.write_pointer(target);
```

#### 结构体读写

```cpp
struct MyStruct {
    int a;
    float b;
    char c[10];
};

blook::Pointer ptr = &my_struct;

// 读取结构体
MyStruct s = ptr.read_struct<MyStruct>();

// 写入结构体
MyStruct new_s = {1, 2.0f, "hello"};
ptr.write_struct(new_s);
```

#### 字节数组操作

```cpp
blook::Pointer ptr = some_address;

// 读取字节数组
std::vector<uint8_t> bytes = ptr.read_bytearray(100);

// 写入字节数组
std::vector<uint8_t> data = {0x90, 0x90, 0x90};
ptr.write_bytearray(data);

// 从 string_view 写入
ptr.write_bytearray("hello");

// 从 wstring_view 写入
ptr.write_bytearray(L"hello");
```

#### 字符串操作

```cpp
blook::Pointer ptr = some_address;

// 读取 UTF-8 字符串
std::string str = ptr.read_utf8_string();

// 读取指定长度的 UTF-8 字符串
std::string str = ptr.read_utf8_string(20);

// 读取 UTF-16 字符串
std::wstring wstr = ptr.read_utf16_string();

// 写入 UTF-8 字符串
ptr.write_utf8_string("Hello, World!");

// 写入 UTF-16 字符串
ptr.write_utf16_string(L"你好，世界！");
```

#### Try 版本（错误处理）

所有读写操作都有 `try_` 前缀的版本，返回 `std::expected`：

```cpp
blook::Pointer ptr = some_address;

// Try 版本返回 expected
auto result = ptr.try_read_s32();
if (result.has_value()) {
    int value = *result;
} else {
    std::cerr << "读取失败: " << result.error() << std::endl;
}

// Try 版本的写入
auto write_result = ptr.try_write_s32(42);
if (!write_result) {
    std::cerr << "写入失败: " << write_result.error() << std::endl;
}
```

#### 指针运算

```cpp
blook::Pointer ptr = some_address;

// 加法
auto ptr2 = ptr + 0x10;
auto ptr3 = ptr.add(0x20);

// 减法
auto ptr4 = ptr - 0x10;
auto ptr5 = ptr.sub(0x20);

// 复合赋值
ptr += 0x10;
ptr -= 0x20;

// 比较
if (ptr1 == ptr2) { }
if (ptr1 < ptr2) { }
if (ptr == nullptr) { }
```

#### 多级指针偏移

```cpp
// 假设有这样的结构: base -> [0x10] -> [0x20] -> [0x30] -> value
blook::Pointer base = some_address;

// 一次性解引用多级指针
auto final = base.offsets({0x10, 0x20, 0x30});
if (final.has_value()) {
    int value = final->read_s32();
}

// 自定义缩放因子（默认是 sizeof(void*)）
auto final2 = base.offsets({0x10, 0x20}, 1); // 不缩放
```

#### 内存分配

```cpp
blook::Pointer ptr = some_address;

// 分配内存
auto new_ptr = ptr.malloc(1024);

// 分配可执行内存
auto code_ptr = ptr.malloc(1024, blook::Protect::rwx);

// 在当前地址附近分配可执行内存
auto near_code = ptr.malloc_rx_near_this(1024);

// 释放内存
ptr.free();
```

#### 转换为函数

```cpp
blook::Pointer ptr = some_function_address;

// 转换为 Function 对象
auto func = ptr.as_function();

// 创建内联钩子
auto hook = func.inline_hook();
```

#### 有效性检查

```cpp
blook::Pointer ptr = some_address;

// 检查指针是否有效（地址是否已提交）
if (ptr.is_valid()) {
    // 可以安全访问
}

// 检查是否指向当前进程
if (ptr.is_self()) {
    // 是当前进程的地址
}
```

### MemoryRange - 内存范围

#### 创建内存范围

```cpp
auto proc = blook::Process::self();

// 从指针和大小创建
blook::Pointer ptr = some_address;
blook::MemoryRange range(ptr, 1024);

// 使用 Pointer 的辅助方法
auto range = ptr.range_size(1024);
auto range2 = ptr.range_to(end_ptr);

// 从指令数量创建范围
auto range3 = ptr.range_next_instr(5); // 覆盖接下来的 5 条指令
```

#### 模式搜索 (AOB)

```cpp
blook::MemoryRange range = some_range;

// 搜索字节模式
auto result = range.find_one({0x48, 0x89, 0x5C, 0x24, 0x08});

// 使用通配符（ANYPattern）
using ANY = blook::memory_scanner::ANYPattern;
auto result = range.find_one({
    0x48, 0x89, ANY, 0x24, 0x08,
    0x48, 0x89, 0x74, 0x24, ANY
});

// 搜索字符串
auto result = range.find_one("Hello, World!");

// 搜索多个模式（返回第一个匹配）
auto result = range.find_one({
    {0x48, 0x89, 0x5C},
    {0x55, 0x8B, 0xEC},
    {0x40, 0x53, 0x48}
});

// 搜索并偏移
auto result = range.find_one(
    std::make_pair(
        std::vector<uint8_t>{0x48, 0x89, 0x5C},
        0x10  // 找到后偏移 0x10
    )
);

// 远程进程搜索（使用 ReadProcessMemory）
auto result = range.find_one_remote({0x90, 0x90, 0x90});
```

#### 交叉引用 (XRef)

```cpp
blook::MemoryRange code_section = text_section;
blook::Pointer target = some_string_address;

// 在代码段中查找引用了 target 的指令
auto xref = code_section.find_xref(target);
if (xref.has_value()) {
    std::cout << "找到引用: " << xref->data() << std::endl;
}
```

#### 迭代内存

```cpp
blook::MemoryRange range = some_range;

// 使用范围 for 循环
for (uint8_t byte : range) {
    std::cout << std::hex << (int)byte << " ";
}

// 使用迭代器
auto it = range.begin();
auto end = range.end();
while (it != end) {
    uint8_t byte = *it;
    ++it;
}

// 检查是否可读
auto it = range.begin();
if (it.is_readable()) {
    uint8_t byte = *it;
}
```

#### CRC32 计算

```cpp
blook::MemoryRange range = some_range;

// 计算 CRC32
int32_t crc = range.crc32();
```

### Function - 函数转换

#### Lambda 转函数指针

blook 提供了将 lambda（包括捕获 lambda）转换为函数指针的能力：

```cpp
// 普通 lambda（无捕获）
auto func_ptr = blook::Function::into_function_pointer(
    [](int a, int b) { return a + b; }
);
int result = func_ptr(10, 20); // 30

// 捕获 lambda
int multiplier = 100;
auto func_ptr2 = blook::Function::into_function_pointer(
    [=](int a, int b) { return a + b + multiplier; }
);
int result2 = func_ptr2(10, 20); // 130

// std::function 转函数指针
std::function<int(int, int)> fn = [](int a, int b) { return a * b; };
auto func_ptr3 = blook::Function::into_function_pointer(std::move(fn));
```

#### 安全函数指针

安全函数指针会保存和恢复寄存器，避免污染调用者的寄存器状态：

```cpp
void my_function(int a, int b) {
    // 函数实现
}

// 创建安全函数指针（非线程安全）
auto safe_func = blook::Function::into_safe_function_pointer(
    my_function,
    false  // thread_safety
);

// 创建线程安全的安全函数指针
auto safe_func_ts = blook::Function::into_safe_function_pointer(
    my_function,
    true  // thread_safety
);

// Lambda 也可以
auto safe_lambda = blook::Function::into_safe_function_pointer(
    [](int a) { return a * 2; },
    true
);
```

### InlineHook - 内联钩子

#### 基本用法

```cpp
// 获取要钩住的函数
auto proc = blook::Process::self();
auto kernel32 = proc->module("kernel32.dll").value();
auto get_tick = kernel32->exports("GetTickCount64").value();

// 创建钩子
auto hook = get_tick->inline_hook();

// 安装钩子
hook->install([=]() -> ULONGLONG {
    // 返回假的时间
    return 114514;
});

// 现在调用 GetTickCount64() 会返回 114514
ULONGLONG tick = GetTickCount64();

// 卸载钩子
hook->uninstall();

// 现在恢复正常
tick = GetTickCount64();
```

#### 使用 Trampoline

Trampoline 允许你在钩子函数中调用原始函数：

```cpp
auto hook = some_function->inline_hook();

hook->install([=](int a, int b) -> int {
    std::cout << "函数被调用: " << a << ", " << b << std::endl;

    // 调用原始函数
    int result = hook->call_trampoline<int>(a, b);

    std::cout << "原始返回值: " << result << std::endl;

    // 可以修改返回值
    return result * 2;
});
```

#### 钩住本地函数

```cpp
int MyFunction(int a, int b) {
    return a + b;
}

int main() {
    // 从函数地址创建钩子
    blook::Pointer ptr = (void*)MyFunction;
    auto hook = ptr.as_function().inline_hook();

    // 安装钩子，改变行为
    hook->install([=](int a, int b) -> int {
        return a * b;  // 改成乘法
    });

    // 现在 MyFunction 会执行乘法
    int result = MyFunction(10, 5); // 返回 50

    // 但可以通过 trampoline 调用原始版本
    int original = hook->call_trampoline<int>(10, 5); // 返回 15

    hook->uninstall();
    return 0;
}
```

#### 钩住 Windows API

```cpp
auto proc = blook::Process::self();
auto user32 = proc->module("user32.dll").value();
auto msgbox = user32->exports("MessageBoxA").value();

auto hook = msgbox->inline_hook();

hook->install([=](HWND hwnd, LPCSTR text, LPCSTR title, UINT type) -> int {
    // 修改消息内容
    return hook->call_trampoline<int>(
        hwnd,
        "内容被修改了！",
        "标题被修改了！",
        type
    );
});

// 所有 MessageBoxA 调用都会被拦截
MessageBoxA(nullptr, "原始内容", "原始标题", MB_OK);
```

#### 批量钩住导出函数

```cpp
auto proc = blook::Process::self();
auto mod = proc->module("user32.dll").value();

// 获取所有导出函数
auto exports = mod->obtain_exports();

std::vector<std::shared_ptr<blook::InlineHook>> hooks;

for (auto& [name, func] : *exports) {
    auto hook = func.inline_hook();

    hook->install([=](int64_t a) -> int64_t {
        std::cout << "调用了: " << name << std::endl;
        return hook->call_trampoline<int64_t>(a);
    });

    hooks.push_back(std::move(hook));
}

// 清理
for (auto& hook : hooks) {
    hook->uninstall();
}
```

### VEHHookManager - VEH 钩子

VEH (Vectored Exception Handler) 钩子使用异常处理机制实现钩子，支持硬件断点、软件断点和页面错误断点。

#### 硬件断点

硬件断点使用 CPU 的调试寄存器（DR0-DR3），最多支持 4 个：

```cpp
bool called = false;

// 添加硬件断点
auto handler = blook::VEHHookManager::instance().add_breakpoint(
    blook::VEHHookManager::HardwareBreakpoint{
        .address = (void*)some_function,
        .dr_index = -1,  // 自动选择
        .size = 1,
        .when = blook::HwBp::When::Executed
    },
    [&](blook::VEHHookManager::VEHHookContext& ctx) {
        called = true;
        // 可以访问异常上下文
        // ctx.exception_info
    }
);

// 调用函数会触发断点
some_function();

// 移除断点
blook::VEHHookManager::instance().remove_breakpoint(handler);
```

#### 软件断点

软件断点通过修改代码为 `0xCC` (INT3) 实现：

```cpp
auto handler = blook::VEHHookManager::instance().add_breakpoint(
    blook::VEHHookManager::SoftwareBreakpoint{
        .address = (void*)some_function
    },
    [&](blook::VEHHookManager::VEHHookContext& ctx) {
        std::cout << "软件断点触发！" << std::endl;
    }
);

some_function();

blook::VEHHookManager::instance().remove_breakpoint(handler);
```

#### 多线程同步

对于硬件断点，需要同步到所有线程：

```cpp
auto handler = blook::VEHHookManager::instance().add_breakpoint(
    blook::VEHHookManager::HardwareBreakpoint{
        .address = (void*)some_function
    },
    [&](auto& ctx) { /* ... */ }
);

// 同步到所有线程
blook::VEHHookManager::instance().sync_hw_breakpoints();

// 现在所有线程都会触发断点
```

### ProcessAllocator - 内存分配器

ProcessAllocator 提供了高效的内存分配管理，支持页面重用和近地址分配。

#### 基本分配

```cpp
auto proc = blook::Process::self();
auto& allocator = proc->allocator();

// 分配内存
auto ptr = allocator.allocate(1024);

// 分配可执行内存
auto code_ptr = allocator.allocate(1024, nullptr, blook::Protect::rwx);

// 释放内存
allocator.deallocate(ptr);
```

#### 近地址分配

用于需要相对跳转的场景（32 位偏移限制在 ±2GB）：

```cpp
auto& allocator = proc->allocator();

// 在某个地址附近分配
void* near_addr = (void*)0x140000000;
auto ptr = allocator.allocate(1024, near_addr);

// 验证距离
int64_t distance = std::abs((int64_t)ptr.data() - (int64_t)near_addr);
// distance < 2GB
```

#### 统计信息

```cpp
auto& allocator = proc->allocator();

// 当前分配的块数
size_t count = allocator.allocated_count();

// 已分配的总字节数
size_t allocated = allocator.total_allocated_bytes();

// 已保留的总字节数（包括未使用的）
size_t reserved = allocator.total_reserved_bytes();
```

#### Try 版本

```cpp
auto& allocator = proc->allocator();

// Try 版本返回 expected
auto result = allocator.try_allocate(1024);
if (result.has_value()) {
    auto ptr = *result;
    // 使用 ptr
    allocator.deallocate(ptr);
} else {
    std::cerr << "分配失败: " << result.error() << std::endl;
}
```

### Disassembly - 反汇编

#### 反汇编内存范围

```cpp
blook::Pointer func_ptr = (void*)some_function;
auto range = func_ptr.range_size(100);

// 获取反汇编迭代器
auto disasm = range.disassembly();

// 遍历指令
for (const auto& instr : disasm) {
    // 获取指令地址
    auto addr = instr.ptr();

    // 获取指令详情
    auto detail = *instr;

    // 打印指令
    std::cout << instr.dump() << std::endl;

    // 获取指令引用的地址
    auto xrefs = instr.xrefs();
    for (auto& xref : xrefs) {
        std::cout << "  引用: " << xref.data() << std::endl;
    }
}
```

#### 查找特定指令

```cpp
auto disasm = range.disassembly();

// 使用 C++20 ranges 查找
auto result = std::ranges::find_if(disasm, [](const auto& instr) {
    // 查找 call 指令
    return instr->getMnemonic() == zasm::x86::Mnemonic::Call;
});

if (result != disasm.end()) {
    std::cout << "找到 call 指令: " << result->dump() << std::endl;
}
```

#### 查找交叉引用

```cpp
// 假设我们有一个字符串地址
auto string_addr = mod->section(".rdata")->find_one("特殊字符串");

// 在代码段中查找引用这个字符串的指令
auto text = mod->section(".text").value();
auto disasm = text.disassembly();

auto result = std::ranges::find_if(disasm, [&](const auto& instr) {
    auto xrefs = instr.xrefs();
    return std::ranges::contains(xrefs, *string_addr);
});

if (result != disasm.end()) {
    // 找到了引用字符串的指令
    auto instr_addr = result->ptr();

    // 尝试猜测函数起始地址
    auto func = instr_addr.guess_function();
}
```

### Thread - 线程管理

#### 枚举线程

```cpp
auto proc = blook::Process::self();
auto threads = proc->threads();

for (auto& thread : threads) {
    std::cout << "线程 ID: " << thread.id << std::endl;

    // 获取线程名称（如果有）
    auto name = thread.name();
    if (name.has_value()) {
        std::cout << "  名称: " << *name << std::endl;
    }
}
```

#### 线程上下文

```cpp
auto threads = proc->threads();
auto& thread = threads[0];

// 捕获线程上下文
auto ctx = thread.capture_context();
if (ctx.has_value()) {
#ifdef BLOOK_ARCHITECTURE_X86_64
    std::cout << "RIP: " << std::hex << ctx->rip << std::endl;
    std::cout << "RAX: " << std::hex << ctx->rax << std::endl;
    std::cout << "RBX: " << std::hex << ctx->rbx << std::endl;
#else
    std::cout << "EIP: " << std::hex << ctx->eip << std::endl;
    std::cout << "EAX: " << std::hex << ctx->eax << std::endl;
#endif
}

// 修改上下文
if (ctx.has_value()) {
    ctx->rax = 0x12345678;
    thread.set_context(*ctx);
}
```

#### 线程控制

```cpp
auto& thread = threads[0];

// 挂起线程
thread.suspend();

// 恢复线程
thread.resume();

// 检查是否挂起
bool suspended = thread.is_suspended();

// 检查线程是否存在
bool exists = thread.exists();

// 终止线程
thread.terminate();

// 等待线程结束
thread.join();
```

#### 读取栈

```cpp
auto& thread = threads[0];

// 读取栈上的值（偏移量）
size_t stack_value = thread.stack(0x10);
```

#### 创建线程

```cpp
blook::Pointer func_ptr = (void*)thread_function;

// 创建线程
auto thread = func_ptr.create_thread(false); // false = 不挂起

if (thread.has_value()) {
    // 等待线程完成
    thread->join();
}

// 创建挂起的线程
auto suspended_thread = func_ptr.create_thread(true);
if (suspended_thread.has_value()) {
    // 做一些准备工作...

    // 恢复线程
    suspended_thread->resume();
}
```

## 高级用法

### 代码重组装 (Reassembly)

#### 基本重组装

```cpp
blook::Pointer ptr = some_code_address;

// 重组装代码
auto patch = ptr.reassembly([](zasm::x86::Assembler& a) {
    // 使用 zasm 汇编器生成新代码
    a.nop();
    a.nop();
    a.ret();
});

// 应用补丁
patch.patch();

// 恢复原始代码
patch.restore();

// 交换（如果已打补丁则恢复，否则打补丁）
patch.swap();
```

#### 带 Padding 的重组装

如果新代码比原始代码短，会用 NOP 填充：

```cpp
blook::MemoryRange range(ptr, 20);

auto patch_result = range.try_reassembly_with_padding(
    [](zasm::x86::Assembler& a) {
        a.ret();  // 只有 1 字节
    }
);

if (patch_result.has_value()) {
    auto& patch = *patch_result;
    patch.patch();
    // 现在前 1 字节是 ret，后 19 字节是 NOP
}
```

#### 带 Trampoline 的重组装

在原始位置插入跳转，跳转到新分配的内存，执行用户代码后再跳回：

```cpp
blook::Pointer func_ptr = (void*)some_function;

auto patch_result = func_ptr.try_reassembly_with_trampoline(
    [](zasm::x86::Assembler& a) {
        // 在原始代码执行前插入的代码
        a.push(zasm::x86::rax);
        a.mov(zasm::x86::rax, zasm::Imm(0x12345678));
        a.pop(zasm::x86::rax);
    }
);

if (patch_result.has_value()) {
    patch_result->patch();
    // 现在函数会先执行用户代码，然后执行原始代码
}
```

#### 暂停所有线程的重组装

```cpp
blook::Pointer ptr = some_code_address;

// 暂停所有线程，重组装代码，然后恢复线程
auto patch = ptr.reassembly_thread_pause();

// 应用补丁（会自动暂停/恢复线程）
patch.patch();
```

### 函数查找

#### 通过模式查找函数

```cpp
auto proc = blook::Process::self();
auto mod = proc->module().value();
auto text = mod->section(".text").value();

// 使用 AOB 模式查找
using ANY = blook::memory_scanner::ANYPattern;
auto result = text.find_one({
    0x55, 0x56, 0x57, 0x48, 0x83, 0xec, 0x70,
    0x48, 0x8d, 0x6c, 0x24, 0x70, 0x48, 0xc7,
    0x45, 0xf8, 0xfe, 0xff, 0xff, 0xff, 0x48,
    0x89, 0xce, 0x48, 0x8d, 0x7d, 0xd0, 0x48,
    0x89, 0xfa, 0xe8, 0x44, ANY, ANY, ANY
});

if (result.has_value()) {
    // 可能需要偏移到函数开始
    auto func_start = result->sub(0x28);

    // 创建钩子
    auto hook = func_start.as_function().inline_hook();
}
```

#### 通过字符串引用查找函数

```cpp
auto mod = proc->module().value();
auto rdata = mod->section(".rdata").value();
auto text = mod->section(".text").value();

// 查找字符串
auto str_addr = rdata.find_one("特殊的错误消息");

if (str_addr.has_value()) {
    // 在代码段中查找引用
    auto xref = text.find_xref(*str_addr);

    if (xref.has_value()) {
        // 猜测函数起始地址
        auto func = xref->guess_function();

        if (func.has_value()) {
            std::cout << "找到函数: " << func->data() << std::endl;
        }
    }
}
```

#### 向上查找函数开始

```cpp
blook::Pointer ptr = some_address_in_function;

// 向上查找函数序言
auto func_start = ptr.find_upwards({
    0x55, 0x8B, 0xEC  // push ebp; mov ebp, esp
}, 1000);

if (func_start.has_value()) {
    std::cout << "函数开始: " << func_start->data() << std::endl;
}
```

### 内存保护

#### 临时修改内存保护

```cpp
blook::Pointer ptr = some_code_address;

{
    // RAII 风格的内存保护修改
    blook::ScopedSetMemoryRWX scoped(ptr, 100);

    // 在这个作用域内，内存是 RWX
    ptr.write_bytearray({0x90, 0x90, 0x90});

} // 离开作用域时自动恢复原始保护属性
```

#### 手动修改保护属性

```cpp
auto proc = blook::Process::self();

// 修改保护属性
auto old_protect = proc->set_memory_protect(
    some_address,
    1024,
    blook::Protect::rwx
);

// 进行操作...

// 恢复原始保护
proc->set_memory_protect(some_address, 1024, old_protect);
```

### 模块所有者查询

```cpp
blook::Pointer ptr = some_address;

// 查找包含这个地址的模块
auto owner = ptr.owner_module();
if (owner.has_value()) {
    std::cout << "地址属于模块: " << owner->base().data() << std::endl;
}
```

### DLL 劫持辅助

```cpp
#include <blook/misc.h>

// 在 DllMain 中
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // 加载原始 DLL 并转发所有导出
        blook::misc::install_optimize_dll_hijacking("original.dll");

        // 或者使用过滤器
        blook::misc::install_optimize_dll_hijacking(
            original_module,
            [](std::string name) {
                // 只转发特定函数
                return name != "MyHookedFunction";
            }
        );
    }
    return TRUE;
}
```

## 示例

### 示例 1: 简单的函数钩子

```cpp
#include <blook/blook.h>
#include <Windows.h>
#include <iostream>

int main() {
    auto proc = blook::Process::self();
    auto kernel32 = proc->module("kernel32.dll").value();
    auto sleep_func = kernel32->exports("Sleep").value();

    auto hook = sleep_func->inline_hook();

    hook->install([=](DWORD ms) {
        std::cout << "Sleep 被调用，参数: " << ms << "ms" << std::endl;

        // 减少睡眠时间
        hook->call_trampoline<void>(ms / 10);

        std::cout << "实际只睡了 " << (ms / 10) << "ms" << std::endl;
    });

    // 测试
    std::cout << "开始睡眠 1000ms..." << std::endl;
    Sleep(1000);
    std::cout << "睡眠结束" << std::endl;

    hook->uninstall();
    return 0;
}
```

### 示例 2: 内存扫描和修改

```cpp
#include <blook/blook.h>
#include <iostream>

int main() {
    auto proc = blook::Process::self();
    auto mod = proc->module().value();

    // 假设我们要找游戏中的生命值
    int health = 100;

    // 在内存中搜索
    auto range = mod->memo();
    auto result = range.find_one(
        std::vector<uint8_t>(
            (uint8_t*)&health,
            (uint8_t*)&health + sizeof(health)
        )
    );

    if (result.has_value()) {
        std::cout << "找到生命值地址: " << result->data() << std::endl;

        // 修改为 999
        result->write_s32(999);

        std::cout << "生命值已修改为: " << health << std::endl;
    }

    return 0;
}
```

### 示例 3: 代码洞穴 (Code Cave)

```cpp
#include <blook/blook.h>

int main() {
    auto proc = blook::Process::self();
    auto mod = proc->module().value();
    auto text = mod->section(".text").value();

    // 查找 NOP 洞穴（连续的 0x90）
    auto cave = text.find_one({
        0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90
    });

    if (cave.has_value()) {
        std::cout << "找到代码洞穴: " << cave->data() << std::endl;

        // 在洞穴中写入自定义代码
        auto patch = cave->reassembly([](zasm::x86::Assembler& a) {
            a.push(zasm::x86::rax);
            a.mov(zasm::x86::rax, zasm::Imm(0x12345678));
            // ... 更多代码
            a.pop(zasm::x86::rax);
            a.ret();
        });

        patch.patch();
    }

    return 0;
}
```

### 示例 4: 多级指针

```cpp
#include <blook/blook.h>
#include <iostream>

int main() {
    auto proc = blook::Process::self();

    // 假设游戏中的玩家数据结构
    // PlayerManager -> Player -> Stats -> Health
    blook::Pointer player_mgr = (void*)0x140000000;

    // 偏移链: [0x10] -> [0x20] -> [0x30] -> health
    auto health_ptr = player_mgr.offsets({0x10, 0x20, 0x30});

    if (health_ptr.has_value()) {
        int health = health_ptr->read_s32();
        std::cout << "当前生命值: " << health << std::endl;

        // 修改生命值
        health_ptr->write_s32(999);
        std::cout << "生命值已修改为 999" << std::endl;
    }

    return 0;
}
```


### 示例 5: 反汇编和分析

```cpp
#include <blook/blook.h>
#include <iostream>

void analyze_function(void* func_addr) {
    blook::Pointer ptr = func_addr;
    auto range = ptr.range_size(200);

    std::cout << "分析函数: " << func_addr << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    auto disasm = range.disassembly();
    int instr_count = 0;

    for (const auto& instr : disasm) {
        // 打印指令
        std::cout << std::hex << instr.ptr().data() << ": "
                  << instr.dump() << std::endl;

        // 检查是否有交叉引用
        auto xrefs = instr.xrefs();
        for (const auto& xref : xrefs) {
            std::cout << "  -> 引用: " << xref.data() << std::endl;
        }

        instr_count++;

        // 遇到 ret 指令停止
        if (instr->getMnemonic() == zasm::x86::Mnemonic::Ret) {
            break;
        }
    }

    std::cout << "总共 " << instr_count << " 条指令" << std::endl;
}

int main() {
    auto proc = blook::Process::self();
    auto kernel32 = proc->module("kernel32.dll").value();
    auto sleep_func = kernel32->exports("Sleep").value();

    analyze_function(sleep_func->data());

    return 0;
}
```

### 示例 6: VEH 钩子监控

```cpp
#include <blook/blook.h>
#include <iostream>
#include <vector>

// 要监控的函数
int sensitive_function(int a, int b) {
    return a * b + 42;
}

int main() {
    std::vector<std::pair<int, int>> call_log;

    // 添加硬件断点
    auto handler = blook::VEHHookManager::instance().add_breakpoint(
        blook::VEHHookManager::HardwareBreakpoint{
            .address = (void*)sensitive_function
        },
        [&](blook::VEHHookManager::VEHHookContext& ctx) {
            // 记录调用参数（x64 calling convention）
#ifdef BLOOK_ARCHITECTURE_X86_64
            auto regs = (CONTEXT*)ctx.exception_info->ContextRecord;
            int a = (int)regs->Rcx;
            int b = (int)regs->Rdx;
#else
            // x86 需要从栈上读取
            auto regs = (CONTEXT*)ctx.exception_info->ContextRecord;
            int* stack = (int*)regs->Esp;
            int a = stack[1];
            int b = stack[2];
#endif

            call_log.push_back({a, b});
            std::cout << "函数被调用: " << a << ", " << b << std::endl;
        }
    );

    // 测试调用
    sensitive_function(10, 20);
    sensitive_function(5, 7);
    sensitive_function(3, 4);

    // 移除断点
    blook::VEHHookManager::instance().remove_breakpoint(handler);

    // 打印日志
    std::cout << "\n调用日志:" << std::endl;
    for (const auto& [a, b] : call_log) {
        std::cout << "  (" << a << ", " << b << ")" << std::endl;
    }

    return 0;
}
```

### 示例 7: 自动查找和钩住函数

```cpp
#include <blook/blook.h>
#include <iostream>

int main() {
    auto proc = blook::Process::self();
    auto mod = proc->module().value();

    // 查找包含特定字符串的函数
    auto rdata = mod->section(".rdata").value();
    auto text = mod->section(".text").value();

    // 查找错误消息字符串
    auto error_msg = rdata.find_one("Critical Error:");

    if (error_msg.has_value()) {
        std::cout << "找到错误消息: " << error_msg->data() << std::endl;

        // 查找引用这个字符串的代码
        auto xref = text.find_xref(*error_msg);

        if (xref.has_value()) {
            std::cout << "找到引用: " << xref->data() << std::endl;

            // 猜测函数起始地址
            auto func = xref->guess_function();

            if (func.has_value()) {
                std::cout << "找到函数: " << func->data() << std::endl;

                // 钩住这个函数
                auto hook = func->inline_hook();

                hook->install([=]() {
                    std::cout << "错误处理函数被调用！" << std::endl;

                    // 可以选择不调用原始函数，阻止错误
                    // 或者调用原始函数
                    hook->call_trampoline<void>();
                });

                std::cout << "已钩住错误处理函数" << std::endl;
            }
        }
    }

    return 0;
}
```

### 示例 8: 内存分配器使用

```cpp
#include <blook/blook.h>
#include <iostream>

int main() {
    auto proc = blook::Process::self();
    auto& allocator = proc->allocator();

    std::cout << "初始状态:" << std::endl;
    std::cout << "  分配数: " << allocator.allocated_count() << std::endl;
    std::cout << "  已分配: " << allocator.total_allocated_bytes() << " 字节" << std::endl;
    std::cout << "  已保留: " << allocator.total_reserved_bytes() << " 字节" << std::endl;

    // 分配多个小块
    std::vector<blook::Pointer> ptrs;
    for (int i = 0; i < 10; i++) {
        auto ptr = allocator.allocate(512);
        ptrs.push_back(ptr);

        // 写入测试数据
        std::vector<uint8_t> data(512, i);
        ptr.write_bytearray(data);
    }

    std::cout << "\n分配 10 个块后:" << std::endl;
    std::cout << "  分配数: " << allocator.allocated_count() << std::endl;
    std::cout << "  已分配: " << allocator.total_allocated_bytes() << " 字节" << std::endl;
    std::cout << "  已保留: " << allocator.total_reserved_bytes() << " 字节" << std::endl;

    // 验证数据
    for (size_t i = 0; i < ptrs.size(); i++) {
        auto data = ptrs[i].read_bytearray(512);
        bool valid = std::all_of(data.begin(), data.end(),
                                 [i](uint8_t b) { return b == i; });
        std::cout << "块 " << i << " 数据" << (valid ? "正确" : "错误") << std::endl;
    }

    // 释放所有块
    for (auto& ptr : ptrs) {
        allocator.deallocate(ptr);
    }

    std::cout << "\n释放后:" << std::endl;
    std::cout << "  分配数: " << allocator.allocated_count() << std::endl;
    std::cout << "  已分配: " << allocator.total_allocated_bytes() << " 字节" << std::endl;

    return 0;
}
```
