> [!WARNING]
> This project is in a relatively early stage and is not ready for production. Use at your own risk.  
> 此项目仍较早期，不建议实际使用。


<div align="center">
<img src="./resources/icon.webp" width="270">
<h1 style="margin-top: -30px;">&nbsp;&nbsp;blook</h1>
<h4>A modern C++ library for hacking.</h4>
</div>

## So what?

Inline hook a function? Easy!

```cpp
auto process = blook::Process::self();
auto hook = process->module("user32.dll").value()
                   ->exports("MessageBoxA")
                   ->inline_hook();
    hook->install([=](int64_t a, char *text, char *title, int64_t b) {
        // DRY: All types are only written once!
        return hook->call_trampoline<int64_t>(a, "oh yes", text, b);
    });

MessageBoxA(nullptr, "hi", "hi", 0);
```

...hook more? Sure!

```cpp
auto process = blook::Process::self();
auto mod = process->module("user32.dll").value();
for (auto& func: mod.obtain_exports()) {
    auto hook = mod
                ->exports(func)
                ->inline_hook();
    hook->install([=](int64_t a) -> int64_t {
        // Yes, capture anything you want!
        std::cout << "Someone called: " << std::hex << func << "\n";
        return hook->call_trampoline<int64_t>(a);
    });
}
```

How about hooking a method that's not exported?

```cpp
auto process = blook::Process::self();
auto mod = process->module().value();
// Let's find the specific function in .text (Code Segment) with blook's AOB shortcut!.
auto text_segment = mod->section(".text").value();
using ANYp = blook::memory_scanner::ANYPattern;
auto hook = text_segment.find_one({
    0x55, 0x56, 0x57, 0x48, 0x83, 0xec, 0x70, 0x48, 0x8d, 0x6c, 0x24, 0x70,
    0x48, 0xc7, 0x45, 0xf8, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0xce, 0x48,
    0x8d, 0x7d, 0xd0, 0x48, 0x89, 0xfa, 0xe8, 0x44, ANYp, ANYp, ANYp
})->sub(-0x28).as_function().inline_hook();

// And now it's easy to hook it.
hook->install([=](int64_t a) -> int64_t {
    std::cout << "Someone called some internal function!\n";
    return hook->call_trampoline<int64_t>(a);
});
```

## Getting started

### Compile

Clone the repository to local, and build it with cmake!

### Using in a CMake project

### a) git submodule

First, add the repo as submodule.

```shell
git submodule add https://github.com/MicroCBer/blook
git submodule update --init --recursive
```

Then, import it and add it to your project in `CMakeLists.txt`

```cmake
add_subdirectory(external/blook)
target_link_libraries(your_target blook)
```

### b) CMake FetchContent

Add those lines into your `CMakeLists.txt`

```cmake
include(FetchContent)

###### Fetch blook from GitHub #####
FetchContent_Declare(
        blook
        GIT_REPOSITORY https://github.com/MicroCBer/blook
        GIT_TAG origin/main
)
FetchContent_MakeAvailable(blook)
####################################

target_link_libraries(your_target blook)
```

### Manual installation

It's strongly discouraged to use the project without CMake, but it should be possible.

## Platforms

- std::function to function pointer [Windows x86/x64]
- Inline Hook [Windows x86/x64]
- Cross reference [Windows x86/x64]
- AOB Scanning [Windows x86/x64]
- Reassembly [Windows x86/x64]
- Disassembly [Windowx x86/x64 (Zydis)]
- Foreign process memory operations [Windows x86/x64]

Linux/Mac support WIP.