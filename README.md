> [!WARNING] 
This project is in a relatively early stage and is not ready for production. Use at your own risk.  
此项目仍较早期，不建议实际使用。


<div align="center">
<img src="./resources/icon.webp" height="300">
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
  hook->install([=](int64_t a, char *text, char *title, int64_t b) -> int64_t {
    return hook->trampoline_t<int64_t(int64_t, char *, char *, int64_t)>()(
        a, "oh yes", text, b);
  });

  MessageBoxA(nullptr, "hi", "hi", 0);
```

...hook more? Sure!

```cpp
  auto process = blook::Process::self();
  auto mod = process->module("user32.dll").value();
  for (auto& func: mod.obtain_exports()) {
      auto hook = mod;
                  ->exports(func)
                  ->inline_hook();
      hook->install([=](int64_t a) -> int64_t {
          // Yes, capture anything you want!
          std::cout << "Someone called: " << std::hex << func << "\n";
          return hook->trampoline_t<int64_t(int64_t)>()(a);
      });
  }
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
target_link_libraries(your_target blook::blook)
```

### b) CMake FetchContent

Add those lines into your `CMakeLists.txt`

```cmake
###### Fetch blook from GitHub #####
FetchContent_Declare(
        blook
        GIT_REPOSITORY https://github.com/MicroCBer/blook
)
FetchContent_MakeAvailable(blook)
####################################

target_link_libraries(your_target blook::blook)
```

### Manual installation

It's strongly discouraged to use the project without CMake, but it should be possible.
