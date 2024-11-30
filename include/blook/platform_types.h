#pragma once

#ifdef WIN32
#define WIN_ONLY(...) __VA_ARGS__
#define LINUX_ONLY(...)
struct HINSTANCE__;
namespace blook {
using WORD = unsigned short;
using DWORD = unsigned long;
using BOOL = int;
using BYTE = unsigned char;
using LPBYTE = BYTE *;
using LPDWORD = DWORD *;
using LPVOID = void *;
using HINSTANCE = HINSTANCE__ *;
using HMODULE = HINSTANCE;
using HANDLE = void *;
} // namespace win
#else
#define WIN_ONLY(...)
#define LINUX_ONLY(...) __VA_ARGS__
#endif
