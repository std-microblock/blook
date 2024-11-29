#pragma once

#ifdef WIN32
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
#endif