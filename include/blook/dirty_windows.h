#pragma once

#if ((ULONG_MAX) == (UINT_MAX))
#define _AMD64_
#elif
#define _IA86_
#endif

#define NOMINMAX
#include <minwindef.h>
#include <winnt.h>