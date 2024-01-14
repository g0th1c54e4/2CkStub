#ifndef _2CKSTUB_STUB_MAIN_
#define _2CKSTUB_STUB_MAIN_

#include <Windows.h>
#include "../Public/StubInfo_Public.h"

#ifdef _WIN64
extern "C" {
	SHARE_INFO share_info = { 0 };
}
#else
SHARE_INFO share_info = { 0 };
#endif

HMODULE g_hCurrentModuleHandle = 0;

#endif