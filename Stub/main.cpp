#include <Windows.h>
#include "../Public/StubInfo_Public.h"

#ifdef _WIN64
extern "C" {
	SHARE_INFO share_info = { 0 };
	VOID WINAPI StubInit();
}
#else
SHARE_INFO share_info = { 0 };
VOID WINAPI StubInit();
#endif

#ifdef _WIN64
DWORD64 imageBase = 0;
#else
DWORD imageBase = 0;
#endif


VOID WINAPI StubInit() {
	//修正映像基址
	#ifdef _WIN64
	imageBase = ((DWORD64)&share_info - share_info.ImageBaseOffset);
	share_info.OriginEntryPoint += imageBase;
	#else
	imageBase = ((DWORD)&share_info - share_info.ImageBaseOffset);
	share_info.OriginEntryPoint += imageBase;
	#endif

	//修正重定位表


}

#ifndef _WIN64
_declspec(naked)
VOID WINAPI StubEntry() {
	StubInit();
	_asm {
		jmp share_info.OriginEntryPoint //需要基址
	}
}
#endif