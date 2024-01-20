#include <Windows.h>
#include "../Public/StubInfo_Public.h"
#include "pe.h"
#include "ApiInit.h"

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

extern _MessageBoxW fnMessageBoxW;


VOID WINAPI StubInit() {
	//修正映像基址
	#ifdef _WIN64
	imageBase = ((DWORD64)&share_info - share_info.ImageBaseOffset);
	#else
	imageBase = ((DWORD)&share_info - share_info.ImageBaseOffset);
	#endif
	share_info.OriginEntryPoint += imageBase;

	//TODO:初始化API函数 (利用IAT的GetProcAddress和LoadLibraryA来获取函数地址，以及用VirtualProtect打开权限)
	ApiInit((LPVOID)imageBase);
	fnMessageBoxW(NULL, L"Welcome to Ck2Stub.\nBy LingMo", L"Ck2Stub:", MB_OK);


	//TODO:恢复原始区块数据(需要Write权限)

	//修正重定位表(需要Write权限)
	if (share_info.Reloc.RvaAddr != 0) {
		RepairReloc((LPVOID)imageBase, share_info.Reloc.RvaAddr, share_info.OldImageBase, imageBase);
	}

	//TODO:修正IAT表(需要Write权限)

	//TODO:处理TLS

	//TODO:恢复资源(需要Write权限)

}

#ifndef _WIN64
_declspec(naked)
VOID WINAPI StubEntry() {
	StubInit();
	_asm {
		jmp dword ptr ds:[share_info.OriginEntryPoint] //需要基址
	}
}
#endif