#include <Windows.h>
#include "../Public/StubInfo_Public.h"
#include "pe.h"
#include "ApiInit.h"

#ifdef _WIN64
extern "C" {
	SHARE_INFO share_info = { 0 };
	VOID WINAPI StubInit();
	VOID WINAPI CallEntry();
}
#else
SHARE_INFO share_info = { 0 };
VOID WINAPI StubInit();
VOID WINAPI CallEntry();
#endif

#ifdef _WIN64
DWORD64 imageBase = 0;
#else
DWORD imageBase = 0;
#endif

extern _MessageBoxW fnMessageBoxW;
extern _VirtualProtect fnVirtualProtect;


VOID WINAPI StubInit() {
	//修正映像基址
	#ifdef _WIN64
	imageBase = ((DWORD64)&share_info - share_info.ImageBaseOffset);
	#else
	imageBase = ((DWORD)&share_info - share_info.ImageBaseOffset);
	#endif
	share_info.OriginEntryPoint += imageBase;

	//初始化API函数
	ApiInit((LPVOID)imageBase);

	//修正权限 ==> Read、Write、Execute
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(imageBase);
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBase + pDos->e_lfanew);
	WORD numOfSec = pNt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pFirstSecHdr = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSecHdr = (pFirstSecHdr + (numOfSec - 1));
	DWORD oldProtVal = 0;
	fnVirtualProtect((LPVOID)(imageBase + pFirstSecHdr->VirtualAddress), (pLastSecHdr->VirtualAddress + pLastSecHdr->Misc.VirtualSize - pFirstSecHdr->VirtualAddress), PAGE_EXECUTE_READWRITE, &oldProtVal);

	//TODO:恢复原始区块数据(需要Write权限)


	//修正重定位表(需要Write权限)
	if (share_info.Reloc.RvaAddr != 0) {
		RepairReloc((LPVOID)imageBase, share_info.Reloc.RvaAddr, share_info.OldImageBase, imageBase);
	}

	//修正IAT表(需要Write权限)
	if (share_info.Import.RvaAddr != 0 && share_info.Iat.RvaAddr != 0) {
		RepairIat((LPVOID)imageBase, &share_info.Import, &share_info.Iat);
	}

	//TODO:处理TLS

	//TODO:恢复资源(需要Write权限)

}

VOID WINAPI CallEntry() {

	fnMessageBoxW(NULL, L"Welcome to Ck2Stub.\nBy LingMo", L"Ck2Stub:", MB_OK);

}

#ifndef _WIN64
_declspec(naked)
VOID WINAPI StubEntry() {
	StubInit();
	CallEntry();
	_asm {
		jmp dword ptr ds:[share_info.OriginEntryPoint]
	}
}
#endif