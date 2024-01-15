#include <Windows.h>
#include "main.h"

#ifndef _WIN64
_declspec(naked)
VOID WINAPI StubEntry() {
	MessageBoxW(NULL, L"Welcome to Ck2Stub.", L"Ck2Stub:", MB_OK);
	imageBase = ((DWORD)&share_info - share_info.ImageBaseOffset);
	share_info.OriginEntryPoint += imageBase;
	_asm {
		jmp share_info.OriginEntryPoint //ÐèÒª»ùÖ·
	}
}
#endif