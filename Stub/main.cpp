#include <Windows.h>
#include "main.h"

#ifndef _WIN64
_declspec(naked)
VOID WINAPI StubEntry() {
	imageBase = ((DWORD)&share_info - share_info.ImageBaseOffset);
	share_info.OriginEntryPoint += imageBase;
	_asm {
		jmp share_info.OriginEntryPoint //ÐèÒª»ùÖ·
	}
}
#endif