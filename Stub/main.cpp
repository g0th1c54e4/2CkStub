#include <Windows.h>
#include "main.h"

#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")


#ifndef _WIN64
_declspec(naked)
VOID WINAPI StubEntry() {

	APIInit();
	VMInit();
	Call_Entry();
	_asm {
		jmp share_info.OriginEntryPoint32
	}
}
#endif