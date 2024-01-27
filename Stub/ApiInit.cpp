#include "ApiInit.h"

_MessageBoxW  fnMessageBoxW = NULL;
_VirtualProtect fnVirtualProtect = NULL;
_LoadLibraryA fnLoadLibraryA = NULL;
_GetModuleHandleA fnGetModuleHandleA = NULL;
_ExitProcess fnExitProcess = NULL;

LPVOID Base_Kernel32 = 0;
LPVOID Base_User32 = 0;

VOID WINAPI ApiInit(LPVOID imageBase) {
	fnGetModuleHandleA = (_GetModuleHandleA)GetImportFunc((LPVOID)imageBase, (CHAR*)"kernel32.dll", (CHAR*)"GetModuleHandleA");
	fnLoadLibraryA = (_LoadLibraryA)GetImportFunc((LPVOID)imageBase, (CHAR*)"kernel32.dll", (CHAR*)"LoadLibraryA");


	Base_Kernel32 = GetModuleBase("kernel32.dll");
	Base_User32 = GetModuleBase("user32.dll");

	fnMessageBoxW = (_MessageBoxW)GetExportFunc(Base_User32, (CHAR*)"MessageBoxW");
	fnExitProcess = (_ExitProcess)GetExportFunc(Base_Kernel32, (CHAR*)"ExitProcess");
	fnVirtualProtect = (_VirtualProtect)GetExportFunc(Base_Kernel32, (CHAR*)"VirtualProtect");
}

LPVOID WINAPI GetModuleBase(LPCSTR moduleName) {
	LPVOID moduleBase = fnGetModuleHandleA(moduleName);
	if (moduleBase == NULL) {
		return fnLoadLibraryA(moduleName);
	}
	return moduleBase;
}