#include "ApiInit.h"

_MessageBoxW  fnMessageBoxW = NULL;
_VirtualProtect fnVirtualProtect = NULL;
_LoadLibraryA fnLoadLibraryA = NULL;
_GetModuleHandleA fnGetModuleHandleA = NULL;
_ExitProcess fnExitProcess = NULL;
_GetProcAddress fnGetProcAddress = NULL;

LPVOID Base_Kernel32 = 0;
LPVOID Base_User32 = 0;

VOID WINAPI ApiInit(LPVOID imageBase) {
	fnGetModuleHandleA = (_GetModuleHandleA)GetImportFunc((LPVOID)imageBase, (CHAR*)"kernel32.dll", (CHAR*)"GetModuleHandleA");
	fnLoadLibraryA = (_LoadLibraryA)GetImportFunc((LPVOID)imageBase, (CHAR*)"kernel32.dll", (CHAR*)"LoadLibraryA");
	fnGetProcAddress = (_GetProcAddress)GetImportFunc((LPVOID)imageBase, (CHAR*)"kernel32.dll", (CHAR*)"GetProcAddress");

	if (fnGetModuleHandleA == 0) {
		fnGetModuleHandleA = (_GetModuleHandleA)GetExportFunc((LPVOID)GetKernelBase(), (CHAR*)"GetModuleHandleA");
	}
	if (fnLoadLibraryA == 0) {
		fnLoadLibraryA = (_LoadLibraryA)GetExportFunc((LPVOID)GetKernelBase(), (CHAR*)"GetModuleHandleA");
	}
	if (fnGetProcAddress == 0) {
		fnGetProcAddress = (_GetProcAddress)GetExportFunc((LPVOID)GetKernelBase(), (CHAR*)"GetProcAddress");
	}

	Base_Kernel32 = GetModuleBase("kernel32.dll");
	Base_User32 = GetModuleBase("user32.dll");

	fnMessageBoxW = (_MessageBoxW)GetExportFunc(Base_User32, (CHAR*)"MessageBoxW");
	fnExitProcess = (_ExitProcess)GetExportFunc(Base_Kernel32, (CHAR*)"ExitProcess");
	fnVirtualProtect = (_VirtualProtect)GetExportFunc(Base_Kernel32, (CHAR*)"VirtualProtect");
}


#ifdef _WIN64
DWORD64 WINAPI GetKernelBase() {
	DWORD64 qwKernelBase = 0;
	_TEB* pTeb = NtCurrentTeb();
	PDWORD64 pPeb = (PDWORD64) * (PDWORD64)((DWORD64)pTeb + 0x60);
	PDWORD64 pLdr = (PDWORD64) * (PDWORD64)((DWORD64)pPeb + 0x18);
	PDWORD64 pInLoadOrderModuleList = (PDWORD64)((DWORD64)pLdr + 0x10);
	PDWORD64 pModuleExe = (PDWORD64)*pInLoadOrderModuleList;
	PDWORD64 pModuleNtdll = (PDWORD64)*pModuleExe;
	PDWORD64 pModuleKernel32 = (PDWORD64)*pModuleNtdll;
	qwKernelBase = pModuleKernel32[6];
	return qwKernelBase;
}
#else
DWORD WINAPI GetKernelBase() {
	DWORD dwKernelBase = 0;
	_TEB* pTeb = NtCurrentTeb();
	PDWORD pPeb = (PDWORD) * (PDWORD)((DWORD)pTeb + 0x30);
	PDWORD pLdr = (PDWORD) * (PDWORD)((DWORD)pPeb + 0x0C);
	PDWORD pInLoadOrderModuleList = (PDWORD)((DWORD)pLdr + 0x14);

	PDWORD pModuleExe = (PDWORD)*pInLoadOrderModuleList;
	PDWORD pModuleNtdll = (PDWORD)*pModuleExe;
	PDWORD pModuleKernel32 = (PDWORD)*pModuleNtdll;
	dwKernelBase = *PDWORD((DWORD)pModuleKernel32 + 0x10);
	return dwKernelBase;
}
#endif