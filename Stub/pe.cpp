#include "pe.h"
#include "basic.h"

DWORD WINAPI GetExportFuncAddrRVA(LPVOID peFileBuf, CHAR* targetFuncName){
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peFileBuf;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PBYTE)peFileBuf + pDos->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)((PBYTE)peFileBuf + pDos->e_lfanew);
#endif
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)peFileBuf + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (pExport == 0) {
		return 0;
	}

	PDWORD pdwName = (PDWORD)(pExport->AddressOfNames + (PBYTE)peFileBuf);
	PWORD pwOrder = (PWORD)(pExport->AddressOfNameOrdinals + (PBYTE)peFileBuf);
	PDWORD pdwFuncAddr = (PDWORD)(pExport->AddressOfFunctions + (PBYTE)peFileBuf);

	for (UINT i = 0; i < pExport->NumberOfFunctions; i++) {
		LPCSTR lpFuncName = (LPCSTR)(pdwName[i] + (PBYTE)peFileBuf);
		if (StringCmp(lpFuncName, targetFuncName) == 0) {
			WORD wOrd = pwOrder[i];
			return (DWORD)pdwFuncAddr[wOrd];
		}
	}
	return 0;
}

#ifdef _WIN64
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD64 oldImageBase, DWORD64 newImageBase) {
	if (oldImageBase == newImageBase) {
		return;
	}
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)peFileBuf + relocBaseRvaAddr);

	while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock != 0) {
		Type_Offset* pTypeOffs = (Type_Offset*)(pReloc + 1);
		DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(Type_Offset);
		for (UINT i = 0; i < dwCount; i++) {
			if (pTypeOffs[i].type != IMAGE_REL_BASED_HIGHLOW) {
				continue;
			}
			PDWORD64 pdwRepairAddr = (PDWORD64)((PBYTE)peFileBuf + pReloc->VirtualAddress + pTypeOffs[i].offset);
			*pdwRepairAddr -= oldImageBase;
			*pdwRepairAddr += newImageBase;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
	}
}
#else
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD oldImageBase, DWORD newImageBase) {
	if (oldImageBase == newImageBase) {
		return;
	}
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)peFileBuf + relocBaseRvaAddr);

	while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock != 0) {
		Type_Offset* pTypeOffs = (Type_Offset*)(pReloc + 1);
		DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(Type_Offset);
		for (UINT i = 0; i < dwCount; i++) {
			if (pTypeOffs[i].type != IMAGE_REL_BASED_HIGHLOW) {
				continue;
			}
			PDWORD pdwRepairAddr = (PDWORD)((PBYTE)peFileBuf + pReloc->VirtualAddress + pTypeOffs[i].offset);
			*pdwRepairAddr -= oldImageBase;
			*pdwRepairAddr += newImageBase;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
	}
}
#endif


