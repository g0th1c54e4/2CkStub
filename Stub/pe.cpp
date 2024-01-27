#include "pe.h"
#include "basic.h"

LPVOID WINAPI GetExportFunc(LPVOID peFileBuf, CHAR* targetFuncName){
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
		if (StringCmp(lpFuncName, targetFuncName) == TRUE) {
			WORD wOrd = pwOrder[i];
			return (LPVOID)((PBYTE)peFileBuf + pdwFuncAddr[wOrd]);
		}
	}
	return 0;
}

LPVOID WINAPI GetExportFunc(LPVOID peFileBuf, WORD FuncOrdinal){
	return LPVOID();
}

LPVOID WINAPI GetImportFunc(LPVOID peFileBuf, CHAR* LibraryName, CHAR* FuncName) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peFileBuf;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PBYTE)peFileBuf + pDos->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)((PBYTE)peFileBuf + pDos->e_lfanew);
#endif
	PIMAGE_DATA_DIRECTORY dirImp = pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
	PIMAGE_DATA_DIRECTORY dirIat = pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IAT;
	DWORD numOfIID = (dirImp->Size - sizeof(IMAGE_IMPORT_DESCRIPTOR)) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	PIMAGE_IMPORT_DESCRIPTOR pFirstIID = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)peFileBuf + dirImp->VirtualAddress);
#ifdef _WIN64
	DWORD numOfFunc = (dirIat->Size - sizeof(PIMAGE_THUNK_DATA64)) / sizeof(PIMAGE_THUNK_DATA64);
#else
	DWORD numOfFunc = (dirIat->Size - sizeof(PIMAGE_THUNK_DATA32)) / sizeof(PIMAGE_THUNK_DATA32);
#endif
	for (UINT i = 0; i < numOfIID; i++) {
		CHAR* dllName = (CHAR*)((PBYTE)peFileBuf + (pFirstIID + i)->Name);
		if (StringCmp(dllName, LibraryName) == TRUE) {
#ifdef _WIN64
			PIMAGE_THUNK_DATA64 OrgFirstThunkData = (PIMAGE_THUNK_DATA64)((PBYTE)peFileBuf + pFirstIID[i].OriginalFirstThunk);
#else
			PIMAGE_THUNK_DATA32 OrgFirstThunkData = (PIMAGE_THUNK_DATA32)((PBYTE)peFileBuf + pFirstIID[i].OriginalFirstThunk);
#endif
			for (UINT j = 0; j < numOfFunc; j++) {
				PIMAGE_IMPORT_BY_NAME impByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)peFileBuf + OrgFirstThunkData[j].u1.AddressOfData);
				if (StringCmp(impByName->Name, FuncName) == TRUE) {
#ifdef _WIN64
					PIMAGE_THUNK_DATA64 firstThunkData = (PIMAGE_THUNK_DATA64)((PBYTE)peFileBuf + pFirstIID[i].FirstThunk);
#else
					PIMAGE_THUNK_DATA32 firstThunkData = (PIMAGE_THUNK_DATA32)((PBYTE)peFileBuf + pFirstIID[i].FirstThunk);
#endif
					return (LPVOID)(firstThunkData[j].u1.Function);

				}
			}
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
			if (pTypeOffs[i].type != IMAGE_REL_BASED_DIR64) {
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


VOID WINAPI RepairIat(LPVOID peFileBuf, AREA* importInfo, AREA* iatInfo) {

	return VOID();
}