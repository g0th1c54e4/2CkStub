#ifndef _2CKSTUB_STUB_PE_H_
#define _2CKSTUB_STUB_PE_H_

#include <Windows.h>

typedef struct _Type_Offset {
	WORD offset : 12;
	WORD type : 4;
}Type_Offset;

DWORD WINAPI GetExportFuncAddrRVA(LPVOID peFileBuf, CHAR* targetFuncName); //��ȡ����������ַ(RVA)



#ifdef _WIN64
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD64 oldImageBase, DWORD64 newImageBase); //�޸��ض�λ
#else
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD oldImageBase, DWORD newImageBase); //�޸��ض�λ
#endif


#endif