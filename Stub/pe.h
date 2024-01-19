#ifndef _2CKSTUB_STUB_PE_H_
#define _2CKSTUB_STUB_PE_H_

#include <Windows.h>

typedef struct _Type_Offset {
	WORD offset : 12;
	WORD type : 4;
}Type_Offset;

DWORD WINAPI GetExportFuncAddrRVA(LPVOID peFileBuf, CHAR* targetFuncName); //获取导出函数地址(RVA)



#ifdef _WIN64
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD64 oldImageBase, DWORD64 newImageBase); //修复重定位
#else
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD oldImageBase, DWORD newImageBase); //修复重定位
#endif


#endif