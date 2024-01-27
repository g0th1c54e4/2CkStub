#ifndef _2CKSTUB_STUB_PE_H_
#define _2CKSTUB_STUB_PE_H_

#include <Windows.h>
#include "../Public/StubInfo_Public.h"
#include "ApiInit.h"

typedef struct _Type_Offset {
	WORD offset : 12;
	WORD type : 4;
}Type_Offset;

LPVOID WINAPI GetExportFunc(LPVOID peFileBuf, CHAR* FuncName); //获取导出函数地址(VA)
LPVOID WINAPI GetExportFunc(LPVOID peFileBuf, WORD FuncOrdinal); //获取导出函数地址(VA)
LPVOID WINAPI GetImportFunc(LPVOID peFileBuf, CHAR* LibraryName, CHAR* FuncName); //(面向自身)获取指定模块的导入函数地址(VA)

LPVOID WINAPI GetModuleBase(LPCSTR moduleName);

#ifdef _WIN64
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD64 oldImageBase, DWORD64 newImageBase); //修复重定位
#else
VOID WINAPI RepairReloc(LPVOID peFileBuf, DWORD relocBaseRvaAddr, DWORD oldImageBase, DWORD newImageBase); //修复重定位
#endif

VOID WINAPI RepairIat(LPVOID peFileBuf, AREA* importInfo, AREA* iatInfo); //修复IAT表

#endif