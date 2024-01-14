#ifndef _2CKSTUB_PUBLIC_
#define _2CKSTUB_PUBLIC_

#include <Windows.h>
#define SHARE_INFO_NAME "share_info"//请勿改动

typedef struct _SHARE_INFO {
	//原始程序的正常原始执行入口
	DWORD64 OriginEntryPoint;

	//壳程序的执行入口偏移
	DWORD StubOriginEntryPointOffest;

	//原程序重定位表RVA
	DWORD RelocRva;
	DWORD RelocSize;

}SHARE_INFO;

#endif