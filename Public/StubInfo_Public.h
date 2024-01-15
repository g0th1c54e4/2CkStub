#ifndef _2CKSTUB_PUBLIC_
#define _2CKSTUB_PUBLIC_

#include <Windows.h>
#define SHARE_INFO_NAME "share_info"//请勿改动

typedef struct _AREA {
	DWORD RvaAddr;
	DWORD Size;
}AREA;

typedef struct _SHARE_INFO {
	//原始程序的正常原始执行入口偏移
	DWORD64 OriginEntryPoint;

	//用于计算当前模块的基址
	DWORD ImageBaseOffset;

	//原程序的代码区域位置
	AREA OriginCode;

	//原程序重定位表RVA
	AREA Reloc;

	//原程序导入表
	AREA Import;
	AREA Iat;

}SHARE_INFO;

#endif