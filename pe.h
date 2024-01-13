#ifndef _2CKSTUB_PE_H_
#define _2CKSTUB_PE_H_

#include <Windows.h>
#include <vector>
#include "file.h"
#include "buf.h"

enum FileBit { Bit32 = 0, Bit64 = 1 };

#define IMAGE_FIRST_SECTION32( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_FIRST_SECTION64( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef class _PeFile : public FileBuf {
private:

	//判断是否为PE文件
	BOOL init_checkPeFile();
	//检测PE文件的运行位数(32、64位)
	FileBit init_judgeBit();

	LocalBuf memBuf;
	VOID VirtualLoad(); //将PE文件提升到内存形式
	VOID VirtualUpdate(); //将内存形式内的全部更改都更新到文件形式的PE文件内
	
public:
	PIMAGE_DOS_HEADER dosHdr;
	PIMAGE_NT_HEADERS32 ntHdr32;
	PIMAGE_NT_HEADERS64 ntHdr64;
	PIMAGE_SECTION_HEADER firstSecHdr;
	FileBit fileBit; //当前PE文件的运行位数

	//初始化
	BOOL Init(CHAR* targetFilePath);
	BOOL Init(WCHAR* targetFilePath);
	
	std::vector<PIMAGE_SECTION_HEADER> GetSecHdrList(); //获取区块头数组
	
	DWORD Rva2Foa(DWORD RvaValue); //RVA转换FOA
	DWORD Foa2Rva(DWORD FoaValue); //FOA转换RVA

	//以下为待编写区域

	DWORD64 GetExportFuncAddrRVA(); //获取导出函数地址(RVA)
	DWORD64 GetExportFuncAddrVA(); //获取导出函数地址(VA)


	VOID ClosePeFile();
	_PeFile();
	~_PeFile();
} PeFile;

#endif