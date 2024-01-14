#ifndef _2CKSTUB_PE_H_
#define _2CKSTUB_PE_H_

#include <Windows.h>
#include <vector>
#include "file.h"
#include "buf.h"

enum FileBit { 
	Bit32 = 0,
	Bit64 = 1 
};
enum DirEntryOrder {
	Dir_Export = IMAGE_DIRECTORY_ENTRY_EXPORT,
	Dir_Import = IMAGE_DIRECTORY_ENTRY_IMPORT,
	Dir_Resource = IMAGE_DIRECTORY_ENTRY_RESOURCE,
	Dir_Exception = IMAGE_DIRECTORY_ENTRY_EXCEPTION,
	Dir_Security = IMAGE_DIRECTORY_ENTRY_SECURITY,
	Dir_BaseReloc = IMAGE_DIRECTORY_ENTRY_BASERELOC,
	Dir_Debug = IMAGE_DIRECTORY_ENTRY_DEBUG,
	Dir_Architecture = IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
	Dir_GlobalPtr = IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
	Dir_Tls = IMAGE_DIRECTORY_ENTRY_TLS,
	Dir_LoadConfig = IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
	Dir_BoundImport = IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
	Dir_Iat = IMAGE_DIRECTORY_ENTRY_IAT,
	Dir_DelayImport = IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
	Dir_ComDescriptor = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
};

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
	//判断程序是否有合适的空间以插入新的区块项
	BOOL CheckSecTabSpace(UINT numOfInsertSec = 1);
	//修改Buffer大小并重置私有成员信息
	VOID ReSize(DWORD newSize);

	//WORD nunOfSec;
	
public:

	// 注意，此类不提供针对内存形式的PE文件的存储形式的方法函数。原因在于方便后续Buffer保存到原文件。

	PIMAGE_DOS_HEADER dosHdr;
	PIMAGE_NT_HEADERS32 ntHdr32;
	PIMAGE_NT_HEADERS64 ntHdr64;
	PIMAGE_SECTION_HEADER firstSecHdr;
	FileBit fileBit; //当前PE文件的运行位数

	//初始化
	BOOL Init(CHAR* targetFilePath);
	BOOL Init(WCHAR* targetFilePath);
	
	std::vector<PIMAGE_SECTION_HEADER> GetSecHdrList(); //获取区块头数组
	PIMAGE_SECTION_HEADER GetSecHdrByName(CONST CHAR* sectionName); //根据区块名来获取对应区块头
	PIMAGE_SECTION_HEADER GetCodeSec(); //获取OEP所在区块对应的区块头
	PIMAGE_SECTION_HEADER GetRelocSec(); //获取重定位表所在区块对应的区块头
	
	DWORD Rva2Foa(DWORD RvaValue); //RVA转换FOA
	DWORD Foa2Rva(DWORD FoaValue); //FOA转换RVA
	DWORD AlignFile(DWORD value); //文件对齐
	DWORD AlignSection(DWORD value); //内存对齐

	DWORD GetExportFuncAddrRVA(CHAR* targetFuncName); //获取导出函数地址(RVA)

	PIMAGE_DATA_DIRECTORY GetDirByOrder(DirEntryOrder dirOrder); //获取特定数据目录表
	VOID RemoveDebugInfo(); //清除调试数据目录表信息(参数removeData表示是否清除数据目录所具体引用的数据)
	VOID RemoveExportInfo(); //清除导出数据目录表信息(参数removeData表示是否清除数据目录所具体引用的数据)

	VOID DynamicsBaseOff(); //关闭动态基址
	BOOL AddSection(CONST CHAR* newSecName, DWORD newSecSize, DWORD newSecAttrib, IMAGE_SECTION_HEADER* newSecReturnHdr, DWORD* newSecReturnFOA); //添加新区块
	BOOL ExtendLastSection(DWORD addSize, DWORD newSecAttrib, IMAGE_SECTION_HEADER* secReturnHdr, DWORD* secReturnFOA); //扩充最后一个区块
	
	VOID SetOep(DWORD oepValue); //设置新的OEP入口点

	DWORD64 GetImageBase(); //获取映像基址 (32位下请自行将返回值强制转换成DWORD型)

	DWORD GetCheckSum(); //获取当前PE文件的校验和(直接从NT头读取)
	DWORD SetCheckSum(); //设置当前PE文件的校验和
	DWORD CalcCheckSum(); //计算当前PE文件的校验和(输入整个PE文件，计算出准确的校验和)

	VOID ClosePeFile();
	_PeFile();
	~_PeFile();
} PeFile;

#endif