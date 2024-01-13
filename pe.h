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

	//�ж��Ƿ�ΪPE�ļ�
	BOOL init_checkPeFile();
	//���PE�ļ�������λ��(32��64λ)
	FileBit init_judgeBit();

	LocalBuf memBuf;
	VOID VirtualLoad(); //��PE�ļ��������ڴ���ʽ
	VOID VirtualUpdate(); //���ڴ���ʽ�ڵ�ȫ�����Ķ����µ��ļ���ʽ��PE�ļ���
	
public:
	PIMAGE_DOS_HEADER dosHdr;
	PIMAGE_NT_HEADERS32 ntHdr32;
	PIMAGE_NT_HEADERS64 ntHdr64;
	PIMAGE_SECTION_HEADER firstSecHdr;
	FileBit fileBit; //��ǰPE�ļ�������λ��

	//��ʼ��
	BOOL Init(CHAR* targetFilePath);
	BOOL Init(WCHAR* targetFilePath);
	
	std::vector<PIMAGE_SECTION_HEADER> GetSecHdrList(); //��ȡ����ͷ����
	
	DWORD Rva2Foa(DWORD RvaValue); //RVAת��FOA
	DWORD Foa2Rva(DWORD FoaValue); //FOAת��RVA

	//����Ϊ����д����

	DWORD64 GetExportFuncAddrRVA(); //��ȡ����������ַ(RVA)
	DWORD64 GetExportFuncAddrVA(); //��ȡ����������ַ(VA)


	VOID ClosePeFile();
	_PeFile();
	~_PeFile();
} PeFile;

#endif