#ifndef _2CKSTUB_PE_H_
#define _2CKSTUB_PE_H_

#include <Windows.h>
#include <vector>
#include <imagehlp.h>
#pragma comment(lib, "Imagehlp.lib")
#include "file.h"
#include "buf.h"

typedef struct _Type_Offset {
	WORD offset : 12;
	WORD type : 4;
}Type_Offset;

typedef struct _Base_reloc_sec {
	DWORD VirtualAddress;
	DWORD SizeOfBlock;
	std::vector<Type_Offset> TypeOffsetArray;
}Base_reloc_sec;

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
	//��ʼ��peͷ��Ϣ
	BOOL init_peHdr();
	//�ж��Ƿ�ΪPE�ļ�
	BOOL init_checkPeFile();
	//���PE�ļ�������λ��(32��64λ)
	FileBit init_judgeBit();
	//�жϳ����Ƿ��к��ʵĿռ��Բ����µ�������
	BOOL CheckSecTabSpace(UINT numOfInsertSec = 1);
	//�޸�Buffer��С������˽�г�Ա��Ϣ
	VOID ReSize(DWORD newSize);

	//WORD nunOfSec;
	
public:

	// ע�⣬���಻�ṩ����ڴ���ʽ��PE�ļ��Ĵ洢��ʽ�ķ���������ԭ�����ڷ������Buffer���浽ԭ�ļ���

	PIMAGE_DOS_HEADER dosHdr;
	PIMAGE_NT_HEADERS32 ntHdr32;
	PIMAGE_NT_HEADERS64 ntHdr64;
	PIMAGE_SECTION_HEADER firstSecHdr;
	FileBit fileBit; //��ǰPE�ļ�������λ��

	//��ʼ��
	BOOL Init(CHAR* targetFilePath);
	BOOL Init(WCHAR* targetFilePath);

	PIMAGE_FILE_HEADER GetFileHdr(); //��ȡ�ļ�ͷ
	WORD GetSecNum(); //��ȡ��������
	
	std::vector<PIMAGE_SECTION_HEADER> GetSecHdrList(); //��ȡ����ͷ����
	PIMAGE_SECTION_HEADER GetSecHdrByName(CONST CHAR* sectionName); //��������������ȡ��Ӧ����ͷ
	PIMAGE_SECTION_HEADER GetSecHdrByRva(DWORD rvaValue); //����Rva����ȡ��Ӧ����ͷ
	PIMAGE_SECTION_HEADER GetSecHdrByFoa(DWORD foaValue); //����Foa����ȡ��Ӧ����ͷ
	PIMAGE_SECTION_HEADER GetCodeSec(); //��ȡOEP���������Ӧ������ͷ
	PIMAGE_SECTION_HEADER GetRelocSec(); //��ȡ�ض�λ�����������Ӧ������ͷ
	
	DWORD Rva2Foa(DWORD RvaValue); //RVAת��FOA
	DWORD Foa2Rva(DWORD FoaValue); //FOAת��RVA
	DWORD AlignFile(DWORD value); //�ļ�����
	DWORD AlignSection(DWORD value); //�ڴ����

	DWORD GetExportFuncAddrRVA(CHAR* targetFuncName); //��ȡ����������ַ(RVA)

	PIMAGE_DATA_DIRECTORY GetDirByOrder(DirEntryOrder dirOrder); //��ȡ�ض�����Ŀ¼��
	VOID RemoveDebugInfo(); //�����������Ŀ¼����Ϣ(����removeData��ʾ�Ƿ��������Ŀ¼���������õ�����)
	//VOID RemoveExportInfo(); //�����������Ŀ¼����Ϣ(����removeData��ʾ�Ƿ��������Ŀ¼���������õ�����)

	VOID DynamicsBaseOff(); //�رն�̬��ַ
	BOOL AddSection(CONST CHAR* newSecName, DWORD newSecSize, DWORD newSecAttrib, IMAGE_SECTION_HEADER* newSecReturnHdr = NULL, DWORD* newSecReturnFOA = NULL, DWORD* newSecReturnRVA = NULL); //���������
	VOID ExtendLastSection(DWORD addSize, DWORD newSecAttrib, IMAGE_SECTION_HEADER* secReturnHdr = NULL, DWORD* secReturnFOA = NULL, DWORD* secReturnRVA = NULL); //�������һ������
	
	VOID SetOep(DWORD oepValue); //�����µ�OEP��ڵ�
	DWORD GetOep(); //��ȡOEP��ڵ�

	DWORD64 GetImageBase(); //��ȡӳ���ַ (32λ�������н�����ֵǿ��ת����DWORD��)

	DWORD GetCheckSum(); //��ȡ��ǰPE�ļ���У���(ֱ�Ӵ�NTͷ��ȡ)
	VOID SetCheckSum(DWORD checksumValue); //���õ�ǰPE�ļ���У���
	DWORD CalcCheckSum(); //���㵱ǰPE�ļ���У���(��������PE�ļ��������׼ȷ��У���)

	std::vector<PIMAGE_IMPORT_DESCRIPTOR> GetIIDList(); //��ȡIID������б�

	DWORD RemoveDosStub(); //���Dos�����������PEͷ�����ƶ����������ڳ��Ŀ����ֽ���(ͨ����Ϊ�����Ӹ�������ͷ��ʹ�õ�)
	
	std::vector<Base_reloc_sec> GetRelocInfo(); //��PE�ļ��ڵ��ض�λ������ת���ɿ�������ض�λ��Ϣ����
	DWORD RelocInfo2Buf(std::vector<Base_reloc_sec>* inRelocInfo, LocalBuf* outRelocInfoBuf); //���ض�λ��Ϣ����ת�����ض�λ�����ݡ�����Buffer�Ĵ�С(outRelocInfoBuf������δ��ʼ����״̬)
	VOID RepairReloc(DWORD relocBaseFoaAddr, DWORD diffValue); //�޸��ض�λ

	VOID ClosePeFile();
	_PeFile();
	~_PeFile();
} PeFile;

#endif