#ifndef _2CKSTUB_PACKER_H_
#define _2CKSTUB_PACKER_H_

#include <Windows.h>
#include "pe.h"
#include "Public\StubInfo_Public.h"

#define _SEC_READ IMAGE_SCN_MEM_READ
#define _SEC_WRITE IMAGE_SCN_MEM_WRITE
#define _SEC_EXEC IMAGE_SCN_MEM_EXECUTE
#define _SEC_CODE IMAGE_SCN_CNT_CODE
#define _SEC_INITDATA IMAGE_SCN_CNT_INITIALIZED_DATA
#define SEC_ATTRIB_RWE (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)

#define CODE_SECTION_NAME ".ck0"
#define CODEINFO_SECTION_NAME ".ck1"

namespace Ck2Stub {
	DWORD WINAPI GetStubOriginEntryPointOffset(PeFile* stubFile);
	DWORD WINAPI GetStubShareInfoOffset(PeFile* stubFile);
	

	BOOL WINAPI Pack(CHAR* targetFilePath, CHAR* stubFilePath, CHAR* saveFilePath);

	VOID TlsPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info);
	VOID IatPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info);
	VOID RelocPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info);
	VOID BoundImportPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info);
	VOID ResourcePack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info);
	VOID CodeProtectPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info);

	VOID RemoveSectionName(PeFile* stubFile, WORD secNum);
	VOID UpdataChecksum(PeFile* stubFile);
}

#endif