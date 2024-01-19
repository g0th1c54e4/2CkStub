#ifndef _2CKSTUB_PACKER_H_
#define _2CKSTUB_PACKER_H_

#include <Windows.h>
#include "pe.h"
#include "Public\StubInfo_Public.h"

#define CODE_SECTION_NAME "CK0"
#define CODEINFO_SECTION_NAME "CK1"

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