#ifndef _2CKSTUB_PACKER_H_
#define _2CKSTUB_PACKER_H_

#include <Windows.h>
#include "pe.h"

#define CK2STUB_SECTION_ATTRIB (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA)
#define CODE_SECTION_NAME ".ck0"
#define CODEINFO_SECTION_NAME ".ck1"

namespace Ck2Stub {
	DWORD WINAPI GetStubOriginEntryPointOffset(PeFile* stubFile);


	BOOL WINAPI Pack(CHAR* targetFilePath, CHAR* stubFilePath, CHAR* saveFilePath);

	VOID TlsPack(PeFile* targetFile, PeFile* stubFile);
	VOID IatPack(PeFile* targetFile, PeFile* stubFile);
	VOID RelocPack(PeFile* targetFile, PeFile* stubFile);
	VOID BoundImportPack(PeFile* targetFile, PeFile* stubFile);
	VOID ResourcePack(PeFile* targetFile, PeFile* stubFile);

}

#endif