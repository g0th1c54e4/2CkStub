#ifndef _2CKSTUB_PACKER_H_
#define _2CKSTUB_PACKER_H_

#include <Windows.h>
#include "pe.h"

namespace Ck2Stub {

	BOOL WINAPI Pack(CHAR* targetFilePath, CHAR* stubFilePath, CONST CHAR* stubSecName, CHAR* saveFilePath);
	DWORD WINAPI GetStubOriginEntryPointOffset(PeFile* stubFile);

	VOID TlsPack();
	VOID IatPack();

}


#endif