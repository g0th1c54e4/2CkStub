#ifndef _2CKSTUB_PE_H_
#define _2CKSTUB_PE_H_

#include <Windows.h>
#include "file.h"

BOOL __stdcall CheckPeFile(LPVOID buffer);

typedef class _PeFile {
private:
	FileBuf file;


	PIMAGE_DOS_HEADER dosHdr;
	
public:
	BOOL init(CHAR* targetFilePath);
	BOOL init(WCHAR* targetFilePath);
	BOOL checkPeFile();


}PeFile;

#endif