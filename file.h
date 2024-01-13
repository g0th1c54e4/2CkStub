#ifndef _2CKSTUB_FILE_H_
#define _2CKSTUB_FILE_H_

#include <Windows.h>
#include "buf.h"

typedef class _FileBuf : public LocalBuf {
private:
	DWORD lastError;
	BOOL _isLoadFile;
protected:
	HANDLE fileHandle;
public:
	BOOL OpenFile(CHAR* targetFilePath);
	BOOL OpenFile(WCHAR* targetFilePath);
	DWORD GetLastError();
	HANDLE GetFileHandle();
	VOID CloseFile();

	~_FileBuf();
	_FileBuf();
} FileBuf;

#endif