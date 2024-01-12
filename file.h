#ifndef _2CKSTUB_FILE_H_
#define _2CKSTUB_FILE_H_

#include <Windows.h>

class FileBuf {
private:
	HANDLE fileHandle;
	LPVOID fileBuffer;
	DWORD fileSize;
	DWORD lastError;

	BOOL _isLoadFile;
public:
	BOOL openFile(CHAR* targetFilePath);
	BOOL openFile(WCHAR* targetFilePath);
	LPVOID getBufAddr();
	DWORD getBufSize();
	DWORD getLastError();
	HANDLE getFileHandle();
	VOID close();

	~FileBuf();
	FileBuf();
};

#endif