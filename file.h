#ifndef _2CKSTUB_FILE_H_
#define _2CKSTUB_FILE_H_

#include <Windows.h>
#include "buf.h"

typedef class _FileBuf : public LocalBuf { //其实FileBuf不应该继承LocalBuf的
private:
	DWORD lastError;
	BOOL _isLoadFile;
protected:
	HANDLE fileHandle;
	DWORD GetLastError();
public:
	BOOL OpenFile(CHAR* targetFilePath);
	BOOL OpenFile(WCHAR* targetFilePath);
	VOID CloseFile();

	BOOL Save(); //保存当前文件
	BOOL SaveAs(CHAR* saveFilePath); //保存到另一个文件
	BOOL SaveAs(WCHAR* saveFilePath); //保存到另一个文件

	~_FileBuf();
	_FileBuf();
} FileBuf;

#endif