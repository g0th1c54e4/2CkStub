#ifndef _2CKSTUB_FILE_H_
#define _2CKSTUB_FILE_H_

#include <Windows.h>
#include "buf.h"

typedef class _FileBuf : public LocalBuf { //��ʵFileBuf��Ӧ�ü̳�LocalBuf��
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

	BOOL Save(); //���浱ǰ�ļ�
	BOOL SaveAs(CHAR* saveFilePath); //���浽��һ���ļ�
	BOOL SaveAs(WCHAR* saveFilePath); //���浽��һ���ļ�

	~_FileBuf();
	_FileBuf();
} FileBuf;

#endif