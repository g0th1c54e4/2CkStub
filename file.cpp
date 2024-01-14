#include "file.h"

BOOL _FileBuf::OpenFile(CHAR* targetFilePath){
	if (_isLoadFile == TRUE) {
		//FileBuf object: 文件已打开。
		lastError = 0;

		return FALSE;
	}
	fileHandle = CreateFileA(targetFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		//无法打开文件。
		lastError = GetLastError();

		return FALSE;
	}
	LARGE_INTEGER fileSizeInfo = { 0 };
	if (GetFileSizeEx(fileHandle, &fileSizeInfo) == FALSE) {
		//获取文件大小失败。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (fileSizeInfo.HighPart != 0) {
		//文件大小过大。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	DWORD fileSize = fileSizeInfo.LowPart;
	if (fileSize <= 0) {
		//文件大小获取异常。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (this->CreateBuffer(fileSize, HEAP_ZERO_MEMORY) == FALSE) {
		//申请缓冲区失败。(无LastError值)
		lastError = 0;
		CloseHandle(fileHandle);

		return FALSE;
	}

	DWORD dwNumOfRead = 0;
	if (SetFilePointer(fileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		//移动指针到头部失败。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (ReadFile(fileHandle, this->bufAddr, fileSize, &dwNumOfRead, NULL) == FALSE) {
		lastError = GetLastError();
		CloseHandle(fileHandle);
		this->FreeBuffer();

		return FALSE;
	}

	_isLoadFile = TRUE;
	return TRUE;
}

BOOL _FileBuf::OpenFile(WCHAR* targetFilePath){
	if (_isLoadFile == TRUE) {
		//FileBuf object: 文件已打开。
		lastError = 0;

		return FALSE;
	}
	fileHandle = CreateFileW(targetFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		//无法打开文件。
		lastError = GetLastError();

		return FALSE;
	}
	LARGE_INTEGER fileSizeInfo = { 0 };
	if (GetFileSizeEx(fileHandle, &fileSizeInfo) == FALSE) {
		//获取文件大小失败。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (fileSizeInfo.HighPart != 0) {
		//文件大小过大。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	DWORD fileSize = fileSizeInfo.LowPart;
	if (fileSize <= 0) {
		//文件大小获取异常。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (this->CreateBuffer(fileSize) == FALSE) {
		//申请缓冲区失败。(无LastError值)
		lastError = 0;
		CloseHandle(fileHandle);

		return FALSE;
	}

	DWORD dwNumOfRead = 0;
	if (SetFilePointer(fileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		//移动指针到头部失败。
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (ReadFile(fileHandle, this->bufAddr, fileSize, &dwNumOfRead, NULL) == FALSE) {
		lastError = GetLastError();
		CloseHandle(fileHandle);
		this->FreeBuffer();

		return FALSE;
	}

	_isLoadFile = TRUE;
	return TRUE;
}

DWORD _FileBuf::GetLastError(){
	if (_isLoadFile == FALSE) {
		return 0;
	}
	return lastError;
}

VOID _FileBuf::CloseFile(){
	if (_isLoadFile == FALSE) {
		return;
	}
	lastError = 0;
	
	this->FreeBuffer();

	if (fileHandle != 0) {
		CloseHandle(fileHandle);
		fileHandle = 0;
	}
	_isLoadFile = FALSE;
}

BOOL _FileBuf::Save(){
	if (_isLoadFile == FALSE) {
		return FALSE;
	}

	DWORD dwNumOfRead = 0;
	if (SetFilePointer(fileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		CloseHandle(fileHandle);
		return FALSE;
	}
	if (WriteFile(fileHandle, this->bufAddr, this->bufSize, &dwNumOfRead, NULL) == FALSE) {
		CloseHandle(fileHandle);
		return FALSE;
	}
	return TRUE;
}

BOOL _FileBuf::SaveAs(CHAR* saveFilePath){
	if (_isLoadFile == FALSE) {
		return FALSE;
	}
	HANDLE hFileHandle = CreateFileA(saveFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	DWORD dwNumOfRead = 0;
	if (SetFilePointer(hFileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		CloseHandle(hFileHandle);
		return FALSE;
	}
	if (ReadFile(hFileHandle, this->bufAddr, this->bufSize, &dwNumOfRead, NULL) == FALSE) {
		CloseHandle(hFileHandle);
		return FALSE;
	}
	return TRUE;
}

BOOL _FileBuf::SaveAs(WCHAR* saveFilePath){
	if (_isLoadFile == FALSE) {
		return FALSE;
	}
	HANDLE hFileHandle = CreateFileW(saveFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	DWORD dwNumOfRead = 0;
	if (SetFilePointer(hFileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		CloseHandle(hFileHandle);
		return FALSE;
	}
	if (ReadFile(hFileHandle, this->bufAddr, this->bufSize, &dwNumOfRead, NULL) == FALSE) {
		CloseHandle(hFileHandle);
		return FALSE;
	}
	return TRUE;
}

_FileBuf::~_FileBuf(){
	CloseFile();
}

_FileBuf::_FileBuf(){
	fileHandle = 0;
	lastError = 0;
	_isLoadFile = FALSE;
}