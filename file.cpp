#include "file.h"

BOOL FileBuf::openFile(CHAR* targetFilePath){
	if (_isLoadFile == TRUE) {
		//errorMsg = "FileBuf object: 文件已打开。";
		lastError = 0;

		return FALSE;
	}
	fileHandle = CreateFileA(targetFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		//errorMsg = "无法打开文件。";
		lastError = GetLastError();

		return FALSE;
	}
	LARGE_INTEGER fileSizeInfo = { 0 };
	if (GetFileSizeEx(fileHandle, &fileSizeInfo) == FALSE) {
		//errorMsg = "获取文件大小失败。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (fileSizeInfo.HighPart != 0) {
		//errorMsg = "文件大小过大。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	fileSize = fileSizeInfo.LowPart;
	if (fileSize <= 0) {
		//errorMsg = "文件大小获取异常。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	fileBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	if (fileBuffer == NULL) {
		//errorMsg = "申请缓冲区失败。(无LastError值)";
		lastError = 0;
		CloseHandle(fileHandle);

		return FALSE;
	}
	DWORD dwNumOfRead = 0;
	if (SetFilePointer(fileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		//errorMsg = "移动指针到头部失败。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (ReadFile(fileHandle, fileBuffer, fileSize, &dwNumOfRead, NULL) == FALSE) {
		lastError = GetLastError();
		CloseHandle(fileHandle);
		HeapFree(GetProcessHeap(), NULL, fileBuffer);

		return FALSE;
	}

	_isLoadFile = TRUE;
	return TRUE;
}

BOOL FileBuf::openFile(WCHAR* targetFilePath){
	if (_isLoadFile == TRUE) {
		//errorMsg = "FileBuf object: 文件已打开。";
		lastError = 0;

		return FALSE;
	}
	fileHandle = CreateFileW(targetFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		//errorMsg = "无法打开文件。";
		lastError = GetLastError();

		return FALSE;
	}
	LARGE_INTEGER fileSizeInfo = { 0 };
	if (GetFileSizeEx(fileHandle, &fileSizeInfo) == FALSE) {
		//errorMsg = "获取文件大小失败。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (fileSizeInfo.HighPart != 0) {
		//errorMsg = "文件大小过大。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	fileSize = fileSizeInfo.LowPart;
	if (fileSize <= 0) {
		//errorMsg = "文件大小获取异常。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	fileBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	if (fileBuffer == NULL) {
		//errorMsg = "申请缓冲区失败。(无LastError值)";
		lastError = 0;
		CloseHandle(fileHandle);

		return FALSE;
	}
	DWORD dwNumOfRead = 0;
	if (SetFilePointer(fileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		//errorMsg = "移动指针到头部失败。";
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (ReadFile(fileHandle, fileBuffer, fileSize, &dwNumOfRead, NULL) == FALSE) {
		lastError = GetLastError();
		CloseHandle(fileHandle);
		HeapFree(GetProcessHeap(), NULL, fileBuffer);

		return FALSE;
	}

	_isLoadFile = TRUE;
	return TRUE;
}

LPVOID FileBuf::getBufAddr(){
	if (_isLoadFile == FALSE) {
		return 0;
	}
    return fileBuffer;
}

DWORD FileBuf::getBufSize(){
	if (_isLoadFile == FALSE) {
		return 0;
	}
    return fileSize;
}

DWORD FileBuf::getLastError(){
	if (_isLoadFile == FALSE) {
		return 0;
	}
	return lastError;
}

HANDLE FileBuf::getFileHandle(){
	if (_isLoadFile == FALSE) {
		return 0;
	}
	return fileHandle;
}

VOID FileBuf::close(){
	if (_isLoadFile == FALSE) {
		return;
	}
	fileSize = 0;
	//errorMsg = "";
	lastError = 0;
	if (fileBuffer != 0) {
		HeapFree(GetProcessHeap(), NULL, fileBuffer);
		fileBuffer = 0;
	}
	if (fileHandle != 0) {
		CloseHandle(fileHandle);
		fileHandle = 0;
	}
	_isLoadFile = FALSE;
}


FileBuf::~FileBuf(){
	close();
}

FileBuf::FileBuf(){
	fileHandle = 0;
	fileBuffer = 0;
	fileSize = 0;
	//errorMsg = "";
	lastError = 0;
	_isLoadFile = FALSE;
}