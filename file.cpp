#include "file.h"

BOOL _FileBuf::OpenFile(CHAR* targetFilePath){
	if (_isLoadFile == TRUE) {
		//FileBuf object: �ļ��Ѵ򿪡�
		lastError = 0;

		return FALSE;
	}
	fileHandle = CreateFileA(targetFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		//�޷����ļ���
		lastError = GetLastError();

		return FALSE;
	}
	LARGE_INTEGER fileSizeInfo = { 0 };
	if (GetFileSizeEx(fileHandle, &fileSizeInfo) == FALSE) {
		//��ȡ�ļ���Сʧ�ܡ�
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (fileSizeInfo.HighPart != 0) {
		//�ļ���С����
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	DWORD fileSize = fileSizeInfo.LowPart;
	if (fileSize <= 0) {
		//�ļ���С��ȡ�쳣��
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (this->CreateBuffer(fileSize, HEAP_ZERO_MEMORY) == FALSE) {
		//���뻺����ʧ�ܡ�(��LastErrorֵ)
		lastError = 0;
		CloseHandle(fileHandle);

		return FALSE;
	}

	DWORD dwNumOfRead = 0;
	if (SetFilePointer(fileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		//�ƶ�ָ�뵽ͷ��ʧ�ܡ�
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
		//FileBuf object: �ļ��Ѵ򿪡�
		lastError = 0;

		return FALSE;
	}
	fileHandle = CreateFileW(targetFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		//�޷����ļ���
		lastError = GetLastError();

		return FALSE;
	}
	LARGE_INTEGER fileSizeInfo = { 0 };
	if (GetFileSizeEx(fileHandle, &fileSizeInfo) == FALSE) {
		//��ȡ�ļ���Сʧ�ܡ�
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (fileSizeInfo.HighPart != 0) {
		//�ļ���С����
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	DWORD fileSize = fileSizeInfo.LowPart;
	if (fileSize <= 0) {
		//�ļ���С��ȡ�쳣��
		lastError = GetLastError();
		CloseHandle(fileHandle);

		return FALSE;
	}
	if (this->CreateBuffer(fileSize) == FALSE) {
		//���뻺����ʧ�ܡ�(��LastErrorֵ)
		lastError = 0;
		CloseHandle(fileHandle);

		return FALSE;
	}

	DWORD dwNumOfRead = 0;
	if (SetFilePointer(fileHandle, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		//�ƶ�ָ�뵽ͷ��ʧ�ܡ�
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

HANDLE _FileBuf::GetFileHandle(){
	if (_isLoadFile == FALSE) {
		return 0;
	}
	return fileHandle;
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

_FileBuf::~_FileBuf(){
	CloseFile();
}

_FileBuf::_FileBuf(){
	fileHandle = 0;
	lastError = 0;
	_isLoadFile = FALSE;
}