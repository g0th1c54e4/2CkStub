#include <Windows.h>
#include "pe.h"

BOOL __stdcall CheckPeFile(LPVOID buffer) {
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS32 ntHdr = (PIMAGE_NT_HEADERS32)((DWORD64)buffer + dosHdr->e_lfanew);
	return (dosHdr->e_magic == IMAGE_DOS_SIGNATURE && ntHdr->Signature == IMAGE_NT_SIGNATURE);
}

BOOL _PeFile::init(CHAR* targetFilePath){
	if (file.openFile(targetFilePath) == FALSE) {
		return FALSE;
	}
	dosHdr = (PIMAGE_DOS_HEADER)(file.getBufAddr());
	//if (checkPeFile() == FALSE) {

	return checkPeFile();

}

BOOL _PeFile::init(WCHAR* targetFilePath){
	if (file.openFile(targetFilePath) == FALSE) {
		return FALSE;
	}
	dosHdr = (PIMAGE_DOS_HEADER)(file.getBufAddr());
	//if (checkPeFile() == FALSE) {

	return checkPeFile();
}

BOOL _PeFile::checkPeFile(){
	PIMAGE_NT_HEADERS32 ntHdr = (PIMAGE_NT_HEADERS32)((DWORD64)file.getBufAddr() + dosHdr->e_lfanew);
	return (dosHdr->e_magic == IMAGE_DOS_SIGNATURE && ntHdr->Signature == IMAGE_NT_SIGNATURE);
}

