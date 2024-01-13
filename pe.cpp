#include <Windows.h>
#include "pe.h"

BOOL _PeFile::Init(CHAR* targetFilePath){
	if (this->OpenFile(targetFilePath) == FALSE) {
		return FALSE;
	}
	dosHdr = (PIMAGE_DOS_HEADER)(this->bufAddr);
	ntHdr32 = (PIMAGE_NT_HEADERS32)((DWORD64)this->bufAddr + dosHdr->e_lfanew);
	ntHdr64 = (PIMAGE_NT_HEADERS64)((DWORD64)this->bufAddr + dosHdr->e_lfanew);
	if (init_checkPeFile() == FALSE) {
		return FALSE;
	}
	fileBit = init_judgeBit();
	switch (fileBit){
	case Bit32:
		firstSecHdr = IMAGE_FIRST_SECTION32(ntHdr32);
		break;
	case Bit64:
		firstSecHdr = IMAGE_FIRST_SECTION64(ntHdr64);
		break;
	}
	return TRUE;
}

BOOL _PeFile::Init(WCHAR* targetFilePath){
	if (this->OpenFile(targetFilePath) == FALSE) {
		return FALSE;
	}
	dosHdr = (PIMAGE_DOS_HEADER)(this->bufAddr);
	ntHdr32 = (PIMAGE_NT_HEADERS32)((DWORD64)this->bufAddr + dosHdr->e_lfanew);
	ntHdr64 = (PIMAGE_NT_HEADERS64)((DWORD64)this->bufAddr + dosHdr->e_lfanew);
	if (init_checkPeFile() == FALSE) {
		return FALSE;
	}
	fileBit = init_judgeBit();
	switch (fileBit) {
	case Bit32:
		firstSecHdr = IMAGE_FIRST_SECTION32(ntHdr32);
		break;
	case Bit64:
		firstSecHdr = IMAGE_FIRST_SECTION64(ntHdr64);
		break;
	}
	return TRUE;
}

BOOL _PeFile::init_checkPeFile(){
	return (dosHdr->e_magic == IMAGE_DOS_SIGNATURE && ntHdr32->Signature == IMAGE_NT_SIGNATURE);
}

FileBit _PeFile::init_judgeBit(){  // 1 ==> 64Bit¡¢0 ==> 32Bit
	if ((ntHdr32->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == 0) {
		return Bit64;
	}
	else {
		return Bit32;
	}
}

VOID _PeFile::VirtualLoad(){

	return VOID();
}

VOID _PeFile::VirtualUpdate(){

	return VOID();
}

std::vector<PIMAGE_SECTION_HEADER> _PeFile::GetSecHdrList(){
	std::vector<PIMAGE_SECTION_HEADER> resultSecHdrList;
	for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
		resultSecHdrList.push_back((firstSecHdr + i));
	}
	return resultSecHdrList;
}

DWORD _PeFile::Rva2Foa(DWORD RvaValue){
	switch (fileBit){
	case Bit32:
		if (RvaValue < ntHdr32->OptionalHeader.SizeOfHeaders) {
			return RvaValue;
		}
		for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
			if (RvaValue >= firstSecHdr[i].VirtualAddress && RvaValue < firstSecHdr[i].VirtualAddress + firstSecHdr[i].SizeOfRawData) {
				DWORD ret = (RvaValue - firstSecHdr[i].VirtualAddress) + firstSecHdr[i].PointerToRawData;
				return ret;
			}
		}
		return 0;
	case Bit64:
		if (RvaValue < ntHdr64->OptionalHeader.SizeOfHeaders) {
			return RvaValue;
		}
		for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
			if (RvaValue >= firstSecHdr[i].VirtualAddress && RvaValue < firstSecHdr[i].VirtualAddress + firstSecHdr[i].SizeOfRawData) {
				DWORD ret = (RvaValue - firstSecHdr[i].VirtualAddress) + firstSecHdr[i].PointerToRawData;
				return ret;
			}
		}
		return 0;
	default:
		return 0;
	}
	
}

DWORD _PeFile::Foa2Rva(DWORD FoaValue){
	switch (fileBit){
	case Bit32:
		if (FoaValue < ntHdr32->OptionalHeader.SizeOfHeaders) {
			return FoaValue;
		}
		for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
			if (FoaValue >= firstSecHdr[i].PointerToRawData && FoaValue < firstSecHdr[i].PointerToRawData + firstSecHdr[i].SizeOfRawData) {
				DWORD ret = (FoaValue - firstSecHdr[i].PointerToRawData) + firstSecHdr[i].VirtualAddress;
				return ret;
			}
		}
		return 0;
	case Bit64:
		if (FoaValue < ntHdr64->OptionalHeader.SizeOfHeaders) {
			return FoaValue;
		}
		for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
			if (FoaValue >= firstSecHdr[i].PointerToRawData && FoaValue < firstSecHdr[i].PointerToRawData + firstSecHdr[i].SizeOfRawData) {
				DWORD ret = (FoaValue - firstSecHdr[i].PointerToRawData) + firstSecHdr[i].VirtualAddress;
				return ret;
			}
		}
		return 0;
	default:
		return 0;
	}
}

DWORD64 _PeFile::GetExportFuncAddrRVA(){
	//pass
	return DWORD64();
}

DWORD64 _PeFile::GetExportFuncAddrVA(){
	//pass
	return DWORD64();
}

_PeFile::_PeFile() {
	dosHdr = 0;
	ntHdr32 = 0;
	ntHdr64 = 0;
	fileBit = Bit32;
	firstSecHdr = 0;
}

VOID _PeFile::ClosePeFile(){
	dosHdr = 0;
	ntHdr32 = 0;
	ntHdr64 = 0;
	fileBit = Bit32;
	firstSecHdr = 0;
	memBuf.FreeBuffer();
	this->CloseFile();
}

_PeFile::~_PeFile(){
	ClosePeFile();
}