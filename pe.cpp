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

FileBit _PeFile::init_judgeBit(){  // 1 ==> 64Bit、0 ==> 32Bit
	if ((ntHdr32->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == 0) {
		return Bit64;
	}
	else {
		return Bit32;
	}
}

BOOL _PeFile::CheckSecTabSpace(UINT numOfInsertSec){
	if (numOfInsertSec <= 0) {
		return FALSE;
	}
	UINT numOfSec = this->ntHdr32->FileHeader.NumberOfSections;

	DWORD secTabSize = sizeof(IMAGE_SECTION_HEADER) * (numOfSec + numOfInsertSec);
	DWORD secTabAddr = (DWORD)((DWORD64)firstSecHdr - (DWORD64)this->bufAddr);
	for (UINT i = 0; i < numOfSec; i++) {
		if ((secTabAddr + secTabSize) >= firstSecHdr[i].PointerToRawData && (firstSecHdr[i].PointerToRawData != 0 && firstSecHdr[i].SizeOfRawData != 0)) {
			return FALSE;
		}
	}

	return TRUE;
}

VOID _PeFile::ReSize(DWORD newSize){

	this->ReBufferSize(newSize);

	dosHdr = (PIMAGE_DOS_HEADER)(this->bufAddr);
	ntHdr32 = (PIMAGE_NT_HEADERS32)((DWORD64)this->bufAddr + dosHdr->e_lfanew);
	ntHdr64 = (PIMAGE_NT_HEADERS64)((DWORD64)this->bufAddr + dosHdr->e_lfanew);
	if (init_checkPeFile() == FALSE) {
		return;
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
}

std::vector<PIMAGE_SECTION_HEADER> _PeFile::GetSecHdrList(){
	std::vector<PIMAGE_SECTION_HEADER> resultSecHdrList;
	for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
		resultSecHdrList.push_back((firstSecHdr + i));
	}
	return resultSecHdrList;
}

PIMAGE_SECTION_HEADER _PeFile::GetSecHdrByName(CONST CHAR* sectionName){
	for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
		if (strcmp((LPCSTR)firstSecHdr[i].Name, sectionName) == 0) {
			return (firstSecHdr + i);
		}
	}
	return 0;
}

PIMAGE_SECTION_HEADER _PeFile::GetSecHdrByRva(DWORD rvaValue){
	for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
		if (rvaValue >= firstSecHdr[i].VirtualAddress && rvaValue <= firstSecHdr[i].VirtualAddress + firstSecHdr[i].Misc.VirtualSize) {
			return (firstSecHdr + i);
		}
	}
	return 0;
}

PIMAGE_SECTION_HEADER _PeFile::GetSecHdrByFoa(DWORD foaValue){
	for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
		if (foaValue >= firstSecHdr[i].PointerToRawData && foaValue <= firstSecHdr[i].PointerToRawData + firstSecHdr[i].SizeOfRawData) {
			return (firstSecHdr + i);
		}
	}
	return 0;
}

PIMAGE_SECTION_HEADER _PeFile::GetCodeSec(){
	DWORD oepAddr = this->ntHdr32->OptionalHeader.AddressOfEntryPoint;

	switch (fileBit) {
	case Bit32:
		for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
			if ((oepAddr >= firstSecHdr[i].VirtualAddress) && (oepAddr <= (firstSecHdr[i].VirtualAddress + firstSecHdr[i].Misc.VirtualSize))) {
				return (firstSecHdr + i);
			}
		}
		return 0;
	case Bit64:
		for (int i = 0; i < ntHdr64->FileHeader.NumberOfSections; i++) {
			if ((oepAddr >= firstSecHdr[i].VirtualAddress) && (oepAddr <= (firstSecHdr[i].VirtualAddress + firstSecHdr[i].Misc.VirtualSize))) {
				return (firstSecHdr + i);
			}
		}
		return 0;
	}
	return 0;
}

PIMAGE_SECTION_HEADER _PeFile::GetRelocSec(){
	DWORD relocDirAddr = this->ntHdr32->OptionalHeader.DataDirectory[Dir_BaseReloc].VirtualAddress;

	switch (fileBit) {
	case Bit32:
		for (int i = 0; i < ntHdr32->FileHeader.NumberOfSections; i++) {
			if ((relocDirAddr >= firstSecHdr[i].VirtualAddress) && (relocDirAddr <= (firstSecHdr[i].VirtualAddress + firstSecHdr[i].Misc.VirtualSize))) {
				return (firstSecHdr + i);
			}
		}
		return 0;
	case Bit64:
		for (int i = 0; i < ntHdr64->FileHeader.NumberOfSections; i++) {
			if ((relocDirAddr >= firstSecHdr[i].VirtualAddress) && (relocDirAddr <= (firstSecHdr[i].VirtualAddress + firstSecHdr[i].Misc.VirtualSize))) {
				return (firstSecHdr + i);
			}
		}
		return 0;
	}
	return 0;
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
		for (int i = 0; i < ntHdr64->FileHeader.NumberOfSections; i++) {
			if (RvaValue >= firstSecHdr[i].VirtualAddress && RvaValue < firstSecHdr[i].VirtualAddress + firstSecHdr[i].SizeOfRawData) {
				DWORD ret = (RvaValue - firstSecHdr[i].VirtualAddress) + firstSecHdr[i].PointerToRawData;
				return ret;
			}
		}
		return 0;
	}
	return 0;
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
		for (int i = 0; i < ntHdr64->FileHeader.NumberOfSections; i++) {
			if (FoaValue >= firstSecHdr[i].PointerToRawData && FoaValue < firstSecHdr[i].PointerToRawData + firstSecHdr[i].SizeOfRawData) {
				DWORD ret = (FoaValue - firstSecHdr[i].PointerToRawData) + firstSecHdr[i].VirtualAddress;
				return ret;
			}
		}
		return 0;
	}
	return 0;
}

DWORD _PeFile::AlignFile(DWORD value){
	switch (fileBit){
	case Bit32:
		if (value / ntHdr32->OptionalHeader.FileAlignment * ntHdr32->OptionalHeader.FileAlignment == value) {
			return value;
		}
		return ((value / ntHdr32->OptionalHeader.FileAlignment) + 1) * ntHdr32->OptionalHeader.FileAlignment;
	case Bit64:
		if (value / ntHdr64->OptionalHeader.FileAlignment * ntHdr64->OptionalHeader.FileAlignment == value) {
			return value;
		}
		return ((value / ntHdr64->OptionalHeader.FileAlignment) + 1) * ntHdr64->OptionalHeader.FileAlignment;
	}
	return 0;
}

DWORD _PeFile::AlignSection(DWORD value){
	switch (fileBit) {
	case Bit32:
		if (value / ntHdr32->OptionalHeader.SectionAlignment * ntHdr32->OptionalHeader.SectionAlignment == value) {
			return value;
		}
		return ((value / ntHdr32->OptionalHeader.SectionAlignment) + 1) * ntHdr32->OptionalHeader.SectionAlignment;
	case Bit64:
		if (value / ntHdr64->OptionalHeader.SectionAlignment * ntHdr64->OptionalHeader.SectionAlignment == value) {
			return value;
		}
		return ((value / ntHdr64->OptionalHeader.SectionAlignment) + 1) * ntHdr64->OptionalHeader.SectionAlignment;
	}
	return 0;
}

DWORD _PeFile::GetExportFuncAddrRVA(CHAR* targetFuncName){
	PIMAGE_EXPORT_DIRECTORY pExport = 0;
	if (fileBit == Bit32) {
		pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)this->bufAddr + Rva2Foa(ntHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	}
	if (fileBit == Bit64) {
		pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)this->bufAddr + Rva2Foa(ntHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	}
	DWORD dwNum = pExport->NumberOfFunctions;

	PDWORD pdwName = (PDWORD)(Rva2Foa(pExport->AddressOfNames) + (DWORD64)this->bufAddr);
	PWORD pwOrder = (PWORD)(Rva2Foa(pExport->AddressOfNameOrdinals) + (DWORD64)this->bufAddr);
	PDWORD pdwFuncAddr = (PDWORD)(Rva2Foa(pExport->AddressOfFunctions) + (DWORD64)this->bufAddr);

	for (UINT i = 0; i < dwNum; i++) {
		LPCSTR lpFuncName = (LPCSTR)(Rva2Foa(pdwName[i]) + (DWORD64)this->bufAddr);
		if (strcmp(lpFuncName, targetFuncName) == 0) {
			WORD wOrd = pwOrder[i];
			return (DWORD64)pdwFuncAddr[wOrd];
		}
	}
	
	return 0;
}

PIMAGE_DATA_DIRECTORY _PeFile::GetDirByOrder(DirEntryOrder dirOrder){
	if (fileBit == Bit32) {
		return ((ntHdr32->OptionalHeader.DataDirectory) + dirOrder);
	}
	if (fileBit == Bit64) {
		return ((ntHdr64->OptionalHeader.DataDirectory) + dirOrder);
	}
	return 0;
}

VOID _PeFile::RemoveDebugInfo() {
	PIMAGE_DATA_DIRECTORY dirDebug = GetDirByOrder(Dir_Debug);
	if (dirDebug->VirtualAddress == 0 || dirDebug->Size == 0) {
		return;
	}
	PIMAGE_DEBUG_DIRECTORY pDebug = (PIMAGE_DEBUG_DIRECTORY)((DWORD64)this->bufAddr + Rva2Foa(dirDebug->VirtualAddress));
	RtlZeroMemory((LPVOID)((DWORD64)this->bufAddr + pDebug->PointerToRawData), pDebug->SizeOfData);
	RtlZeroMemory(pDebug, dirDebug->Size);
}

VOID _PeFile::RemoveExportInfo(){
	PIMAGE_DATA_DIRECTORY dirExport = GetDirByOrder(Dir_Export);
	if (dirExport->VirtualAddress == 0 || dirExport->Size == 0) {
		return;
	}
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)this->bufAddr + Rva2Foa(dirExport->VirtualAddress));
	RtlZeroMemory(pExport, dirExport->Size);
}

VOID _PeFile::DynamicsBaseOff(){
	if (fileBit == Bit32) {
		if ((ntHdr32->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0) {
			ntHdr32->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
		}
		if ((ntHdr32->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0) {
			ntHdr32->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		}
	}
	if (fileBit == Bit64) {
		if ((ntHdr64->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0) {
			ntHdr64->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
		}
		if ((ntHdr64->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0) {
			ntHdr64->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		}
	}
}

BOOL _PeFile::AddSection(CONST CHAR* newSecName, DWORD newSecSize, DWORD newSecAttrib, IMAGE_SECTION_HEADER* newSecReturnHdr, DWORD* newSecReturnFOA){
	
	if (CheckSecTabSpace(1) == FALSE) {
		return FALSE;
	}
	UINT numOfSec = this->ntHdr32->FileHeader.NumberOfSections;

	memset(&firstSecHdr[numOfSec + 1], 0, sizeof(IMAGE_SECTION_HEADER));
	PIMAGE_SECTION_HEADER newSec = &firstSecHdr[numOfSec];
	PIMAGE_SECTION_HEADER lastSec = &firstSecHdr[numOfSec - 1];

	IMAGE_SECTION_HEADER sec = { 0 };
	RtlCopyMemory(sec.Name, newSecName, 8);
	sec.Characteristics = newSecAttrib;
	sec.VirtualAddress = AlignSection(lastSec->VirtualAddress + lastSec->Misc.VirtualSize);
	sec.Misc.VirtualSize = newSecSize;
	sec.PointerToRawData = AlignFile(lastSec->PointerToRawData + lastSec->SizeOfRawData);
	sec.SizeOfRawData = AlignFile(newSecSize);
	RtlCopyMemory(newSec, &sec, sizeof(IMAGE_SECTION_HEADER));
	ntHdr32->FileHeader.NumberOfSections += 1;

	if (fileBit == Bit32) {
		//ntHdr32->OptionalHeader.SizeOfHeaders += sizeof(IMAGE_SECTION_HEADER); //可能不需要? 以后取消这个注释再看看效果
		ntHdr32->OptionalHeader.SizeOfImage += AlignSection(sec.SizeOfRawData);
	}
	if (fileBit == Bit64) {
		//ntHdr64->OptionalHeader.SizeOfHeaders += sizeof(IMAGE_SECTION_HEADER); //可能不需要? 以后取消这个注释再看看效果
		ntHdr64->OptionalHeader.SizeOfImage += AlignSection(sec.SizeOfRawData);
	}

	//处理附加数据
	DWORD sizeOfAddData = this->bufSize - (lastSec->PointerToRawData + lastSec->SizeOfRawData);
	LocalBuf addData;
	LPVOID newSecBufAddr = (LPVOID)((DWORD64)this->bufAddr + sec.PointerToRawData);
	if (sizeOfAddData > 0) {
		addData.CopyBuffer(newSecBufAddr, sizeOfAddData); //保存附加数据
	}

	ReSize(this->bufSize + sec.SizeOfRawData);
	newSecBufAddr = (LPVOID)((DWORD64)this->bufAddr + sec.PointerToRawData); //BufAddr 需要重新计算
	RtlZeroMemory(newSecBufAddr, sec.SizeOfRawData);
	if (sizeOfAddData > 0) {
		RtlCopyMemory((LPVOID)((DWORD64)newSecBufAddr + sec.SizeOfRawData), addData.bufAddr, sizeOfAddData); //追加附加数据
	}
	addData.FreeBuffer();

	if (GetDirByOrder(Dir_Security)->VirtualAddress == sec.PointerToRawData) {
		GetDirByOrder(Dir_Security)->VirtualAddress = sec.PointerToRawData + sec.SizeOfRawData;
	}

	RtlCopyMemory(newSecReturnHdr, &sec, sizeof(IMAGE_SECTION_HEADER));
	*newSecReturnFOA = sec.PointerToRawData;
	return TRUE;
}

BOOL _PeFile::ExtendLastSection(DWORD addSize, DWORD newSecAttrib, IMAGE_SECTION_HEADER* secReturnHdr, DWORD* secReturnFOA){
	UINT numOfSec = this->ntHdr32->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER lastSec = &firstSecHdr[numOfSec - 1];
	DWORD sizeOfAddData = this->bufSize - (lastSec->PointerToRawData + lastSec->SizeOfRawData); //附加数据大小
	DWORD sizeOfOriginRawData = lastSec->SizeOfRawData; //原始区块的文件形式大小
	lastSec->Characteristics = newSecAttrib;
	lastSec->SizeOfRawData += AlignFile(addSize);
	lastSec->Misc.VirtualSize += AlignSection(addSize);

	if (fileBit == Bit32) {
		ntHdr32->OptionalHeader.SizeOfImage += AlignSection(addSize);
	}
	if (fileBit == Bit64) {
		ntHdr64->OptionalHeader.SizeOfImage += AlignSection(addSize);
	}
	
	LocalBuf addData;
	LPVOID newBufAddr = (LPVOID)((DWORD64)this->bufAddr + lastSec->PointerToRawData + sizeOfOriginRawData);
	if (sizeOfAddData > 0) {
		addData.CopyBuffer((LPVOID)((DWORD64)this->bufAddr + lastSec->PointerToRawData + lastSec->SizeOfRawData), sizeOfAddData); //保存附加数据
	}

	ReSize(this->bufSize + AlignFile(addSize));
	lastSec = &firstSecHdr[numOfSec - 1];
	newBufAddr = (LPVOID)((DWORD64)this->bufAddr + lastSec->PointerToRawData + sizeOfOriginRawData); //BufAddr 需要重新计算
	RtlZeroMemory(newBufAddr, AlignFile(addSize));
	if (sizeOfAddData > 0) {
		RtlCopyMemory((LPVOID)((DWORD64)this->bufAddr + lastSec->PointerToRawData + lastSec->SizeOfRawData), addData.bufAddr, sizeOfAddData); //追加附加数据
	}
	addData.FreeBuffer();

	if (GetDirByOrder(Dir_Security)->VirtualAddress == lastSec->PointerToRawData + sizeOfOriginRawData) {
		GetDirByOrder(Dir_Security)->VirtualAddress = lastSec->PointerToRawData + lastSec->SizeOfRawData;
	}

	RtlCopyMemory(secReturnHdr, lastSec, sizeof(IMAGE_SECTION_HEADER));
	*secReturnFOA = lastSec->PointerToRawData + sizeOfOriginRawData;
	return TRUE;
}

VOID _PeFile::SetOep(DWORD oepValue){
	switch (fileBit){
	case Bit32:
		ntHdr32->OptionalHeader.AddressOfEntryPoint = oepValue;
		break;
	case Bit64:
		ntHdr64->OptionalHeader.AddressOfEntryPoint = oepValue;
		break;
	}
}

DWORD _PeFile::GetOep(){
	switch (fileBit) {
	case Bit32:
		return ntHdr32->OptionalHeader.AddressOfEntryPoint;
	case Bit64:
		return ntHdr64->OptionalHeader.AddressOfEntryPoint;
	}
	return 0;
}

DWORD64 _PeFile::GetImageBase(){
	switch (fileBit) {
	case Bit32:
		return ntHdr32->OptionalHeader.ImageBase;
	case Bit64:
		return ntHdr64->OptionalHeader.ImageBase;
	}
	return 0;
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
	this->CloseFile();
}

_PeFile::~_PeFile(){
	ClosePeFile();
}