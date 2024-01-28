#include <Windows.h>
#include "pe.h"

BOOL _PeFile::Init(CHAR* targetFilePath){
	if (this->OpenFile(targetFilePath) == FALSE) {
		return FALSE;
	}
	return init_peHdr();
}

BOOL _PeFile::Init(WCHAR* targetFilePath){
	if (this->OpenFile(targetFilePath) == FALSE) {
		return FALSE;
	}

	return init_peHdr();
}

BOOL _PeFile::JudgeDllFile(){
	return ((ntHdr32->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0);
}

PIMAGE_FILE_HEADER _PeFile::GetFileHdr(){
	return &(ntHdr32->FileHeader);
}

WORD _PeFile::GetSecNum(){
	return ntHdr32->FileHeader.NumberOfSections;
}

BOOL _PeFile::init_peHdr(){
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
	if (ntHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return Bit32;
	}
	else if (ntHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return Bit64;
	}
	return BitNone;
}

BOOL _PeFile::CheckSecTabSpace(UINT numOfInsertSec){
	//TODO: 每个节表占40字节 要保证有80字节空白区(多余40字节用于兼容部分系统)
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

	init_peHdr();
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
	// 注意:转换偏移的时候 "有可能" 对新添加进来的新区块头不起作用
	switch (fileBit){
	case Bit32:
		// 可以判断文件对齐值和内存对齐值是否一致，如果一致则直接返回结果
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
		// 可以判断文件对齐值和内存对齐值是否一致，如果一致则直接返回结果
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
	// 注意:转换偏移的时候 "有可能" 对新添加进来的新区块头不起作用
	switch (fileBit){
	case Bit32:
		// 可以判断文件对齐值和内存对齐值是否一致，如果一致则直接返回结果
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
		// 可以判断文件对齐值和内存对齐值是否一致，如果一致则直接返回结果
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
	
	if (pExport == 0) {
		return 0;
	}
	DWORD dwNum = pExport->NumberOfFunctions;

	PDWORD pdwName = (PDWORD)(Rva2Foa(pExport->AddressOfNames) + (DWORD64)this->bufAddr);
	PWORD pwOrder = (PWORD)(Rva2Foa(pExport->AddressOfNameOrdinals) + (DWORD64)this->bufAddr);
	PDWORD pdwFuncAddr = (PDWORD)(Rva2Foa(pExport->AddressOfFunctions) + (DWORD64)this->bufAddr);

	for (UINT i = 0; i < dwNum; i++) {
		LPCSTR lpFuncName = (LPCSTR)(Rva2Foa(pdwName[i]) + (DWORD64)this->bufAddr);
		if (strcmp(lpFuncName, targetFuncName) == 0) {
			WORD wOrd = pwOrder[i];
			return (DWORD)pdwFuncAddr[wOrd];
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

//VOID _PeFile::RemoveExportInfo(){
//	PIMAGE_DATA_DIRECTORY dirExport = GetDirByOrder(Dir_Export);
//	if (dirExport->VirtualAddress == 0 || dirExport->Size == 0) {
//		return;
//	}
//	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)this->bufAddr + Rva2Foa(dirExport->VirtualAddress));
//	RtlZeroMemory(pExport, dirExport->Size);
//}

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

BOOL _PeFile::AddSection(CONST CHAR* newSecName, DWORD newSecSize, DWORD newSecAttrib, IMAGE_SECTION_HEADER* newSecReturnHdr, DWORD* newSecReturnFOA, DWORD* newSecReturnRVA){
	
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
		ntHdr32->OptionalHeader.SizeOfImage += AlignSection(sec.SizeOfRawData);
	}
	if (fileBit == Bit64) {
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

	if (GetDirByOrder(Dir_Security)->VirtualAddress != 0) {
		GetDirByOrder(Dir_Security)->VirtualAddress += AlignFile(newSecSize);
	}

	if (newSecReturnHdr != NULL) {
		RtlCopyMemory(newSecReturnHdr, &sec, sizeof(IMAGE_SECTION_HEADER));
	}
	if (newSecReturnFOA != NULL) {
		*newSecReturnFOA = sec.PointerToRawData;
	}
	if (newSecReturnRVA != NULL) {
		*newSecReturnRVA = sec.VirtualAddress;
	}
	return TRUE;
}

VOID _PeFile::ExtendLastSection(DWORD addSize, IMAGE_SECTION_HEADER* secReturnHdr, DWORD* secReturnFOA, DWORD* secReturnRVA){
	UINT numOfSec = this->ntHdr32->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER lastSec = &firstSecHdr[numOfSec - 1];
	DWORD sizeOfAddData = this->bufSize - (lastSec->PointerToRawData + lastSec->SizeOfRawData); //附加数据大小
	DWORD sizeOfOriginRawData = lastSec->SizeOfRawData; //原始区块的文件形式大小
	lastSec->SizeOfRawData += AlignFile(addSize);
	lastSec->Misc.VirtualSize += AlignSection(addSize);

	if (fileBit == Bit32) {
		ntHdr32->OptionalHeader.SizeOfImage += AlignSection(addSize);
	}
	if (fileBit == Bit64) {
		ntHdr64->OptionalHeader.SizeOfImage += AlignSection(addSize);
	}
	
	LocalBuf addData;
	LPVOID newBufAddr = (LPVOID)((DWORD64)this->bufAddr + lastSec->PointerToRawData + sizeOfOriginRawData); //重新计算
	if (sizeOfAddData > 0) {
		addData.CopyBuffer(newBufAddr, sizeOfAddData); //保存附加数据
	}

	ReSize(this->bufSize + AlignFile(addSize));
	lastSec = &firstSecHdr[numOfSec - 1];
	newBufAddr = (LPVOID)((DWORD64)this->bufAddr + lastSec->PointerToRawData + sizeOfOriginRawData);
	RtlZeroMemory(newBufAddr, AlignFile(addSize));
	if (sizeOfAddData > 0) {
		RtlCopyMemory((LPVOID)((DWORD64)this->bufAddr + lastSec->PointerToRawData + lastSec->SizeOfRawData), addData.bufAddr, sizeOfAddData); //追加附加数据
	}
	addData.FreeBuffer();

	if (GetDirByOrder(Dir_Security)->VirtualAddress != 0) {
		GetDirByOrder(Dir_Security)->VirtualAddress += AlignFile(addSize);
	}

	if (secReturnHdr != NULL) {
		RtlCopyMemory(secReturnHdr, lastSec, sizeof(IMAGE_SECTION_HEADER));
	}
	if (secReturnFOA != NULL) {
		*secReturnFOA = lastSec->PointerToRawData + sizeOfOriginRawData;
	}
	if (secReturnRVA != NULL) {
		*secReturnRVA = lastSec->VirtualAddress + sizeOfOriginRawData;
	}
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

DWORD _PeFile::GetCheckSum(){
	if (fileBit == Bit32) {
		return ntHdr32->OptionalHeader.CheckSum;
	}
	if (fileBit == Bit64) {
		return ntHdr64->OptionalHeader.CheckSum;
	}
	return 0;
}

VOID _PeFile::SetCheckSum(DWORD checksumValue){
	if (fileBit == Bit32) {
		ntHdr32->OptionalHeader.CheckSum = checksumValue;
	}
	if (fileBit == Bit64) {
		ntHdr64->OptionalHeader.CheckSum = checksumValue;
	}
}

DWORD _PeFile::CalcCheckSum(){
	DWORD checkSum = 0;
	DWORD headerSum = 0;
	CheckSumMappedFile(this->bufAddr, this->bufSize, &headerSum, &checkSum);
	return checkSum;
}

_PeFile::_PeFile() {
	dosHdr = 0;
	ntHdr32 = 0;
	ntHdr64 = 0;
	fileBit = Bit32;
	firstSecHdr = 0;
}

//std::vector<PIMAGE_IMPORT_DESCRIPTOR> _PeFile::GetIIDList(){
//	std::vector<PIMAGE_IMPORT_DESCRIPTOR> resultList;
//	PIMAGE_DATA_DIRECTORY dirIat = GetDirByOrder(Dir_Import);
//	DWORD numOfIID = (dirIat->Size - sizeof(IMAGE_IMPORT_DESCRIPTOR)) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
//	PIMAGE_IMPORT_DESCRIPTOR pFirstIID = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)this->bufAddr + Rva2Foa(dirIat->VirtualAddress));
//	for (UINT i = 0; i < numOfIID; i++){
//		//CHAR* dllName = (CHAR*)((DWORD64)this->bufAddr + Rva2Foa((pFirstIID + i)->Name));
//
//		resultList.push_back(pFirstIID + i);
//	}
//
//	return resultList;
//}

DWORD _PeFile::ImpEasyInfo2Buf(std::vector<easy_imp_desc_sec>* inEasyImpInfo, LocalBuf* outImpInfoBuf, DWORD baseRva, DWORD* returnIatRva, DWORD* returnImpRva, DWORD* returnIatSize, DWORD* returnImpSize){ // 构造简易导入表
	// a.计算大小
	DWORD iidTabSize = (inEasyImpInfo->size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR); // 全部IID的大小
	if (returnImpSize != NULL) {
		*returnImpSize = iidTabSize;
	}
	DWORD ftSize = 0; // 全部FirstThunk(或OriginFirstThunk)的大小
	DWORD funcByNameSize = 0; // 全部ByName结构体的大小
	DWORD iidDllNameSize = 0; // 所有DllName字符串的大小
	for (UINT i = 0; i < inEasyImpInfo->size(); i++){
		iidDllNameSize += ((*inEasyImpInfo)[i]).DllName.length() + 1;

		if (fileBit == Bit32) {
			ftSize += (((*inEasyImpInfo)[i]).FunctionNames.size() + 1) * sizeof(IMAGE_THUNK_DATA32);
		}
		if (fileBit == Bit64) {
			ftSize += (((*inEasyImpInfo)[i]).FunctionNames.size() + 1) * sizeof(IMAGE_THUNK_DATA64);
		}
		for (UINT j = 0; j < ((*inEasyImpInfo)[i]).FunctionNames.size(); j++) {
			funcByNameSize += sizeof(WORD) + ((*inEasyImpInfo)[i]).FunctionNames[j].length() + 1;
		}
	}

	if (returnIatSize != NULL) {
		*returnIatSize = ftSize;
	}
	DWORD bufSize = iidTabSize + (ftSize * 2) + funcByNameSize + iidDllNameSize; //整体Buffer的大小
	outImpInfoBuf->CreateBuffer(bufSize);

	// b.构造
	DWORD writePoint_FTs = 0;
	if (returnIatRva != NULL) {
		*returnIatRva = baseRva + writePoint_FTs;
	}
	DWORD writePoint_OFTs = ftSize;
	DWORD writePoint_ByNameArr = (ftSize * 2);
	DWORD writePoint_IIDArr = (ftSize * 2) + funcByNameSize;
	if (returnImpRva != NULL) {
		*returnImpRva = baseRva + writePoint_IIDArr;
	}
	DWORD writePoint_DllNameArr = (ftSize * 2) + funcByNameSize + iidTabSize;
	
	for (UINT i = 0; i < inEasyImpInfo->size(); i++) {
		IMAGE_IMPORT_DESCRIPTOR impDesc = { 0 };
		
		impDesc.FirstThunk = baseRva + writePoint_FTs;
		impDesc.OriginalFirstThunk = baseRva + writePoint_OFTs;
		impDesc.Name = baseRva + writePoint_DllNameArr;
		RtlCopyMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_IIDArr), &impDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		writePoint_IIDArr += sizeof(IMAGE_IMPORT_DESCRIPTOR);

		for (UINT j = 0; j < ((*inEasyImpInfo)[i]).FunctionNames.size(); j++) {
			RtlZeroMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_ByNameArr), sizeof(WORD));
			RtlCopyMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_ByNameArr + sizeof(WORD)), ((*inEasyImpInfo)[i]).FunctionNames[j].c_str(), ((*inEasyImpInfo)[i]).FunctionNames[j].length() + 1);

			if (fileBit == Bit32) {
				IMAGE_THUNK_DATA32 thunkData = { 0 };
				thunkData.u1.AddressOfData = baseRva + writePoint_ByNameArr;

				RtlCopyMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_FTs), &thunkData, sizeof(IMAGE_THUNK_DATA32));
				RtlCopyMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_OFTs), &thunkData, sizeof(IMAGE_THUNK_DATA32));
				writePoint_FTs += sizeof(IMAGE_THUNK_DATA32);
				writePoint_OFTs += sizeof(IMAGE_THUNK_DATA32);
			}
			if (fileBit == Bit64) {
				IMAGE_THUNK_DATA64 thunkData = { 0 };
				thunkData.u1.AddressOfData = (DWORD64)(baseRva + writePoint_ByNameArr);

				RtlCopyMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_FTs), &thunkData, sizeof(IMAGE_THUNK_DATA64));
				RtlCopyMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_OFTs), &thunkData, sizeof(IMAGE_THUNK_DATA64));
				writePoint_FTs += sizeof(IMAGE_THUNK_DATA64);
				writePoint_OFTs += sizeof(IMAGE_THUNK_DATA64);
			}

			writePoint_ByNameArr += sizeof(WORD);
			writePoint_ByNameArr += ((*inEasyImpInfo)[i]).FunctionNames[j].length() + 1;
		}

		if (fileBit == Bit32) {
			writePoint_FTs += sizeof(IMAGE_THUNK_DATA32);
			writePoint_OFTs += sizeof(IMAGE_THUNK_DATA32);
		}
		if (fileBit == Bit64) {
			writePoint_FTs += sizeof(IMAGE_THUNK_DATA64);
			writePoint_OFTs += sizeof(IMAGE_THUNK_DATA64);
		}
		RtlCopyMemory((LPVOID)((DWORD64)outImpInfoBuf->bufAddr + writePoint_DllNameArr), ((*inEasyImpInfo)[i]).DllName.c_str(), ((*inEasyImpInfo)[i]).DllName.length() + 1);
		writePoint_DllNameArr += ((*inEasyImpInfo)[i]).DllName.length() + 1;
	}

	return bufSize;
}

DWORD _PeFile::RemoveDosStub(){
	LocalBuf peHdr;
	LPVOID peHdrAddr = (LPVOID)((DWORD64)this->ntHdr32);
	LPVOID peHdrFinalAddr = (LPVOID)((DWORD64)(firstSecHdr + (ntHdr32->FileHeader.NumberOfSections + 2)));
	DWORD peHdrsize = (DWORD)((DWORD64)peHdrFinalAddr - (DWORD64)peHdrAddr);
	DWORD dosStubSize = ((DWORD64)peHdrAddr - (DWORD64)(dosHdr + 1));

	peHdr.CopyBuffer(peHdrAddr, peHdrsize);
	RtlCopyMemory((LPVOID)(dosHdr + 1), peHdr.bufAddr, peHdrsize);
	dosHdr->e_lfanew -= (dosStubSize);


	if (init_peHdr() == FALSE) {
		return 0;
	}

	RtlZeroMemory((LPVOID)(firstSecHdr + (ntHdr32->FileHeader.NumberOfSections)), dosStubSize);

	peHdr.FreeBuffer();
	return (dosStubSize);
}

std::vector<Base_reloc_sec> _PeFile::GetRelocInfo(){
	std::vector<Base_reloc_sec> baseRelocSecArr;
	PIMAGE_DATA_DIRECTORY pRelocDir = this->GetDirByOrder(Dir_BaseReloc);
	if (pRelocDir->VirtualAddress == 0 || pRelocDir->Size == 0) {
		return baseRelocSecArr;
	}
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)this->bufAddr + Rva2Foa(pRelocDir->VirtualAddress));
	while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock != 0) {
		Type_Offset* pTypeOffs = (Type_Offset*)(pReloc + 1);
		Base_reloc_sec baseRelocSec = { 0 };
		baseRelocSec.VirtualAddress = pReloc->VirtualAddress;
		baseRelocSec.SizeOfBlock = pReloc->SizeOfBlock;
		DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(Type_Offset); //ERROR(x64)
		for (UINT i = 0; i < dwCount; i++) {
			baseRelocSec.TypeOffsetArray.push_back(*(pTypeOffs + i));
		}
		baseRelocSecArr.push_back(baseRelocSec);
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)pReloc + pReloc->SizeOfBlock);
	}

	return baseRelocSecArr;
}

DWORD _PeFile::RelocInfo2Buf(std::vector<Base_reloc_sec>* inRelocInfo, LocalBuf* outRelocInfoBuf){
	DWORD relocTabize = ((inRelocInfo->size() + 1) * sizeof(IMAGE_BASE_RELOCATION));
	for (UINT i = 0; i < inRelocInfo->size(); i++){
		relocTabize += ((*inRelocInfo)[i]).SizeOfBlock;
	}
	outRelocInfoBuf->CreateBuffer(relocTabize);
	DWORD writePoint = 0;
	for (UINT i = 0; i < inRelocInfo->size(); i++){
		IMAGE_BASE_RELOCATION baseReloc = { 0 };
		baseReloc.VirtualAddress = ((*inRelocInfo)[i]).VirtualAddress;
		baseReloc.SizeOfBlock = ((*inRelocInfo)[i]).SizeOfBlock;
		RtlCopyMemory((LPVOID)((DWORD64)outRelocInfoBuf->bufAddr + writePoint), &baseReloc, sizeof(IMAGE_BASE_RELOCATION));
		writePoint += sizeof(IMAGE_BASE_RELOCATION);

		for (UINT j = 0; j < ((*inRelocInfo)[i]).TypeOffsetArray.size(); j++){
			WORD typeOffset = 0;
			typeOffset |= ((*inRelocInfo)[i]).TypeOffsetArray[j].offset;
			typeOffset |= ((((*inRelocInfo)[i]).TypeOffsetArray[j].type) << 12);
			RtlCopyMemory((LPVOID)((DWORD64)outRelocInfoBuf->bufAddr + writePoint), &typeOffset, sizeof(WORD));
			writePoint += sizeof(WORD);
		}
	}
	RtlZeroMemory((LPVOID)((DWORD64)outRelocInfoBuf->bufAddr + writePoint), sizeof(IMAGE_BASE_RELOCATION)); //此句代码用于截断重定位块项数组

	return relocTabize;
}

VOID _PeFile::RepairReloc(DWORD relocBaseFoaAddr, DWORD diffValue){
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)this->bufAddr + relocBaseFoaAddr);

	while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock != 0) {
		Type_Offset* pTypeOffs = (Type_Offset*)(pReloc + 1);
		DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(Type_Offset);
		for (UINT i = 0; i < dwCount; i++) {
			if (fileBit == Bit32) {
				if (pTypeOffs[i].type != IMAGE_REL_BASED_HIGHLOW) {
					continue;
				}
				PDWORD pdwRepairAddr = (PDWORD)((DWORD64)this->bufAddr + this->Rva2Foa(pReloc->VirtualAddress + pTypeOffs[i].offset));
				*pdwRepairAddr += diffValue;
				continue;
			}
			if (fileBit == Bit64) {
				if (pTypeOffs[i].type != IMAGE_REL_BASED_DIR64) {
					continue;
				}
				PDWORD pdwRepairAddr = (PDWORD)((DWORD64)this->bufAddr + this->Rva2Foa(pReloc->VirtualAddress + pTypeOffs[i].offset));
				*pdwRepairAddr += diffValue;
			}
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)pReloc + pReloc->SizeOfBlock);
	}
}

VOID _PeFile::UpdateSecHdrRawInfo(){
	UINT numOfSec = this->ntHdr32->FileHeader.NumberOfSections;

	
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