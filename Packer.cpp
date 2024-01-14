#include <Windows.h>
#include <iostream>
#include "Packer.h"

using std::cout;
using std::endl;

namespace Ck2Stub {
	BOOL WINAPI Pack(CHAR* targetFilePath, CHAR* stubFilePath, CHAR* saveFilePath) {
		PeFile targetFile, stubFile;
		if (targetFile.Init(targetFilePath) == FALSE) {
			return FALSE;
		}
		if (stubFile.Init(stubFilePath) == FALSE) {
			return FALSE;
		}

		if (targetFile.fileBit != stubFile.fileBit) {
			return FALSE;
		}

		DWORD stubOepSecOffset = GetStubOriginEntryPointOffset(&stubFile);
		if (stubOepSecOffset == 0) {
			return FALSE;
		}

		//此处不应该分别设置32位和64位的处理


		if (targetFile.GetDirByOrder(Dir_ComDescriptor)->VirtualAddress != 0) {
			cout << "[-] 此程序为.net程序。" << endl;
			targetFile.ClosePeFile();
			stubFile.ClosePeFile();
			return FALSE;
		}
		if (targetFile.GetDirByOrder(Dir_Security)->VirtualAddress != 0) {
			cout << "[-] 此程序携带有数字签名。" << endl;
			targetFile.ClosePeFile();
			stubFile.ClosePeFile();
			return FALSE;
		}
		if (targetFile.GetDirByOrder(Dir_LoadConfig)->VirtualAddress != 0) { //关闭SafeSEH保护为后续LVMProtectA的开发作基础
			PIMAGE_DATA_DIRECTORY loadConfigDir = targetFile.GetDirByOrder(Dir_LoadConfig);
			LPVOID loadConfigMemAddr = (LPVOID)((DWORD64)targetFile.bufAddr + targetFile.Rva2Foa(loadConfigDir->VirtualAddress));
			memset(loadConfigMemAddr, 0, loadConfigDir->Size);
			loadConfigDir->VirtualAddress = 0;
			loadConfigDir->Size = 0;

			cout << "[+] 已关闭SafeSEH保护。" << endl;
		}
		targetFile.DynamicsBaseOff();
		cout << "[+] 已关闭动态基址。" << endl;

		PIMAGE_SECTION_HEADER pStubCodeSec = stubFile.GetCodeSec();

		IMAGE_SECTION_HEADER newCodeSec = { 0 };
		DWORD newCodeSecAddrFoa = 0;
		targetFile.AddSection(CODE_SECTION_NAME, pStubCodeSec->SizeOfRawData, CK2STUB_SECTION_ATTRIB, &newCodeSec, &newCodeSecAddrFoa);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile.bufAddr + newCodeSecAddrFoa), (LPVOID)((DWORD64)stubFile.bufAddr + pStubCodeSec->PointerToRawData), pStubCodeSec->SizeOfRawData);


		//TODO Stub
		

		//TODO LVMProtect


		RelocPack(&targetFile, &stubFile);
		cout << "[+] 已处理重定位信息。" << endl;
		TlsPack(&targetFile, &stubFile);
		cout << "[+] 已处理TLS回调信息。" << endl;
		IatPack(&targetFile, &stubFile);
		cout << "[+] 已处理IAT表信息。" << endl;

		targetFile.SetOep(newCodeSec.VirtualAddress + targetFile.Foa2Rva(stubOepSecOffset));

		if (targetFile.SaveAs(saveFilePath) == FALSE) {
			targetFile.ClosePeFile();
			stubFile.ClosePeFile();
			return FALSE;
		}
		targetFile.RemoveDebugInfo();
		targetFile.RemoveExportInfo();

		targetFile.ClosePeFile();
		stubFile.ClosePeFile();
		return TRUE;
	}

	VOID TlsPack(PeFile* targetFile, PeFile* stubFile){
		return VOID();
	}

	VOID IatPack(PeFile* targetFile, PeFile* stubFile){
		return VOID();
	}

	VOID RelocPack(PeFile* targetFile, PeFile* stubFile){
		PIMAGE_SECTION_HEADER stubRelocSec = stubFile->GetRelocSec();
		PIMAGE_SECTION_HEADER stubCodeSec = stubFile->GetCodeSec();
		IMAGE_SECTION_HEADER newRelocSec = { 0 };
		DWORD newRelocSecAddrFoa = 0;
		targetFile->AddSection(RELOC_SECTION_NAME, stubRelocSec->SizeOfRawData, CK2STUB_SECTION_ATTRIB, &newRelocSec, &newRelocSecAddrFoa);
		PIMAGE_SECTION_HEADER codeSec = targetFile->GetSecHdrByName(CODE_SECTION_NAME);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa), (LPVOID)((DWORD64)stubFile->bufAddr + stubRelocSec->PointerToRawData), stubRelocSec->SizeOfRawData);
		
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa);

		DWORD relocSize = 0;
		while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock != 0) {
			if ((pReloc->VirtualAddress >= stubCodeSec->VirtualAddress) && (pReloc->VirtualAddress <= (stubCodeSec->VirtualAddress + stubCodeSec->Misc.VirtualSize))) {
				// Code区域
				pReloc->VirtualAddress -= stubCodeSec->VirtualAddress;
				pReloc->VirtualAddress += codeSec->VirtualAddress;

				struct TypeOffset {
					WORD offset : 12;
					WORD type : 4;
				};
				TypeOffset* pTypeOffs = (TypeOffset*)(pReloc + 1);
				DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
				for (UINT i = 0; i < dwCount; i++) {
					if (pTypeOffs[i].type != 3) {
						continue;
					}
					PDWORD pdwRepairAddr = (PDWORD)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(pReloc->VirtualAddress + pTypeOffs[i].offset));
					*pdwRepairAddr -= (DWORD)stubFile->GetImageBase();
					*pdwRepairAddr -= stubCodeSec->VirtualAddress;
					*pdwRepairAddr += (DWORD)targetFile->GetImageBase();
					*pdwRepairAddr += codeSec->VirtualAddress;
				}

				relocSize += pReloc->SizeOfBlock;
			}
			else {
				// 非Code区域
				LPVOID relocBlockAddr = (LPVOID)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(pReloc->VirtualAddress - stubCodeSec->VirtualAddress + codeSec->VirtualAddress));
				RtlZeroMemory(relocBlockAddr, pReloc->SizeOfBlock);
			}
			pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)pReloc + pReloc->SizeOfBlock);
		}
		
		// TODO 保存原先的重定位信息
		
		PIMAGE_DATA_DIRECTORY dirReloc = targetFile->GetDirByOrder(Dir_BaseReloc);
		dirReloc->VirtualAddress = newRelocSec.VirtualAddress;
		dirReloc->Size = relocSize;
		
	}

	DWORD WINAPI GetStubOriginEntryPointOffset(PeFile* stubFile){

		PIMAGE_SECTION_HEADER secCode = stubFile->GetCodeSec();
		if (secCode == 0) {
			return 0;
		}
		DWORD offset = 0;
		switch (stubFile->fileBit){
		case Bit32:
			offset = stubFile->ntHdr32->OptionalHeader.AddressOfEntryPoint - secCode->VirtualAddress;
			break;
		case Bit64:
			offset = stubFile->ntHdr64->OptionalHeader.AddressOfEntryPoint - secCode->VirtualAddress;
			break;
		}

		return offset;
	}

}