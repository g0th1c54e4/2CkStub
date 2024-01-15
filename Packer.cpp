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

		if (targetFile.GetDirByOrder(Dir_ComDescriptor)->VirtualAddress != 0) {
			cout << "[-] �˳���Ϊ.net����" << endl;
			targetFile.ClosePeFile();
			stubFile.ClosePeFile();
			return FALSE;
		}

		//if (targetFile.GetDirByOrder(Dir_Security)->VirtualAddress != 0) {
		//	cout << "[-] �˳���Я��������ǩ����" << endl;
		//	targetFile.ClosePeFile();
		//	stubFile.ClosePeFile();
		//	return FALSE;
		//}
		
		if (targetFile.GetDirByOrder(Dir_LoadConfig)->VirtualAddress != 0) { //�ر�SafeSEH����Ϊ����LVMProtectA�Ŀ���������
			PIMAGE_DATA_DIRECTORY loadConfigDir = targetFile.GetDirByOrder(Dir_LoadConfig);
			LPVOID loadConfigMemAddr = (LPVOID)((DWORD64)targetFile.bufAddr + targetFile.Rva2Foa(loadConfigDir->VirtualAddress));
			memset(loadConfigMemAddr, 0, loadConfigDir->Size);
			loadConfigDir->VirtualAddress = 0;
			loadConfigDir->Size = 0;

			cout << "[+] �ѹر�SafeSEH������" << endl;
		}

		PIMAGE_SECTION_HEADER pStubCodeSec = stubFile.GetCodeSec();

		IMAGE_SECTION_HEADER newCodeSec = { 0 };
		DWORD newCodeSecAddrFoa = 0;
		targetFile.AddSection(CODE_SECTION_NAME, pStubCodeSec->SizeOfRawData, CK2STUB_SECTION_ATTRIB, &newCodeSec, &newCodeSecAddrFoa);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile.bufAddr + newCodeSecAddrFoa), (LPVOID)((DWORD64)stubFile.bufAddr + pStubCodeSec->PointerToRawData), pStubCodeSec->SizeOfRawData);

		SHARE_INFO share_info = { 0 };
		share_info.OriginEntryPoint = targetFile.GetOep();
		

		//TODO LVMProtect

		RelocPack(&targetFile, &stubFile, &share_info);
		cout << "[+] �Ѵ����ض�λ��Ϣ��" << endl;
		
		//TlsPack(&targetFile, &stubFile, &share_info);
		//cout << "[+] �Ѵ���TLS�ص���Ϣ��" << endl;
		IatPack(&targetFile, &stubFile, &share_info);
		cout << "[+] �Ѵ���IAT����Ϣ��" << endl;
		//BoundImportPack(&targetFile, &stubFile, &share_info);
		//cout << "[+] �Ѵ�����������Ϣ��" << endl;
		//ResourcePack(&targetFile, &stubFile, &share_info);
		//cout << "[+] �Ѵ�����Դ����Ϣ��" << endl;
		

		LPVOID shareInfoAddr = (LPVOID)((DWORD64)targetFile.bufAddr + targetFile.Rva2Foa(newCodeSec.VirtualAddress + GetStubShareInfoOffset(&stubFile)));//����PE�ļ���share_info�Ķ�Ӧ��ַ
		share_info.ImageBaseOffset = newCodeSec.VirtualAddress + GetStubShareInfoOffset(&stubFile);
		RtlCopyMemory(shareInfoAddr, &share_info, sizeof(SHARE_INFO)); //�ϴ�share_info

		targetFile.SetOep(newCodeSec.VirtualAddress + stubOepSecOffset);

		SetAllSectionWritable(&targetFile);//����ȫ�������д
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

	VOID TlsPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		
	}

	VOID IatPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//PIMAGE_SECTION_HEADER stubImport = stubFile->GetSecHdrByRva(stubFile->GetDirByOrder(Dir_Iat)->VirtualAddress);
		//IMAGE_SECTION_HEADER newImportSec = { 0 };
		//DWORD newImportSecAddrFoa = 0;
		//targetFile->ExtendLastSection(stubImport->SizeOfRawData, CK2STUB_SECTION_ATTRIB_RWE, &newImportSec, &newImportSecAddrFoa);
		//RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newImportSecAddrFoa), (LPVOID)((DWORD64)stubFile->bufAddr + stubFile->Rva2Foa(stubImport->VirtualAddress)),stubImport->SizeOfRawData);

		//����Iat������Ҫ�����������
		//1.��Stub����ĵ������ԭ������
		//2.������ԭ����ĵ����(���Բο��ᰮ����ѩ��̳�ϵĹ���IAT���ܵ�������ѧϰ)
	}

	VOID RelocPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		PIMAGE_SECTION_HEADER stubRelocSec = stubFile->GetRelocSec();
		if (stubRelocSec == 0) {
			return;
		}
		PIMAGE_SECTION_HEADER stubCodeSec = stubFile->GetCodeSec();
		IMAGE_SECTION_HEADER newRelocSec = { 0 };
		DWORD newRelocSecAddrFoa = 0;
		targetFile->AddSection(CODEINFO_SECTION_NAME, stubRelocSec->SizeOfRawData, CK2STUB_SECTION_ATTRIB, &newRelocSec, &newRelocSecAddrFoa);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa), (LPVOID)((DWORD64)stubFile->bufAddr + stubRelocSec->PointerToRawData), stubRelocSec->SizeOfRawData);
		
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa);

		DWORD relocSize = 0;
		PIMAGE_SECTION_HEADER codeSec = targetFile->GetSecHdrByName(CODE_SECTION_NAME);
		while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock != 0) {
			if ((pReloc->VirtualAddress >= stubCodeSec->VirtualAddress) && (pReloc->VirtualAddress <= (stubCodeSec->VirtualAddress + stubCodeSec->Misc.VirtualSize))) {
				// Code����
				pReloc->VirtualAddress -= stubCodeSec->VirtualAddress;
				pReloc->VirtualAddress += codeSec->VirtualAddress;

				struct TypeOffset {
					WORD offset : 12;
					WORD type : 4;
				};
				TypeOffset* pTypeOffs = (TypeOffset*)(pReloc + 1);
				DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
				for (UINT i = 0; i < dwCount; i++) {
					if (pTypeOffs[i].type != IMAGE_REL_BASED_HIGHLOW) {
						continue;
					}
					PDWORD pdwRepairAddr = (PDWORD)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(pReloc->VirtualAddress + pTypeOffs[i].offset));
					if (stubFile->GetSecHdrByRva((*pdwRepairAddr) - (DWORD)stubFile->GetImageBase()) == stubCodeSec){ //ֻ�޸�ָ��.text��������ݣ���������жϲ�ͬ
						*pdwRepairAddr -= (DWORD)stubFile->GetImageBase();
						*pdwRepairAddr -= stubCodeSec->VirtualAddress;
						*pdwRepairAddr += (DWORD)targetFile->GetImageBase();
						*pdwRepairAddr += codeSec->VirtualAddress;
					}
					//else { //�����ض�λ����Ϊ�����޸�
					//	pTypeOffs[i].type = IMAGE_REL_ALPHA_ABSOLUTE;
					//	continue;
					//}
				}

				relocSize += pReloc->SizeOfBlock;
			}
			else {
				// ��Code����
				DWORD sizeOfRelocBlock = pReloc->SizeOfBlock;
				RtlZeroMemory(pReloc, sizeOfRelocBlock);
				pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)pReloc + sizeOfRelocBlock);
				continue;
			}
			pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)pReloc + pReloc->SizeOfBlock);
		}

		PIMAGE_DATA_DIRECTORY dirReloc = targetFile->GetDirByOrder(Dir_BaseReloc);
		share_info->Reloc.RvaAddr = dirReloc->VirtualAddress;
		share_info->Reloc.Size = dirReloc->Size;
		dirReloc->VirtualAddress = newRelocSec.VirtualAddress;
		dirReloc->Size = relocSize;
		
		targetFile->GetFileHdr()->Characteristics &= ~(IMAGE_FILE_RELOCS_STRIPPED);
	}

	VOID BoundImportPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//������Stub�İ������ ��� �Ϳ�����
		//��������Ŀ¼���RVA��Size����Ϣ���Լ����Ӧָ�����������
	}

	VOID ResourcePack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//����:������ԭ�������Դ�������׸Ķ�
		//ֻ������ͼ�ꡱ����ͼ���顱�����汾�������嵥�ļ�����������Դ��Ҫ����
	}

	VOID CodeProtectPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){


	}

	DWORD WINAPI GetStubOriginEntryPointOffset(PeFile* stubFile){
		PIMAGE_SECTION_HEADER secCode = stubFile->GetCodeSec();
		if (secCode == 0) {
			return 0;
		}
		DWORD offset = stubFile->GetOep() - secCode->VirtualAddress;
		return offset;
	}

	DWORD WINAPI GetStubShareInfoOffset(PeFile* stubFile){
		DWORD funcExportRva = stubFile->GetExportFuncAddrRVA((CHAR*)SHARE_INFO_NAME);
		return (funcExportRva - stubFile->GetCodeSec()->VirtualAddress);
	}

	VOID WINAPI SetAllSectionWritable(PeFile* peFile){
		std::vector<PIMAGE_SECTION_HEADER> SecHdrList = peFile->GetSecHdrList();
		for (UINT i = 0; i < SecHdrList.size(); i++){
			SecHdrList[i]->Characteristics |= IMAGE_SCN_MEM_WRITE;
		}
	}

}