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
		//targetFile.DynamicsBaseOff();
		//cout << "[+] �ѹرն�̬��ַ��" << endl;

		PIMAGE_SECTION_HEADER pStubCodeSec = stubFile.GetCodeSec();

		IMAGE_SECTION_HEADER newCodeSec = { 0 };
		DWORD newCodeSecAddrFoa = 0;
		targetFile.AddSection(CODE_SECTION_NAME, pStubCodeSec->SizeOfRawData, CK2STUB_SECTION_ATTRIB, &newCodeSec, &newCodeSecAddrFoa);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile.bufAddr + newCodeSecAddrFoa), (LPVOID)((DWORD64)stubFile.bufAddr + pStubCodeSec->PointerToRawData), pStubCodeSec->SizeOfRawData);


		SHARE_INFO share_info = { 0 };
		share_info.OriginEntryPoint = targetFile.GetOep(); //RVA
		

		//TODO LVMProtect

		RelocPack(&targetFile, &stubFile, &share_info);
		cout << "[+] �Ѵ����ض�λ��Ϣ��" << endl;
		IMAGE_SECTION_HEADER retSecHdr = { 0 };
		DWORD extBufAddr = 0;

		/*
		TlsPack(&targetFile, &stubFile);
		cout << "[+] �Ѵ���TLS�ص���Ϣ��" << endl;
		IatPack(&targetFile, &stubFile);
		cout << "[+] �Ѵ���IAT����Ϣ��" << endl;
		BoundImportPack(&targetFile, &stubFile);
		cout << "[+] �Ѵ�����������Ϣ��" << endl;
		ResourcePack(&targetFile, &stubFile);
		cout << "[+] �Ѵ�����Դ����Ϣ��" << endl;
		*/

		//����PE�ļ���share_info�Ķ�Ӧ��ַ
		LPVOID shareInfoAddr = (LPVOID)((DWORD64)targetFile.bufAddr + targetFile.Rva2Foa(newCodeSec.VirtualAddress + GetStubShareInfoOffset(&stubFile)));
		share_info.ImageBaseOffset = newCodeSec.VirtualAddress + GetStubShareInfoOffset(&stubFile);
		RtlCopyMemory(shareInfoAddr, &share_info, sizeof(SHARE_INFO)); //�ϴ�share_info


		targetFile.SetOep(newCodeSec.VirtualAddress + stubOepSecOffset);

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
		//
	}

	VOID IatPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//����Iat������Ҫ�����������
		//1.��Stub����ĵ������ԭ������
		//2.������ԭ����ĵ����(���Բο��ᰮ����ѩ��̳�ϵĹ���IAT���ܵ�������ѧϰ)
	}

	VOID RelocPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		PIMAGE_SECTION_HEADER stubRelocSec = stubFile->GetRelocSec();
		PIMAGE_SECTION_HEADER stubCodeSec = stubFile->GetCodeSec();
		IMAGE_SECTION_HEADER newRelocSec = { 0 };
		DWORD newRelocSecAddrFoa = 0;
		targetFile->AddSection(CODEINFO_SECTION_NAME, stubRelocSec->SizeOfRawData, CK2STUB_SECTION_ATTRIB, &newRelocSec, &newRelocSecAddrFoa);
		PIMAGE_SECTION_HEADER codeSec = targetFile->GetSecHdrByName(CODE_SECTION_NAME);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa), (LPVOID)((DWORD64)stubFile->bufAddr + stubRelocSec->PointerToRawData), stubRelocSec->SizeOfRawData);
		
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa);

		DWORD relocSize = 0;
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
				// ��Code����
				DWORD sizeOfRelocBlock = pReloc->SizeOfBlock;
				RtlZeroMemory(pReloc, sizeOfRelocBlock);
				pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)pReloc + sizeOfRelocBlock);
				continue;
			}
			pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)pReloc + pReloc->SizeOfBlock);
		}
		
		PIMAGE_DATA_DIRECTORY dirReloc = targetFile->GetDirByOrder(Dir_BaseReloc);
		share_info->RelocRva = dirReloc->VirtualAddress;
		share_info->RelocSize = dirReloc->Size;
		dirReloc->VirtualAddress = newRelocSec.VirtualAddress;
		dirReloc->Size = relocSize;
		
	}

	VOID BoundImportPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//������Stub�İ������ ��� �Ϳ�����
		//��������Ŀ¼���RVA��Size����Ϣ���Լ����Ӧָ�����������
	}

	VOID ResourcePack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//����:������ԭ�������Դ�������׸Ķ�
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

}