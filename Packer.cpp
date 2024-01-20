#include <Windows.h>
#include <iostream>
#include "Packer.h"

using std::cout;
using std::endl;

namespace Ck2Stub {
	BOOL WINAPI Pack(CHAR* targetFilePath, CHAR* stubFilePath, CHAR* saveFilePath) {
		PeFile targetFile, stubFile;
		if (targetFile.Init(targetFilePath) == FALSE || stubFile.Init(stubFilePath) == FALSE) {
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
		//if (targetFile.GetDirByOrder(Dir_Exception)->VirtualAddress != 0) {
		//	cout << "[-] �˳������쳣����Ԫ���޷��ӿǡ�" << endl;
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
		targetFile.RemoveDosStub();
		stubFile.RemoveDebugInfo();
		WORD originSecNum = targetFile.GetSecNum();
		// --------------------------------
		PIMAGE_SECTION_HEADER pStubCodeSec = stubFile.GetCodeSec();

		IMAGE_SECTION_HEADER newCodeSec = { 0 };
		DWORD newCodeSecAddrFoa = 0;
		targetFile.AddSection(CODE_SECTION_NAME, pStubCodeSec->SizeOfRawData, SEC_CODE | _SEC_WRITE, &newCodeSec, &newCodeSecAddrFoa);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile.bufAddr + newCodeSecAddrFoa), (LPVOID)((DWORD64)stubFile.bufAddr + pStubCodeSec->PointerToRawData), pStubCodeSec->SizeOfRawData);

		SHARE_INFO share_info = { 0 };
		share_info.OriginEntryPoint = targetFile.GetOep();
		

		//TODO LVMProtect

		targetFile.AddSection(CODEINFO_SECTION_NAME, 0, SEC_DATA);
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
		share_info.OldImageBase = targetFile.GetImageBase();
		RtlCopyMemory(shareInfoAddr, &share_info, sizeof(SHARE_INFO)); //�ϴ�share_info

		targetFile.SetOep(newCodeSec.VirtualAddress + stubOepSecOffset);
		RemoveSectionName(&targetFile, originSecNum);
		UpdataChecksum(&targetFile);

		if (targetFile.SaveAs(saveFilePath) == FALSE) {
			targetFile.ClosePeFile();
			stubFile.ClosePeFile();
			return FALSE;
		}


		targetFile.ClosePeFile();
		stubFile.ClosePeFile();
		return TRUE;
	}

	VOID TlsPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		
	}

	VOID IatPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		
		PIMAGE_SECTION_HEADER lastSec = targetFile->firstSecHdr + (targetFile->GetSecNum() - 1);
		DWORD lastSecRva = lastSec->VirtualAddress + lastSec->SizeOfRawData;

		//����ǵĵ����
		std::vector<easy_imp_desc_sec> easy_impDesc_secArr; 

		easy_imp_desc_sec east_impDesc_sec_kernel32;
		east_impDesc_sec_kernel32.DllName = "kernel32.dll";
		east_impDesc_sec_kernel32.FunctionNames.push_back("LoadLibraryA");
		east_impDesc_sec_kernel32.FunctionNames.push_back("GetModuleHandleA");
		easy_impDesc_secArr.push_back(east_impDesc_sec_kernel32);

		LocalBuf importBuf;
		DWORD iatRva = 0, impRva = 0;
		DWORD iatSize = 0, impSize = 0;
		DWORD impBufSize = targetFile->ImpEasyInfo2Buf(&easy_impDesc_secArr, &importBuf, lastSecRva, &iatRva, &impRva, &iatSize, &impSize);
		DWORD newImportSecFoa = 0;
		targetFile->ExtendLastSection(impBufSize, NULL, &newImportSecFoa, NULL);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newImportSecFoa), importBuf.bufAddr, impBufSize);

		//����
		PIMAGE_DATA_DIRECTORY iatDir = targetFile->GetDirByOrder(Dir_Iat);
		PIMAGE_DATA_DIRECTORY impDir = targetFile->GetDirByOrder(Dir_Import);
		share_info->Iat.RvaAddr = iatDir->VirtualAddress;
		share_info->Iat.Size = iatDir->Size;
		share_info->Import.RvaAddr = impDir->VirtualAddress;
		share_info->Import.Size = impDir->Size;
		iatDir->VirtualAddress = iatRva;
		iatDir->Size = iatSize;
		impDir->VirtualAddress = impRva;
		impDir->Size = impSize;
	}

	VOID RelocPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		PIMAGE_SECTION_HEADER stubCodeSec = stubFile->GetCodeSec();
		PIMAGE_SECTION_HEADER codeSec = targetFile->GetSecHdrByName(CODE_SECTION_NAME);
		if (stubFile->GetDirByOrder(Dir_BaseReloc)->VirtualAddress == 0 || stubFile->GetDirByOrder(Dir_BaseReloc)->Size == 0) {
			return;
		}
		std::vector<Base_reloc_sec> stubRelocInfo = stubFile->GetRelocInfo();
		for (UINT i = 0; i < stubRelocInfo.size(); i++){
			if ((stubRelocInfo[i].VirtualAddress >= stubCodeSec->VirtualAddress) && (stubRelocInfo[i].VirtualAddress <= (stubCodeSec->VirtualAddress + stubCodeSec->Misc.VirtualSize))) {
				stubRelocInfo[i].VirtualAddress += codeSec->VirtualAddress - stubCodeSec->VirtualAddress;
			}
			else {
				stubRelocInfo.erase(stubRelocInfo.begin() + i);
				continue;
			}
		}

		LocalBuf relocBuf;
		DWORD relocBufSize = stubFile->RelocInfo2Buf(&stubRelocInfo, &relocBuf);

		IMAGE_SECTION_HEADER newRelocSec = { 0 };
		DWORD newRelocSecAddrFoa = 0, newRelocSecAddrRva = 0;
		targetFile->ExtendLastSection(relocBufSize, &newRelocSec, &newRelocSecAddrFoa, &newRelocSecAddrRva);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa), relocBuf.bufAddr, relocBufSize);
		
		codeSec = targetFile->GetSecHdrByName(CODE_SECTION_NAME);
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)targetFile->bufAddr + newRelocSecAddrFoa);

		DWORD diffValue = (DWORD)targetFile->GetImageBase() + codeSec->VirtualAddress - (DWORD)stubFile->GetImageBase() - stubCodeSec->VirtualAddress;
		targetFile->RepairReloc(newRelocSecAddrFoa, diffValue);
		
		PIMAGE_DATA_DIRECTORY dirReloc = targetFile->GetDirByOrder(Dir_BaseReloc);
		share_info->Reloc.RvaAddr = dirReloc->VirtualAddress;
		share_info->Reloc.Size = dirReloc->Size;
		dirReloc->VirtualAddress = newRelocSecAddrRva;
		dirReloc->Size = relocBufSize;

		targetFile->GetFileHdr()->Characteristics &= ~(IMAGE_FILE_RELOCS_STRIPPED);

		relocBuf.FreeBuffer();
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
		//���ú�vmpһ����������������ͷ��raw��Ϣɾ������֮���ٽ�ԭ��������ݽ��ܺ���д�ص�ԭ��������������


	}

	VOID RemoveSectionName(PeFile* stubFile, WORD secNum){
		for (UINT i = 0; i < secNum; i++) {
			RtlZeroMemory(stubFile->firstSecHdr[i].Name, 8);
		}
	}

	VOID UpdataChecksum(PeFile* stubFile){ //����CheckSum
		if (stubFile->GetCheckSum() != 0) { 
			stubFile->SetCheckSum(stubFile->CalcCheckSum());
		}
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