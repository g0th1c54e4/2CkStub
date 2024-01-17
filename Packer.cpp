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
		targetFile.AddSection(CODE_SECTION_NAME, pStubCodeSec->SizeOfRawData, _SEC_CODE | SEC_ATTRIB_RWE, &newCodeSec, &newCodeSecAddrFoa);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile.bufAddr + newCodeSecAddrFoa), (LPVOID)((DWORD64)stubFile.bufAddr + pStubCodeSec->PointerToRawData), pStubCodeSec->SizeOfRawData);

		SHARE_INFO share_info = { 0 };
		share_info.OriginEntryPoint = targetFile.GetOep();
		

		//TODO LVMProtect

		targetFile.AddSection(CODEINFO_SECTION_NAME, 0, SEC_ATTRIB_RWE);
		RelocPack(&targetFile, &stubFile, &share_info); //ERROR������ǩ������û��
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
		//PIMAGE_SECTION_HEADER stubImport = stubFile->GetSecHdrByRva(stubFile->GetDirByOrder(Dir_Iat)->VirtualAddress);
		//IMAGE_SECTION_HEADER newImportSec = { 0 };
		//DWORD newImportSecAddrFoa = 0;
		//targetFile->ExtendLastSection(stubImport->SizeOfRawData, CK2STUB_SECTION_ATTRIB_RWE, &newImportSec, &newImportSecAddrFoa);
		//RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newImportSecAddrFoa), (LPVOID)((DWORD64)stubFile->bufAddr + stubFile->Rva2Foa(stubImport->VirtualAddress)),stubImport->SizeOfRawData);

		//����Iat������Ҫ�����������
		//1.��Stub����ĵ�����ӵ�ԭ������
		//2.������ԭ����ĵ����(���Բο��ᰮ����ѩ��̳�ϵĹ���IAT���ܵ�������ѧϰ)
	}
	VOID RelocPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		PIMAGE_SECTION_HEADER stubCodeSec = stubFile->GetCodeSec();
		PIMAGE_SECTION_HEADER codeSec = targetFile->GetSecHdrByName(CODE_SECTION_NAME);
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
		targetFile->ExtendLastSection(relocBufSize, SEC_ATTRIB_RWE, &newRelocSec, &newRelocSecAddrFoa, &newRelocSecAddrRva);
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
			RtlZeroMemory(stubFile->firstSecHdr[i].Name, 7);
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