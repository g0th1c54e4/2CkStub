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
			cout << "[-] 此程序为.net程序。" << endl;
			targetFile.ClosePeFile();
			stubFile.ClosePeFile();
			return FALSE;
		}
		//if (targetFile.GetDirByOrder(Dir_Exception)->VirtualAddress != 0) {
		//	cout << "[-] 此程序含有异常处理单元，无法加壳。" << endl;
		//	targetFile.ClosePeFile();
		//	stubFile.ClosePeFile();
		//	return FALSE;
		//}
		if (targetFile.GetDirByOrder(Dir_LoadConfig)->VirtualAddress != 0) { //关闭SafeSEH保护为后续LVMProtectA的开发作基础
			PIMAGE_DATA_DIRECTORY loadConfigDir = targetFile.GetDirByOrder(Dir_LoadConfig);
			LPVOID loadConfigMemAddr = (LPVOID)((DWORD64)targetFile.bufAddr + targetFile.Rva2Foa(loadConfigDir->VirtualAddress));
			memset(loadConfigMemAddr, 0, loadConfigDir->Size);
			loadConfigDir->VirtualAddress = 0;
			loadConfigDir->Size = 0;
			cout << "[+] 已关闭SafeSEH保护。" << endl;
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
		cout << "[+] 已处理重定位信息。" << endl;
		
		TlsPack(&targetFile, &stubFile, &share_info);
		cout << "[+] 已处理TLS回调信息。" << endl;
		IatPack(&targetFile, &stubFile, &share_info);
		cout << "[+] 已处理IAT表信息。" << endl;
		//BoundImportPack(&targetFile, &stubFile, &share_info);
		//cout << "[+] 已处理绑定输入表信息。" << endl;
		//ResourcePack(&targetFile, &stubFile, &share_info);
		//cout << "[+] 已处理资源表信息。" << endl;
		
		CodeProtectPack(&targetFile, &stubFile, &share_info); //调用位置仍然有待确定
		cout << "[+] 已压缩并加密原始区块信息。" << endl;

		LPVOID shareInfoAddr = (LPVOID)((DWORD64)targetFile.bufAddr + targetFile.Rva2Foa(newCodeSec.VirtualAddress + GetStubShareInfoOffset(&stubFile)));//本地PE文件的share_info的对应地址
		share_info.ImageBaseOffset = newCodeSec.VirtualAddress + GetStubShareInfoOffset(&stubFile);
		share_info.OldImageBase = targetFile.GetImageBase();
		RtlCopyMemory(shareInfoAddr, &share_info, sizeof(SHARE_INFO)); //上传share_info

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
		PIMAGE_DATA_DIRECTORY tlsDataDir = targetFile->GetDirByOrder(Dir_Tls);
		if (tlsDataDir->VirtualAddress != 0) {

			if (targetFile->fileBit == Bit32) {
				PIMAGE_TLS_DIRECTORY32 tlsDir = (PIMAGE_TLS_DIRECTORY32)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(tlsDataDir->VirtualAddress));
				DWORD rawSize = tlsDir->EndAddressOfRawData - tlsDir->StartAddressOfRawData;
				
				//以下代码有待持续更新(更新完毕后请删除此段注释)
				DWORD tlsDataSecFoa = 0, tlsDataSecRva = 0;
				targetFile->ExtendLastSection(rawSize, NULL, &tlsDataSecFoa, &tlsDataSecRva);

				tlsDir = (PIMAGE_TLS_DIRECTORY32)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(tlsDataDir->VirtualAddress));
				LPVOID StartRawAddr = (LPVOID)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa((tlsDir->StartAddressOfRawData - (DWORD)targetFile->GetImageBase())));
				

				RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + tlsDataSecFoa), StartRawAddr, rawSize); //复制TLS数据块到壳区块内
				RtlZeroMemory(StartRawAddr, rawSize); //清除原TLS数据块

				//tlsDir->StartAddressOfRawData = (DWORD)targetFile->GetImageBase() + tlsDataSecRva;
				//tlsDir->EndAddressOfRawData = tlsDir->StartAddressOfRawData + rawSize;      //TlsDir需要在PE文件中重新构造

				DWORD tlsIndexSecFoa = 0, tlsIndexSecRva = 0;
				targetFile->ExtendLastSection(sizeof(tlsDir->AddressOfIndex), NULL, &tlsIndexSecFoa, &tlsIndexSecRva);
				tlsDir = (PIMAGE_TLS_DIRECTORY32)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(tlsDataDir->VirtualAddress));
				LPVOID tlsIndexAddr = (LPVOID)(((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(tlsDir->AddressOfIndex - (DWORD)targetFile->GetImageBase())));
				DWORD tlsIndexVal = *(DWORD*)tlsIndexAddr;
				RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + tlsIndexSecFoa), &tlsIndexVal, sizeof(tlsDir->AddressOfIndex));
				RtlZeroMemory(tlsIndexAddr, sizeof(tlsDir->AddressOfIndex));

				//tlsDir->AddressOfIndex = (DWORD)targetFile->GetImageBase() + tlsDataSecRva;

				DWORD* tlsCallBackFuncArr = (DWORD*)(((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(tlsDir->AddressOfCallBacks - (DWORD)targetFile->GetImageBase())));
				

				while (*tlsCallBackFuncArr != 0) {



					tlsCallBackFuncArr++;
				}


			}
			if (targetFile->fileBit == Bit64) {
				PIMAGE_TLS_DIRECTORY64 tlsDir = (PIMAGE_TLS_DIRECTORY64)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(tlsDataDir->VirtualAddress));
				LPVOID StartRawAddr = (LPVOID)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa((tlsDir->StartAddressOfRawData - (DWORD64)targetFile->GetImageBase())));
				DWORD rawSize = tlsDir->EndAddressOfRawData - tlsDir->StartAddressOfRawData;
				DWORD tlsIndexVal = *(DWORD*)((DWORD64)targetFile->bufAddr + targetFile->Rva2Foa(tlsDir->AddressOfIndex - (DWORD64)targetFile->GetImageBase())); //tlsDir->AddressOfIndex


			}
			

			//tlsDataDir->VirtualAddress = 0;
			//tlsDataDir->Size = 0;
		}
	}

	VOID IatPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		
		PIMAGE_SECTION_HEADER lastSec = targetFile->firstSecHdr + (targetFile->GetSecNum() - 1);
		DWORD lastSecRva = lastSec->VirtualAddress + lastSec->SizeOfRawData;

		//构造壳的导入表
		std::vector<easy_imp_desc_sec> easy_impDesc_secArr; 

		easy_imp_desc_sec east_impDesc_sec_kernel32;
		east_impDesc_sec_kernel32.DllName = "kernel32.dll";
		east_impDesc_sec_kernel32.FunctionNames.push_back("LoadLibraryA");
		east_impDesc_sec_kernel32.FunctionNames.push_back("GetModuleHandleA");
		east_impDesc_sec_kernel32.FunctionNames.push_back("GetProcAddress");
		easy_impDesc_secArr.push_back(east_impDesc_sec_kernel32);

		LocalBuf importBuf;
		DWORD iatRva = 0, impRva = 0;
		DWORD iatSize = 0, impSize = 0;
		DWORD impBufSize = targetFile->ImpEasyInfo2Buf(&easy_impDesc_secArr, &importBuf, lastSecRva, &iatRva, &impRva, &iatSize, &impSize);
		DWORD newImportSecFoa = 0;
		targetFile->ExtendLastSection(impBufSize, NULL, &newImportSecFoa, NULL);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newImportSecFoa), importBuf.bufAddr, impBufSize);

		//更新
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
		//仅仅将Stub的绑定输入表 清除 就可以了
		//包括数据目录表的RVA和Size的信息，以及其对应指向的数据区域
	}

	VOID ResourcePack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//任务:保护好原程序的资源不被轻易改动
		//只保留“图标”、“图标组”、“版本”、“清单文件”，其他资源都要保护
	}

	VOID CodeProtectPack(PeFile* targetFile, PeFile* stubFile, SHARE_INFO* share_info){
		//采用和vmp一样的做法，将区块头的raw信息删除掉，之后再将原区块的数据解密后再写回到原来的区块区域内
		//https://bbs.kanxue.com/thread-264023.htm#msg_header_h2_0
		
		PIMAGE_SECTION_HEADER targetCodeSecHdr =  targetFile->GetCodeSec();

		BYTE* targetCodeAddr = (BYTE*)((DWORD64)targetFile->bufAddr + targetCodeSecHdr->PointerToRawData);
		DWORD taretCodeSize = targetCodeSecHdr->Misc.VirtualSize;

		LocalBuf apLibWorkSpace;
		apLibWorkSpace.CreateBuffer(aP_workmem_size(taretCodeSize));
		LocalBuf packData;
		packData.CreateBuffer(aP_max_packed_size(taretCodeSize));
		DWORD packSize = aPsafe_pack(targetCodeAddr, packData.bufAddr, taretCodeSize, apLibWorkSpace.bufAddr, NULL, NULL); //压缩后的大小
		if (packSize == APLIB_ERROR) {
			cout << "[-] 压缩失败" << endl;
		}
		



		//DWORD newSecFoa = 0, newSecRva = 0;
		//targetFile->ExtendLastSection(packSize, NULL, &newSecFoa, &newSecRva);
		//targetCodeSecHdr = targetFile->GetCodeSec();
		//
		//RtlCopyMemory((LPVOID)((DWORD64)targetFile->bufAddr + newSecFoa), packData.bufAddr, packSize);

		packData.FreeBuffer();
		apLibWorkSpace.FreeBuffer();

		share_info->OriginCode.RvaAddr = targetCodeSecHdr->VirtualAddress;
		share_info->OriginCode.Size = targetCodeSecHdr->Misc.VirtualSize;

	}

	VOID RemoveSectionName(PeFile* stubFile, WORD secNum){
		for (UINT i = 0; i < secNum; i++) {
			RtlZeroMemory(stubFile->firstSecHdr[i].Name, 8);
		}
	}

	VOID UpdataChecksum(PeFile* stubFile){ //更新CheckSum
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