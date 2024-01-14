#include <Windows.h>
#include <iostream>
#include "Packer.h"

using std::cout;
using std::endl;

namespace Ck2Stub {
	BOOL WINAPI Pack(CHAR* targetFilePath, CHAR* stubFilePath, CONST CHAR* stubSecName, CHAR* saveFilePath) {
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

		//�˴���Ӧ�÷ֱ�����32λ��64λ�Ĵ���


		if (targetFile.GetDirByOrder(Dir_ComDescriptor)->VirtualAddress != 0) {
			cout << "[-]�˳���Ϊ.net����" << endl;
			targetFile.ClosePeFile();
			stubFile.ClosePeFile();
			return FALSE;
		}
		if (targetFile.GetDirByOrder(Dir_Security)->VirtualAddress != 0) {
			cout << "[-]�˳���Я��������ǩ����" << endl;
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

			cout << "[+]�ѹر�SafeSEH������" << endl;
		}
		targetFile.DynamicsBaseOff();
		cout << "[+]�ѹرն�̬��ַ��" << endl;

		PIMAGE_SECTION_HEADER pStubCodeSec = stubFile.GetCodeSec();
		PIMAGE_SECTION_HEADER pStubRelocSec = stubFile.GetRelocSec();

		IMAGE_SECTION_HEADER newCodeSec = { 0 };
		DWORD newCodeSecAddrFoa = 0;
		targetFile.AddSection(stubSecName, pStubCodeSec->SizeOfRawData, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA, &newCodeSec, &newCodeSecAddrFoa);
		RtlCopyMemory((LPVOID)((DWORD64)targetFile.bufAddr + newCodeSecAddrFoa), (LPVOID)((DWORD64)stubFile.bufAddr + pStubCodeSec->PointerToRawData), pStubCodeSec->SizeOfRawData);

		//TODO

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