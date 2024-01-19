#include <Windows.h>
#include "../Public/StubInfo_Public.h"
#include "pe.h"

#ifdef _WIN64
extern "C" {
	SHARE_INFO share_info = { 0 };
	VOID WINAPI StubInit();
}
#else
SHARE_INFO share_info = { 0 };
VOID WINAPI StubInit();
#endif

#ifdef _WIN64
DWORD64 imageBase = 0;
#else
DWORD imageBase = 0;
#endif


VOID WINAPI StubInit() {
	//����ӳ���ַ
	#ifdef _WIN64
	imageBase = ((DWORD64)&share_info - share_info.ImageBaseOffset);
	#else
	imageBase = ((DWORD)&share_info - share_info.ImageBaseOffset);
	#endif
	share_info.OriginEntryPoint += imageBase;

	//TODO:��ʼ��API���� (����IAT��GetProcAddress��LoadLibraryA����ȡ������ַ���Լ���VirtualProtect��Ȩ��)

	//TODO:�ָ�ԭʼ��������(��ҪWriteȨ��)

	//�����ض�λ��(��ҪWriteȨ��)
	if (share_info.Reloc.RvaAddr != 0) {
		RepairReloc((LPVOID)imageBase, share_info.Reloc.RvaAddr, share_info.OldImageBase, imageBase);
	}

	//TODO:����IAT��(��ҪWriteȨ��)

	//TODO:����TLS

	//TODO:�ָ���Դ(��ҪWriteȨ��)

}

#ifndef _WIN64
_declspec(naked)
VOID WINAPI StubEntry() {
	StubInit();
	_asm {
		jmp dword ptr ds:[share_info.OriginEntryPoint] //��Ҫ��ַ
	}
}
#endif