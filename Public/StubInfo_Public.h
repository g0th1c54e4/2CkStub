#ifndef _2CKSTUB_PUBLIC_
#define _2CKSTUB_PUBLIC_

#include <Windows.h>
#define SHARE_INFO_NAME "share_info"//����Ķ�

typedef struct _SHARE_INFO {
	//ԭʼ���������ԭʼִ�����ƫ��
	DWORD OriginEntryPoint;

	//���ڼ��㵱ǰģ��Ļ�ַ
	DWORD ImageBaseOffset;

	//�ǳ����ִ�����ƫ��
	DWORD StubOriginEntryPointOffest;

	//ԭ�����ض�λ��RVA
	DWORD RelocRva;
	DWORD RelocSize;

}SHARE_INFO;

#endif