#ifndef _2CKSTUB_PUBLIC_
#define _2CKSTUB_PUBLIC_

#include <Windows.h>
#define SHARE_INFO_NAME "share_info"//����Ķ�

typedef struct _AREA {
	DWORD RvaAddr;
	DWORD Size;
}AREA;

typedef struct _SHARE_INFO {
	//ԭʼ���������ԭʼִ�����ƫ��
	DWORD64 OriginEntryPoint;

	//���ڼ��㵱ǰģ��Ļ�ַ
	DWORD ImageBaseOffset;

	//ԭ����Ĵ�������λ��
	AREA OriginCode;

	//ԭ�����ض�λ��RVA
	AREA Reloc;

	//ԭ�������
	AREA Import;
	AREA Iat;

}SHARE_INFO;

#endif