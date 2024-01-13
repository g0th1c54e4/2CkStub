#ifndef _2CKSTUB_BUF_H_
#define _2CKSTUB_BUF_H_

#include <Windows.h>

typedef class _LocalBuf {
private:
	BOOL BufCreated;
	HANDLE hProcessHeap;
	DWORD saveFlags;
public:
	LPVOID bufAddr;
	DWORD bufSize;
	BOOL CreateBuffer(DWORD dwSize, DWORD dwFlags = HEAP_ZERO_MEMORY);
	BOOL FreeBuffer();
	BOOL ReBufferSize(DWORD newSize);

	_LocalBuf();
	~_LocalBuf();
} LocalBuf;

#endif