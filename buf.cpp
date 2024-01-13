#include "buf.h"

BOOL _LocalBuf::CreateBuffer(DWORD dwSize, DWORD dwFlags){
    if (BufCreated == TRUE) {
        return FALSE;
    }
    
    bufAddr = HeapAlloc(hProcessHeap, dwFlags, dwSize);
    if (bufAddr == NULL) {
        return FALSE;
    }
    bufSize = dwSize;
    saveFlags = dwFlags;

    BufCreated = TRUE;
    return TRUE;
}

BOOL _LocalBuf::FreeBuffer(){
    if (BufCreated == FALSE) {
        return FALSE;
    }
    HeapFree(hProcessHeap, NULL, bufAddr);

    bufAddr = 0;
    bufSize = 0;
    saveFlags = 0;

    BufCreated = FALSE;
    return TRUE;
}

BOOL _LocalBuf::ReBufferSize(DWORD newSize){
    if (BufCreated == FALSE) {
        return FALSE;
    }
    LPVOID newFileBuffer = HeapAlloc(hProcessHeap, saveFlags, newSize);
    if (newFileBuffer == NULL) {
        return FALSE;
    }
    RtlCopyMemory(newFileBuffer, bufAddr, bufSize); //复制原先的Buf内容
    HeapFree(hProcessHeap, NULL, bufAddr);
    bufAddr = newFileBuffer;
    bufSize = newSize;

    return TRUE;
}

_LocalBuf::_LocalBuf(){
    BufCreated = FALSE;
    bufAddr = 0;
    bufSize = 0;
    saveFlags = 0;
    hProcessHeap = GetProcessHeap();
}

_LocalBuf::~_LocalBuf(){
    if (BufCreated == TRUE) {
        FreeBuffer();
    }
}
