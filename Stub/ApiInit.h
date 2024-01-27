#ifndef _2CKSTUB_STUB_APIINIT_H_
#define _2CKSTUB_STUB_APIINIT_H_

#include <Windows.h>
#include "pe.h"

typedef int (WINAPI* _MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
typedef BOOL(WINAPI* _VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HMODULE (WINAPI* _LoadLibraryA)(LPCSTR lpLibFileName);
typedef HMODULE(WINAPI* _GetModuleHandleA)(LPCSTR lpModuleName);
typedef VOID (WINAPI* _ExitProcess)(UINT uExitCode);
typedef LPVOID(WINAPI* _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
//--------------------------------------------------------------------------
//typedef LPVOID(WINAPI* GETPROCADDRESS)(HANDLE, LPCSTR);
//typedef HANDLE(WINAPI* LOADLIBRARYA)(LPCSTR);
//typedef int(WINAPI* MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
//typedef HANDLE(WINAPI* CREATETHREAD)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
//typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);
//typedef BOOL(WINAPI* DISABLETHREADLIBRARYCALLS)(HMODULE hLibModule);
//typedef	INT(WINAPIV* WSPRINTFW)(LPWSTR lpOut, LPCWSTR lpIn, ...);
//typedef	INT(WINAPIV* WSPRINTFA)(LPSTR lpOut, LPCSTR lpIn, ...);
//typedef LPVOID(WINAPI* HEAPALLOC)(HANDLE, DWORD, SIZE_T);
//typedef BOOL(WINAPI* HEAPFREE)(HANDLE, DWORD, LPVOID);
//typedef HANDLE(WINAPI* GETPROCESSHEAP)();
//typedef VOID(WINAPI* EXITPROCESS)(
//	UINT uExitCode
//	);
//typedef DWORD(WINAPI* GETLASTERROR)();
//typedef VOID(WINAPI* EXITTHREAD)(
//	DWORD dwExitCode
//	);
//typedef BOOL(WINAPI* GETMODULEHANDLEEXW)(
//	DWORD   dwFlags,
//	LPCWSTR lpModuleName,
//	HMODULE* phModule
//	);
//typedef PVOID(WINAPI* ADDVECTOREDEXCEPTIONHANDLER)(
//	ULONG                       First,
//	PVECTORED_EXCEPTION_HANDLER Handler
//	);
//typedef ULONG(WINAPI* REMOVEVECTOREDEXCEPTIONHANDLER)(
//	PVOID Handle
//	);
//--------------------------------------------------------------------------
//GETPROCADDRESS _GetProcAddress;
//LOADLIBRARYA _LoadLibraryA;
//MESSAGEBOXW _MessageBoxW;
//CREATETHREAD _CreateThread;
//CLOSEHANDLE _CloseHandle;
//DISABLETHREADLIBRARYCALLS _DisableThreadLibraryCalls;
//WSPRINTFW _wsprintfW;
//WSPRINTFA _wsprintfA;
//HEAPALLOC _HeapAlloc;
//HEAPFREE _HeapFree;
//GETPROCESSHEAP _GetProcessHeap;
//EXITPROCESS _ExitProcess;
//GETLASTERROR _GetLastError;
//EXITTHREAD _ExitThread;
//GETMODULEHANDLEEXW _GetModuleHandleExW;
//ADDVECTOREDEXCEPTIONHANDLER _AddVectoredExceptionHandler;
//REMOVEVECTOREDEXCEPTIONHANDLER _RemoveVectoredExceptionHandler;
//--------------------------------------------------------------------------

VOID WINAPI ApiInit(LPVOID imageBase);
LPVOID WINAPI GetModuleBase(LPCSTR moduleName);


#ifdef _WIN64
DWORD64 WINAPI GetKernelBase();
#else
DWORD WINAPI GetKernelBase();
#endif
#endif