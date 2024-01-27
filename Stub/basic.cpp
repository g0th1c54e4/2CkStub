#include "basic.h"

BOOL WINAPI StringCmp(LPCSTR lpStr1, LPCSTR lpStr2) {
	if (lpStr1 == NULL || lpStr2 == NULL) {
		return FALSE;
	}
	if (StringLen(lpStr1) != StringLen(lpStr2)) {
		return FALSE;
	}
	for (DWORD dwCount = 0; lpStr1[dwCount] != 0 && lpStr2[dwCount] != 0; dwCount++) {
		if (lpStr1[dwCount] != lpStr2[dwCount]) {
			return FALSE;
		}
	}
	
	return TRUE;
}

DWORD WINAPI StringLen(LPCSTR lpStr){
	DWORD i = 0;
	while (*((BYTE*)lpStr + i) != '\0') {
		i++;
	}
	return i;
}
