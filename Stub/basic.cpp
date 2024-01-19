#include "basic.h"

BOOL WINAPI StringCmp(LPCSTR lpStr1, LPCSTR lpStr2) {
	if (lpStr1 == NULL || lpStr2 == NULL) {
		return FALSE;
	}
	for (DWORD dwCount = 0; lpStr1[dwCount] != 0 && lpStr2[dwCount] != 0; dwCount++) {
		if (lpStr1[dwCount] != lpStr2[dwCount]) {
			return FALSE;
		}
	}
	return TRUE;
}