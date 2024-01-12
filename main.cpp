#include <Windows.h>
#include <iostream>
#include "pe.h"
#include "file.h"

#include <capstone/capstone.h>
#pragma comment (lib, "capstone.lib")

using namespace std;

int main() {
	cout << "2CkStub By LingMo" << endl;
	cout << "QQ:909656889   Q群:952827612" << endl;
	cout << "-----------------------------" << endl;

	// C:\Users\90965\Desktop\Test.exe
	cout << "[*] 请键入需要加壳的程序路径: ";
	CHAR targetFilePath[MAX_PATH] = { 0 };
	cin.getline(targetFilePath, sizeof(targetFilePath));


	PeFile curFile;
	if (curFile.init(targetFilePath) == FALSE) {
		cout << "[-] 打开PE文件失败或文件非PE文件。" << endl;
		return 0;
	}
	


	return 0;
	
}