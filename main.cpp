#include <Windows.h>
#include <iostream>
#include "pe.h"
#include "file.h"

#include <capstone/capstone.h>
#pragma comment (lib, "capstone.lib")

using namespace std;

int main() {
	cout << "2CkStub By LingMo" << endl;
	cout << "QQ:909656889   QȺ:952827612" << endl;
	cout << "-----------------------------" << endl;

	// C:\Users\90965\Desktop\Test.exe
	cout << "[*] �������Ҫ�ӿǵĳ���·��: ";
	CHAR targetFilePath[MAX_PATH] = { 0 };
	cin.getline(targetFilePath, sizeof(targetFilePath));


	PeFile targetFile;
	if (targetFile.Init(targetFilePath) == FALSE) {
		cout << "[-] ��PE�ļ�ʧ�ܻ��ļ���PE�ļ���" << endl;
		return 0;
	}


	targetFile.ClosePeFile();
	return 0;
	
}