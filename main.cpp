#include <Windows.h>
#include <iostream>
#include "pe.h"
#include "file.h"
#include "buf.h"
#include "Packer.h"

#include <capstone/capstone.h>
#pragma comment (lib, "capstone.lib")

using namespace std;

int main() {
	cout << "Ck2Stub By LingMo" << endl;
	cout << "QQ:909656889   QȺ:952827612" << endl;
	cout << "-----------------------------" << endl;

	// C:\Users\90965\Desktop\Ck2Stub\Test.exe
	cout << "[*] �������Ҫ�ӿǵĳ���·��: C:\\Users\\90965\\Desktop\\Ck2Stub\\Test.exe" << endl;
	//CHAR targetFilePath[MAX_PATH] = { 0 };
	CHAR targetFilePath[MAX_PATH] = "C:\\Users\\90965\\Desktop\\Ck2Stub\\Test.exe";
	//cin.getline(targetFilePath, sizeof(targetFilePath));

	// C:\Users\90965\Desktop\Ck2Stub\Stub32.bin
	cout << "[*] �����ǵ��ļ�·��: C:\\Users\\90965\\Desktop\\Ck2Stub\\Stub32.bin" << endl;
	//CHAR stubFilePath[MAX_PATH] = { 0 };
	CHAR stubFilePath[MAX_PATH] = "C:\\Users\\90965\\Desktop\\Ck2Stub\\Stub32.bin";
	//cin.getline(stubFilePath, sizeof(stubFilePath));


	if (Ck2Stub::Pack(targetFilePath, stubFilePath, ".ck2_0", (CHAR*)"C:\\Users\\90965\\Desktop\\Ck2Stub\\Test.Ck2.exe") == TRUE) {
		cout << "[+] �ӿǳɹ���";
	}
	else {
		cout << "[-] �ӿ�ʧ�ܡ�";
	}

	return 0;
	
}