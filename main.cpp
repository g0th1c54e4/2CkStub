#include <Windows.h>
#include <iostream>
#include "pe.h"
#include "file.h"
#include "buf.h"
#include "Packer.h"
#include "shlwapi.h"
#pragma comment(lib, "Shlwapi.lib")

#include <capstone/capstone.h>
#pragma comment (lib, "capstone.lib")

#pragma comment (lib, "aplib.lib")


using namespace std;

int main() {

	cout << "Ck2Stub By LingMo" << endl;
	cout << "QQ:909656889   Q群:952827612" << endl;
	cout << "-----------------------------" << endl;

	// C:\Users\90965\Desktop\Ck2Stub\Test.exe
	cout << "[*] 请键入需要加壳的程序路径: " << endl;
	//CHAR targetFilePath[MAX_PATH] = { 0 };
	CHAR targetFilePath[MAX_PATH] = "C:\\Users\\90965\\Desktop\\Ck2Stub\\Test.exe";
	//CHAR targetFilePath[MAX_PATH] = "C:\\Users\\90965\\Desktop\\Ck2Stub\\Test64.exe";
	//cin.getline(targetFilePath, sizeof(targetFilePath));

	// C:\Users\90965\Desktop\Ck2Stub\Stub32.bin
	cout << "[*] 请键入壳的文件路径: " << endl;
	//CHAR stubFilePath[MAX_PATH] = { 0 };
	CHAR stubFilePath[MAX_PATH] = "C:\\Users\\90965\\source\\repos\\2CkStub\\Release\\Stub32.bin";
	//CHAR stubFilePath[MAX_PATH] = "C:\\Users\\90965\\source\\repos\\2CkStub\\x64\\Release\\Stub64.bin";
	//cin.getline(stubFilePath, sizeof(stubFilePath));

	CHAR saveFilePath[MAX_PATH] = { 0 };
	if (PathRenameExtensionA(strcpy(saveFilePath, targetFilePath), ".Ck2") == FALSE) {
		cout << "[-] 拼接保存路径时发生错误。";
		return 0;
	}

	cout << "[#] 保存路径: " << strcat(saveFilePath, PathFindExtensionA(targetFilePath)) << endl;
	if (Ck2Stub::Pack(targetFilePath, stubFilePath, saveFilePath) == TRUE) {
		cout << "[+] 加壳成功。";
	}
	else {
		cout << "[-] 加壳失败。";
	}

	return 0;
	
}