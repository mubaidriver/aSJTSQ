#include <iostream>
#include <Windows.h>
#include <string>
#include <codecvt>
#include <random>
#include <tuple>
#include <TlHelp32.h>
#include <vector>
#include <psapi.h>
#include <intrin.h>
#include <array>
#include <mutex>
#include <fstream>
#include <sstream>
#include "Common.h"

namespace Common
{

	HANDLE hMutex;// ���࿪
	bool isIntel = false;
	bool isAMD = false;
	std::mutex mutex; // ������

	//stringתwstring
	std::wstring stringToWideString(const std::string& narrowStr)
	{
		// ��ȡ���ַ��ַ����ĳ��ȣ���������ֹ����
		int wideStrLength = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, nullptr, 0);

		// �����ڴ����洢���ַ��ַ���
		wchar_t* wideStr = new wchar_t[wideStrLength];

		// ��խ�ַ�ת��Ϊ���ַ�
		MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, wideStr, wideStrLength);

		// ���� std::wstring ����
		std::wstring result(wideStr);

		// �ͷ��ڴ�
		delete[] wideStr;

		return result;
	}

	//wstringתstring
	//ע��: ��Windows�½�utf16תutf8��std::string���޷�������ʾ���ĵ�
	std::string wideStringToString(const std::wstring& wideStr)
	{
		int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
		std::string str(bufferSize - 1, 0);
		WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &str[0], bufferSize - 1, nullptr, nullptr);
		return str;
	}

	//wstringת����string
	//ע��: ����ansi������ʾ���ģ����벻Ҫ���������ݴ�����ʹ��������Ϊ��ͬ��������ش���ҳ����ͬ.
	std::string wideStringToString2(const std::wstring& wideStr)
	{
		int bufferSize = WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
		std::string str(bufferSize - 1, 0);
		WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), -1, &str[0], bufferSize - 1, nullptr, nullptr);
		return str;
	}

	//wchar_t*תstring
	std::string wcharToString(const wchar_t* str)
	{
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		return converter.to_bytes(str);
	}

	//wchar_t*תwstring
	std::wstring wcharToWideString(const wchar_t* wcharStr)
	{
		// ʹ�ù��캯���� wchar_t* ת��Ϊ std::wstring
		std::wstring wideStr(wcharStr);

		return wideStr;
	}

	//char*תwchar_t*
	std::wstring ConvertCharToWchar(const char* charStr)
	{
		const int charStrLength = strlen(charStr) + 1; // char �ַ����ĳ��ȣ����� null ��ֹ����

		// ���� wchar_t �ַ�������Ļ�������С
		const int wcharStrSize = MultiByteToWideChar(CP_UTF8, 0, charStr, charStrLength, nullptr, 0);

		// ���� wchar_t ������
		wchar_t* wcharStr = new wchar_t[wcharStrSize];

		// ִ��ת��
		MultiByteToWideChar(CP_UTF8, 0, charStr, charStrLength, wcharStr, wcharStrSize);

		// �� wchar_t �ַ�����װ�� std::wstring ����
		std::wstring result(wcharStr);

		// �ͷ��ڴ�
		delete[] wcharStr;

		return result;
	}

	//gbkתutf8
	std::string GbkToUTF8(const std::string& gbkString)
	{
		int bufferSize = MultiByteToWideChar(CP_ACP, 0, gbkString.c_str(), -1, nullptr, 0);
		std::wstring wideString(bufferSize - 1, L'\0');
		MultiByteToWideChar(CP_ACP, 0, gbkString.c_str(), -1, &wideString[0], bufferSize - 1);

		bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, nullptr, 0, nullptr, nullptr);
		std::string utf8String(bufferSize - 1, '\0');
		WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, &utf8String[0], bufferSize - 1, nullptr, nullptr);

		return utf8String;
	}

	//gbkתutf8
	//std::string GbkToUTF8(const std::string& gbkString)
	//{
	//	int bufferSize = MultiByteToWideChar(CP_ACP, 0, gbkString.c_str(), -1, nullptr, 0);
	//	std::wstring wideString(bufferSize, L'\0');
	//	MultiByteToWideChar(CP_ACP, 0, gbkString.c_str(), -1, &wideString[0], bufferSize);

	//	bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, nullptr, 0, nullptr, nullptr);
	//	std::string utf8String(bufferSize, '\0');
	//	WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, &utf8String[0], bufferSize, nullptr, nullptr);

	//	return utf8String;
	//}

	// �� utf8 ������ַ���ת��Ϊ GBK ����
	std::string utf8ToGbk(const std::string& utf8String)
	{
		int bufferSize = MultiByteToWideChar(CP_UTF8, 0, utf8String.c_str(), -1, nullptr, 0);
		if (bufferSize == 0)
		{
			// ת��ʧ�ܣ����Ը���ʵ��������д�����
			return "";
		}

		std::wstring wideString(bufferSize, L'\0');
		MultiByteToWideChar(CP_UTF8, 0, utf8String.c_str(), -1, &wideString[0], bufferSize);

		bufferSize = WideCharToMultiByte(CP_ACP, 0, wideString.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (bufferSize == 0)
		{
			// ת��ʧ�ܣ����Ը���ʵ��������д�����
			return "";
		}

		std::string gbkString(bufferSize, '\0');
		WideCharToMultiByte(CP_ACP, 0, wideString.c_str(), -1, &gbkString[0], bufferSize, nullptr, nullptr);

		return gbkString;
	}

	// �� utf8 ������ַ���ת��Ϊ Unicode ����
	std::wstring utf8ToUnicode(const std::string& utf8String)
	{
		int bufferSize = MultiByteToWideChar(CP_UTF8, 0, utf8String.c_str(), -1, nullptr, 0);
		std::wstring unicodeString(bufferSize, 0);
		MultiByteToWideChar(CP_UTF8, 0, utf8String.c_str(), -1, &unicodeString[0], bufferSize);
		return unicodeString;
	}

	//���ش���ҳתstd::wstring
	std::wstring ConvertLocalCodePageToWideString(const std::string& str)
	{
		int wideStrLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
		if (wideStrLen == 0)
		{
			// ת��ʧ�ܣ����Ը���ʵ������������
			return L"";
		}

		std::wstring wideStr(wideStrLen, L'\0');
		if (MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wideStr[0], wideStrLen) == 0)
		{
			// ת��ʧ�ܣ����Ը���ʵ������������
			return L"";
		}

		// ȥ��ĩβ�Ŀ��ַ�
		wideStr.resize(wideStrLen - 1);

		return wideStr;
	}

	//���ش���ҳתstd::string
	std::string LocalCodePageToUtf8(const std::string& localString)
	{
		int wideCharLength = MultiByteToWideChar(CP_ACP, 0, localString.c_str(), -1, nullptr, 0);
		if (wideCharLength == 0) {
			// ת��ʧ��
			return "";
		}

		std::wstring wideString(wideCharLength, L'\0');
		if (MultiByteToWideChar(CP_ACP, 0, localString.c_str(), -1, &wideString[0], wideCharLength) == 0) {
			// ת��ʧ��
			return "";
		}

		int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (utf8Length == 0) {
			// ת��ʧ��
			return "";
		}

		std::string utf8String(utf8Length, '\0');
		if (WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, &utf8String[0], utf8Length, nullptr, nullptr) == 0) {
			// ת��ʧ��
			return "";
		}

		return utf8String;
	}

	//UnicodeתUtf8
	std::string UnicodeToUtf8(const std::wstring& unicodeString)
	{
		int utf8Length = WideCharToMultiByte(CP_UTF8, 0, unicodeString.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (utf8Length == 0) {
			// ת��ʧ��
			return "";
		}

		std::string utf8String(utf8Length, '\0');
		if (WideCharToMultiByte(CP_UTF8, 0, unicodeString.c_str(), -1, &utf8String[0], utf8Length, nullptr, nullptr) == 0) {
			// ת��ʧ��
			return "";
		}

		return utf8String;
	}

	//����16λ����ַ���
	std::string generateRandomString()
	{
		const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		const int length = 16;

		std::random_device rd;
		std::mt19937 generator(rd());
		std::uniform_int_distribution<int> distribution(0, characters.length() - 1);

		std::string randomString;

		for (int i = 0; i < length; ++i) {
			randomString += characters[distribution(generator)];
		}

		return randomString;
	}

	//�ַ�����ȡ
	std::string truncateString(const std::string& input, int length)
	{
		if (length >= input.length())
		{
			return input;
		}
		else
		{
			return input.substr(0, length);
		}
	}

	//��ȡ�ַ��� ��ʣ���ַ���
	std::tuple<std::string, std::string> truncateString2(const std::string& input, int length)
	{
		if (length >= input.length())
		{
			return std::make_tuple(input, "");
		}
		else
		{
			return std::make_tuple(input.substr(0, length), input.substr(length));
		}
	}

	//��stringתСд
	std::string ToLowerWindows(const std::string& str)
	{
		std::string lowerStr(str);
		CharLowerBuffA(&lowerStr[0], static_cast<DWORD>(lowerStr.size()));

		return lowerStr;
	}

	//��wstringתСд
	std::wstring ToLowerWindows(const std::wstring& str)
	{
		std::wstring lowerStr(str);
		CharLowerBuffW(&lowerStr[0], static_cast<DWORD>(lowerStr.size()));

		return lowerStr;
	}

	//ö�ٽ���
	std::vector<ProcessInfo> EnumerateProcesses()
	{
		std::vector<ProcessInfo> processes;

		// ��ȡϵͳ�����н��̵Ŀ���
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			// ���ؿ�����
			return processes;
		}

		PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) };

		// ö�ٽ��̿����еĽ�����Ϣ
		if (Process32First(hSnapshot, &processEntry))
		{
			do
			{
				ProcessInfo process;
				process.processId = processEntry.th32ProcessID;
				process.processName = processEntry.szExeFile;

				// �򿪽���
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
				if (hProcess != nullptr)
				{
					TCHAR modulePath[MAX_PATH] = { 0 };
					if (GetModuleFileNameEx(hProcess, NULL, modulePath, MAX_PATH))
					{
						process.FullPath = modulePath;
					}
					CloseHandle(hProcess);					
				}
				processes.push_back(process);
			} while (Process32Next(hSnapshot, &processEntry));
		}

		// �رս��̿��վ��
		CloseHandle(hSnapshot);

		return processes;
	}

	//���Ŀ������Ƿ���������
	BOOL IsProcessRunning(const std::wstring& processName)
	{
		BOOL boRet = FALSE;
		PROCESSENTRY32W entry;
		entry.dwSize = sizeof(PROCESSENTRY32W);

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			if (Process32FirstW(hSnapshot, &entry))
			{
				do
				{
					std::wstring currentProcessName = Common::ToLowerWindows(entry.szExeFile);
					if (currentProcessName.find(Common::ToLowerWindows(processName)) != std::wstring::npos)  //�����Ӵ�
					{
						boRet = TRUE;
						break;
					}
				} while (Process32NextW(hSnapshot, &entry));
			}
			CloseHandle(hSnapshot);
		}
		return boRet;
	}

	//���Ҵ�����Ϣ
	BOOL FindWindowInfo(LPCWSTR lpClassName, LPCWSTR titleName)
	{
		if (FindWindow(lpClassName, titleName))
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}

	//��ֹ����
	bool TerminateWindowsProcess(DWORD processId)
	{
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
		if (hProcess == NULL)
		{
			// ����򿪽���ʧ�ܵ����
			return false;
		}

		// ��ֹ����
		bool result = TerminateProcess(hProcess, 0);

		// �رս��̾��
		CloseHandle(hProcess);

		return result;
	}


	//����ģʽ
	//��ֹ����࿪
	BOOL SingletonPattern(const wchar_t* mutexName)
	{
		BOOL boRet = FALSE;

		// ����������
		hMutex = CreateMutexW(nullptr, TRUE, mutexName);

		// ��黥�����Ƿ��Ѵ���
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			// �رջ����������˳�����
			CloseHandle(hMutex);
		}
		else
		{
			boRet = TRUE;;
		}
		return boRet;
	}

	//�˳�����
	void SingletonProgramEnd()
	{
		// �رջ�������
		if (hMutex)
		{
			CloseHandle(hMutex);
		}		
	}

	//intתwstring
	std::wstring IntToWString(int value)
	{
		return std::to_wstring(value);
	}

	//wstringתint
	int WStringToInt(const std::wstring& str)
	{
		return std::stoi(str);
	}

	//ȷ��CPU�ͺ�
	void ConfirmCPUVendor()
	{
		std::array<int, 4> cpui;

		// Calling __cpuid with 0x0 as the function_id argument
		// gets the number of the highest valid function ID.
		__cpuid(cpui.data(), 0);

		// Capture vendor string
		char vendor[0x20];
		memset(vendor, 0, sizeof(vendor));
		*reinterpret_cast<int*>(vendor) = cpui[ebx];
		*reinterpret_cast<int*>(vendor + 4) = cpui[edx];
		*reinterpret_cast<int*>(vendor + 8) = cpui[ecx];
		std::string vendor_ = vendor;
		if (vendor_ == "GenuineIntel")
		{
			isIntel = true;
		}
		else if (vendor_ == "AuthenticAMD")
		{
			isAMD = true;
		}
	}

	BOOL xxx_Process(DWORD dwProcessID, BOOL fSuspend)
	{
		BOOL bRet = FALSE;
		//Get the list of threads in the system.
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);

		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			//Walk the list of threads.
			THREADENTRY32 te = { sizeof(te) };
			BOOL fOk = Thread32First(hSnapshot, &te);

			for (; fOk; fOk = Thread32Next(hSnapshot, &te))
			{
				//Is this thread in the desired process?
				if (te.th32OwnerProcessID == dwProcessID)
				{
					//Attempt to convert the thread ID into a handle.
					HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

					if ((hThread != NULL) && (GetCurrentThreadId() != te.th32ThreadID))
					{
						//Suspend or resume the thread.
						if (fSuspend)
						{
							if (SuspendThread(hThread) != -1)
								bRet = TRUE;
						}
						else
						{
							if (ResumeThread(hThread) != -1)
								bRet = TRUE;
						}
					}
					CloseHandle(hThread);
				}
			}
			CloseHandle(hSnapshot);
		}
		return bRet;
	}

	//��ͣ����
	BOOL SuspendProcess(DWORD dwProcessID)
	{
		return xxx_Process(dwProcessID, TRUE);
	}

	//�ָ�����
	BOOL ResumeProcess(DWORD dwProcessID)
	{
		return xxx_Process(dwProcessID, FALSE);
	}

	void ReportSeriousError(const char* format, ...)
	{
		// �߳�ͬ����ʹ�û����������ٽ���
		std::lock_guard<std::mutex> lock(mutex);

		va_list args;
		va_start(args, format);
		char message[1024] = { 0 };
		vsnprintf(message, sizeof(message), format, args);
		va_end(args);

		std::ostringstream oss;
		oss << message;

		std::string logMessage = oss.str();
		if (!logMessage.empty())
		{
			MessageBoxA(NULL, logMessage.c_str(), "���ش���:", MB_ICONERROR | MB_SYSTEMMODAL);
		}		
	}

	bool fileExists(const std::wstring& path)
	{
		HANDLE hFile = CreateFile(
			path.c_str(),
			GENERIC_READ,
			0, // ������
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hFile != INVALID_HANDLE_VALUE) {
			CloseHandle(hFile);
			return true; // �ļ�����
		}
		else {
			return false; // �ļ�������
		}
	}

	//��ȡϵͳ�汾��Ϣ
	BOOL GetNtVersionNumbers(DWORD& dwMajorVer, DWORD& dwMinorVer, DWORD& dwBuildNumber)
	{
		BOOL bRet = FALSE;
		HMODULE hModNtdll = GetModuleHandle(L"ntdll.dll");
		if (hModNtdll)
		{
			typedef VOID(NTAPI* PFN_RTLGETNTVERSIONNUMBERS)(OUT PULONG pMajorVersion,
					OUT PULONG pMinorVersion,
					OUT PULONG pBuildNumber);
			PFN_RTLGETNTVERSIONNUMBERS pfnRtlGetNtVersionNumbers;
			pfnRtlGetNtVersionNumbers = (PFN_RTLGETNTVERSIONNUMBERS)GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
			if (pfnRtlGetNtVersionNumbers)
			{
				pfnRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer, &dwBuildNumber);
				dwBuildNumber &= 0x0ffff;
				bRet = TRUE;
			}
		}

		return bRet;
	}

}