#include "../../dllmain.h"
#include "../../Log/Log.h"
#include "../../Globals.h"
#include "InjectCode.h"

unsigned char ShellCode[] =
{
	//0x48, 0x83, 0xEC, 0x28, 0x90, 0x33, 0xC9, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, /*0x50, 0xC3,*/ 0x48, 0x83, 0xC4, 0x28, 0xC3
	0x48, 0x83, 0xEC, 0x28, 0xCC, 0x48, 0x83, 0xC4, 0x28, 0xC3
};


const DWORD ins_len = 20;

BYTE originalInstructions[ins_len] = { 0 };


//ժ������
void RemoveHook(DWORD dwPid)
{
	try
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess)
		{
			LdrInitializeThunk = (PFN_LDRINITIALIZETHUNK)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "LdrInitializeThunk");
			SIZE_T Size = 0;
			DWORD dwOldProtect;
			BYTE InstructionsBuf[ins_len] = { 0 };

			VirtualProtect((LPVOID)LdrInitializeThunk, ins_len, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy(InstructionsBuf, LdrInitializeThunk, ins_len);  //�������ڴ����û�б��޸ĵĿ�һ������

			//����Ŀ����̵�����
			if (!ReadProcessMemory(hProcess, LdrInitializeThunk, originalInstructions, sizeof(originalInstructions), &Size))
			{
				throw std::runtime_error("RemoveHook ����ʧ��");
			}
			//ժ������
			if (!WriteProcessMemory(hProcess, LdrInitializeThunk, InstructionsBuf, sizeof(InstructionsBuf), &Size))
			{
				throw std::runtime_error("RemoveHook д������ʧ��");
			}
			VirtualProtect((LPVOID)LdrInitializeThunk, ins_len, dwOldProtect, &dwOldProtect);
			// �رս��̾��
			CloseHandle(hProcess);
		}
		else
		{
			logger.Log("�򿪽���ʧ�� error: %d",GetLastError());
		}
	}
	catch (const std::exception& e)
	{
		OutputDebugStringA(e.what());
	}
}

//�ָ�����
void RestoreHook(DWORD dwPid)
{
	try
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess)
		{
			LdrInitializeThunk = (PFN_LDRINITIALIZETHUNK)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "LdrInitializeThunk");
			SIZE_T Size = 0;

			//�ָ�����
			if (!WriteProcessMemory(hProcess, LdrInitializeThunk, originalInstructions, sizeof(originalInstructions), &Size))
			{
				throw std::runtime_error("RestoreHook д������ʧ��");
			}
			// �رս��̾��
			CloseHandle(hProcess);
		}
		else
		{
			logger.Log("�򿪽���ʧ�� error: %d", GetLastError());
		}
	}
	catch (const std::exception& e)
	{
		OutputDebugStringA(e.what());
	}
}


//ժ������
void RemoveKiUserApcDispatcherHook(DWORD dwPid)
{
	try
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess)
		{
			KiUserApcDispatcher = (PFN_LDRINITIALIZETHUNK)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "KiUserApcDispatcher");
			SIZE_T Size = 0;
			DWORD dwOldProtect;
			BYTE InstructionsBuf[ins_len] = { 0 };

			VirtualProtect((LPVOID)KiUserApcDispatcher, ins_len, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy(InstructionsBuf, KiUserApcDispatcher, ins_len);  //�������ڴ����û�б��޸ĵĿ�һ������

			//����Ŀ����̵�����
			if (!ReadProcessMemory(hProcess, KiUserApcDispatcher, originalInstructions, sizeof(originalInstructions), &Size))
			{
				throw std::runtime_error("RemoveHook ����ʧ��");
			}
			//ժ������
			if (!WriteProcessMemory(hProcess, KiUserApcDispatcher, InstructionsBuf, sizeof(InstructionsBuf), &Size))
			{
				throw std::runtime_error("RemoveHook д������ʧ��");
			}
			VirtualProtect((LPVOID)KiUserApcDispatcher, ins_len, dwOldProtect, &dwOldProtect);
			// �رս��̾��
			CloseHandle(hProcess);
		}
		else
		{
			logger.Log("�򿪽���ʧ�� error: %d", GetLastError());
		}
	}
	catch (const std::exception& e)
	{
		OutputDebugStringA(e.what());
	}
}

//�ָ�����
void RestoreKiUserApcDispatcherHook(DWORD dwPid)
{
	try
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess)
		{
			KiUserApcDispatcher = (PFN_LDRINITIALIZETHUNK)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "KiUserApcDispatcher");
			SIZE_T Size = 0;

			//�ָ�����
			if (!WriteProcessMemory(hProcess, KiUserApcDispatcher, originalInstructions, sizeof(originalInstructions), &Size))
			{
				throw std::runtime_error("RestoreHook д������ʧ��");
			}
			// �رս��̾��
			CloseHandle(hProcess);
		}
		else
		{
			logger.Log("�򿪽���ʧ�� error: %d", GetLastError());
		}
	}
	catch (const std::exception& e)
	{
		OutputDebugStringA(e.what());
	}
}


BOOL InjectCode(HANDLE hProcess)
{
	HANDLE remoteThread;
	PVOID remoteAddress;
	DWORD error = 0;
	BOOL boRet = FALSE;

	HANDLE hThread;
	CLIENT_ID ClientId;
	NTSTATUS Status;

	//*(ULONG64*)(&ShellCode[9]) = (ULONG64)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "RtlExitUserThread");
	//*(ULONG64*)(&ShellCode[9]) = (ULONG64)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "DbgBreakPoint");

	//hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess)
	{
		//remoteAddress = VirtualAllocEx(hProcess, NULL, sizeof(ShellCode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		//if (remoteAddress)
		//{
		//	WriteProcessMemory(hProcess, remoteAddress, ShellCode, sizeof(ShellCode), NULL);


			///* Create the thread that will do the breakin */
			//Status = RtlCreateUserThread(hProcess,
			//    NULL,
			//    FALSE,
			//    0,
			//    0,
			//    PAGE_SIZE,
			//    (PUSER_THREAD_START_ROUTINE)DbgBreakPoint,
			//    NULL,
			//    &hThread,
			//    &ClientId);

			///* Close the handle on success */
			//if (NT_SUCCESS(Status))
			//{
			//	NtClose(hThread);
			//}
			//else
			//{
			//	error = GetLastError();
			//	outDebug((TCHAR*)_T("����Զ���߳�ʧ�ܣ�(error:%d)"), error);
			//}

		//	remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)DbgBreakPoint, NULL, 0, NULL);
		//	if (remoteThread)
		//	{
		//		//outDebug((TCHAR*)_T("remoteAddress:  %llX"), remoteAddress);
		//		CloseHandle(remoteThread);
		//	}
		//	else
		//	{
		//		error = GetLastError();
		//		outDebug((TCHAR*)_T("����Զ���߳�ʧ�ܣ�(error:%d)"), error);
		//	}
		//}
		//else
		//{
		//	error = GetLastError();
		//	outDebug((TCHAR*)_T("����Զ�����ڴ�ʧ�ܣ�(error:%d)"), error);
		//}

		//remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)DbgBreakPoint, NULL, 0, NULL);
		remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((BYTE*)DbgUserBreakPoint + 0x10), NULL, 0, NULL);
		if (remoteThread)
		{
			logger.Log("����Զ���߳�DbgBreakPoint�ɹ���");
			CloseHandle(remoteThread);
			boRet = TRUE;
		}
		else
		{
			error = GetLastError();
			outDebug((TCHAR*)_T("����Զ���߳�DbgBreakPointʧ�ܣ�(error:%d)"), error);
		}
	}
	else
	{
		error = GetLastError();
		outDebug((TCHAR*)_T("�򿪽��̾��ʧ�ܣ�(error:%d)"), error);
	}
	return boRet;
}