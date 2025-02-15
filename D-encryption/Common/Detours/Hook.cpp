#include <Windows.h>
#include "detours.h"
#include "Hook.h"


#ifdef _WIN64
#pragma comment(lib,"../Common/Detours/x64/detours.lib")
#else
#pragma comment(lib,"../Common/Detours/x86/detours.lib")
#endif // _WIN64

//��װhook
void HookOn(_In_ PVOID* pfun, _In_ PVOID proxy_fun, _In_ HANDLE hThread)
{
	//�޸�Ŀ���ڴ�ҳ��������
	DetourTransactionBegin();
	//��ͣĿ���߳�
	DetourUpdateThread(hThread);
	//��ʼhook
	DetourAttach(pfun, proxy_fun);
	//�ύִ��
	DetourTransactionCommit();
}

//ж��hook
void HookOff(_In_ PVOID* pfun, _In_ PVOID proxy_fun, _In_ HANDLE hThread)
{
	//�޸�Ŀ���ڴ�ҳ��������
	DetourTransactionBegin();
	//��ͣĿ���߳�
	DetourUpdateThread(hThread);
	//ж��hook
	DetourDetach(pfun, proxy_fun);
	//�ύִ��
	DetourTransactionCommit();
}