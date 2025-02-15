#include "../../dllmain.h"
#include "../../Globals.h"
#include "../../Channels/DispatchData.h"
#include "ApcInject.h"

void ApcCallRemoteFunc(HANDLE hProcess)
{
	if (!_ApcCallRemoteFunc(hProcess))
	{
		logger.Log("APCע���߳�ʧ��");
	}
	else
	{
		logger.Log("APCע��ɹ�");
	}
}

//ͨ������ע��apc�̵߳�Ŀ�����
BOOL _ApcCallRemoteFunc(HANDLE hProcess)
{
	BOOL bRet;
	DWORD BytesReturned = 0;
	RING3_REMOTE_THREAD Info = { 0 };
	Info.hProcess = (ULONG64)hProcess;
	Info.pUserFunc = (ULONG64)DbgUserBreakPoint;
	bRet = SendUserDataToDriver(IOCTL_CREATE_REMOTE_THREAD, &Info, sizeof(RING3_REMOTE_THREAD), NULL, 0, &BytesReturned);
	return bRet;
}