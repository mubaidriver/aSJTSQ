#pragma once

#ifndef _START_PROCESS_H

//������Ϣ
typedef struct _STARTUP_INFO
{
	TCHAR szExe[256];
	TCHAR sPath[256];
}STARTUP_INFO, * PSTARTUP_INFO;

BOOL StartProcess(TCHAR* szExe, TCHAR* sPath);

//���ݹ��λ�û�ȡ����pid
DWORD GetProcessId_ByCursor();

//�·���������Ϣ������
BOOL SendDebuggerDataToDriver(DWORD dwProcessId);


#endif // !_START_PROCESS_H
