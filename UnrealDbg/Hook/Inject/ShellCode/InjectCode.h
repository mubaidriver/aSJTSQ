#pragma once

#ifndef _INJECT_CODE_H

BOOL InjectCode(HANDLE hProcess);


//ժ������
void RemoveHook(DWORD dwPid);

//�ָ�����
void RestoreHook(DWORD dwPid);

//ժ������
void RemoveKiUserApcDispatcherHook(DWORD dwPid);

//�ָ�����
void RestoreKiUserApcDispatcherHook(DWORD dwPid);


#endif // !_INJECT_CODE_H
