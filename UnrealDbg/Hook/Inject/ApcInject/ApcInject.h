#pragma once

#ifndef _APC_INJECT_H
#define _APC_INJECT_H

void ApcCallRemoteFunc(HANDLE hProcess);

//ͨ������ע��apc�̵߳�Ŀ�����
BOOL _ApcCallRemoteFunc(HANDLE hProcess);

#endif // !_APC_INJECT_H
