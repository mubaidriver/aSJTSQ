#pragma once

#ifndef _INIT_NTDEVICE_H
#define _INIT_NTDEVICE_H

extern HANDLE g_hGeneralDriverDevice;

//��ʼ�������豸
BOOL InitializeDevice(const std::wstring DriveImagePath);

BOOL _Initialize(const TCHAR* sPath);
//����ʱ��ɨβ����
BOOL UnInitialize();

#endif // !_INIT_NTDEVICE_H
