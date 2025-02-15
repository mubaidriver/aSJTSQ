#pragma once

#ifndef _DISPATCH_DATA_H
#define _DISPATCH_DATA_H

//��ǲ���ݵ�����
BOOL DispatchDataToDriver(DWORD dwIoControlCode,
    PUSER_DATA userData,
    PVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned);

BOOL SendUserDataToDriver(DWORD dwIoControlCode,
    PVOID source,
    SIZE_T size,
    PVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned);

//��ȡ����������
ULONG GetDriverData(DWORD dwIoControlCode, PVOID pBuf);


#endif // !_DISPATCH_DATA_H
