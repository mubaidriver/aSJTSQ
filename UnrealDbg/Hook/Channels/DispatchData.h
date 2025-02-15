#pragma once

#ifndef _DISPATCHDATA_H
#define _DISPATCHDATA_H

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


#endif // !_DISPATCHDATA_H
