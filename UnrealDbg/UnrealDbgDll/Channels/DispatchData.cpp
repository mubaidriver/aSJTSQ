#include "../dllmain.h"
#include "../Init/InitNTDevice.h"
#include "DispatchData.h"

//��ǲ���ݵ�����
BOOL DispatchDataToDriver(DWORD dwIoControlCode,
    PUSER_DATA userData,
    PVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned)
{
    BOOL bRet = FALSE;
    if (g_hGeneralDriverDevice != INVALID_HANDLE_VALUE)
    {
        bRet = DeviceIoControl(g_hGeneralDriverDevice,
            dwIoControlCode,
            userData,
            sizeof(USER_DATA),
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            NULL);
        DWORD dwError = GetLastError();
    }
    return bRet;
}

BOOL SendUserDataToDriver(DWORD dwIoControlCode,
    PVOID source,
    SIZE_T size,
    PVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned)
{
    BOOL bRet;
    std::string encodeData;
    USER_DATA userData = { 0 };
    userData.uSize = size;  //��¼���ĳ���
    if (source)
    {
        encodeData = EncryptData((const char*)source, size, KEY);
        userData.pUserData = (ULONG64)encodeData.c_str();
    }
    bRet = DispatchDataToDriver(dwIoControlCode,
        &userData,
        lpOutBuffer,
        nOutBufferSize,
        lpBytesReturned);
    return bRet;
}

//��ȡ����������
//ULONG GetDriverData(DWORD dwIoControlCode, PVOID pBuf)
//{
//    USER_DATA userData = { 0 };
//    userData.pUserData = (ULONG64)pBuf;
//    if (DispatchDataToDriver(dwIoControlCode, &userData))
//    {
//        return userData.uSize;
//    }
//    return 0;
//}