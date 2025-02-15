#include "../dllmain.h"
#include "InitNTDevice.h"


//����NT����
typedef BOOL(__stdcall* PFN_LOADNT)(const std::wstring DriveImagePath, const std::wstring ServiceName);
//ж��NT����
typedef BOOL(__stdcall* PFN_UNLOADNT)(const std::wstring ServiceName);

typedef int(__stdcall* PFN_OUTDEBUG)(const TCHAR* _Format, ...);

PFN_LOADNT pfnLoadNT;
PFN_UNLOADNT pfnUnloadNT;
PFN_OUTDEBUG outDebug;

HANDLE g_hGeneralDriverDevice = INVALID_HANDLE_VALUE;


//��������
HANDLE CreateDeviceHandle(const std::wstring DriveImagePath, const std::wstring ServiceName)
{
    DWORD error = 0;
    //������������
    HANDLE hDevice = CreateFile(SYMBOLICLINK, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice != INVALID_HANDLE_VALUE)
    {
        return hDevice;
    }
    else
    {
        pfnLoadNT(DriveImagePath, ServiceName);

        logger.outDebug(L"�������ӷ���...");
        hDevice = CreateFile(SYMBOLICLINK, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDevice != INVALID_HANDLE_VALUE)
        {
            logger.outDebug(L"���������ɹ���");
            return hDevice;
        }
        else
        {
            error = GetLastError();
            logger.outDebug(L"��������ʧ�ܣ�����������������δ��װ! (error:%d)", error);
        }
    }

    return INVALID_HANDLE_VALUE;
}

//����VT����
BOOL LoadVT(const std::wstring DriveImagePath, const std::wstring ServiceName)
{
    if (!pfnLoadNT(DriveImagePath, ServiceName))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

//������������
BOOL LoadGeneralDriver(const std::wstring DriveImagePath, const std::wstring ServiceName)
{
    g_hGeneralDriverDevice = CreateDeviceHandle(DriveImagePath, ServiceName);
    if (g_hGeneralDriverDevice == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

//��ʼ�������豸
BOOL InitializeDevice(const std::wstring DriveImagePath)
{
    BOOL bRet = TRUE;

    if (!LoadVT(DriveImagePath + L"VT_Driver.sys", L"VT_Driver"))
    {
        return FALSE;
    }

    DWORD dwMajorVer, dwMinorVer, dwBuildNumber, error;
    if (Common::GetNtVersionNumbers(dwMajorVer, dwMinorVer, dwBuildNumber))
    {
        if (dwBuildNumber >= 22000)
        {
            //Win11
            if (!LoadGeneralDriver(DriveImagePath + L"DbgkSysWin11.sys", L"UnrealDevice"))
            {
                bRet = FALSE;
            }
        }
        else
        {
            //Win10
            if (!LoadGeneralDriver(DriveImagePath + L"DbgkSysWin10.sys", L"UnrealDevice"))
            {
                bRet = FALSE;
            }
        }
    }
    else
    {
        error = GetLastError();
        logger.outDebug(L"�޷���ȡϵͳ�汾��Ϣ! (error:%d)", error);
        bRet = FALSE;
    }
    return bRet;
}

//��ʼ���ӿ�
BOOL InitInterface()
{
    HMODULE AIHelperMod = LoadLibrary(L"AIHelper.dll");
    if (!AIHelperMod)
    {
        ::MessageBox(NULL, _T("û���ҵ� AIHelper.dll"), _T("������Ϣ:"), MB_ICONWARNING);
        return FALSE;
    }
    pfnLoadNT = (PFN_LOADNT)GetProcAddress(AIHelperMod, "LoadNT");
    pfnUnloadNT = (PFN_UNLOADNT)GetProcAddress(AIHelperMod, "UnloadNT");
    outDebug = (PFN_OUTDEBUG)GetProcAddress(AIHelperMod, "outDebug");
    return TRUE;
}

BOOL _Initialize(const TCHAR* sPath)
{
    BOOL boInit = FALSE;
    std::wstring sDrivePath(sPath);
    if (!sDrivePath.empty())
    {
        if (InitInterface())
        {
            boInit = InitializeDevice(sDrivePath);
        }
    }
    return boInit;
}

//����ʱ��ɨβ����
BOOL UnInitialize()
{
    BOOL boUnInit = FALSE;
    if (g_hGeneralDriverDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hGeneralDriverDevice);
        g_hGeneralDriverDevice = INVALID_HANDLE_VALUE;
    }

    if (pfnUnloadNT(L"BACDevice"))
    {
        outDebug(L"ֹͣ����������ɹ�..");
        boUnInit = TRUE;
    }
    else
    {
        outDebug(L"ֹͣ����������ʧ��!");
        boUnInit = FALSE;
    }

    if (pfnUnloadNT(L"VT_Driver"))
    {
        outDebug(L"ֹͣVT����ɹ�..");
        boUnInit = TRUE;
    }
    else
    {
        outDebug(L"ֹͣVT����ʧ��!");
        boUnInit = FALSE;
    }
    return boUnInit;
}