#include "../dllmain.h"
#include "../Globals.h"
#include "../Log/Log.h"
#include "vmx.h"


//bool __vm_call(unsigned __int64 vmcall_reason, unsigned __int64 rdx, unsigned __int64 r8, unsigned __int64 r9)
//{
//    __asm
//    {
//        vmcall
//    }
//}

//���߳�������ָ��cpu����
//CPU������0��ʼ
void RunOnCPU(HANDLE hThread, int CpuNo)
{
    try
    {
        if (SetProcessAffinityMask(GetCurrentProcess(), 1 << CpuNo))
        {
            DWORD_PTR previous_mask = SetThreadAffinityMask(hThread, 1 << CpuNo);
            if (!previous_mask)
            {
                throw std::runtime_error("�����߳��׺���ʧ��");
            }
        }
        else
        {
            throw std::runtime_error("���ý����׺���ʧ��");
        }
    }
    catch (const std::exception& e)
    {
        ReportSeriousError(e.what());
    }
}

bool vmcall_internal(PVOID vmcallinfo)
{
    unsigned long ecode = 0;
    bool boSuccess = false;
    __try {
        //����vmxģʽ���ָ��ᴥ��#UD�쳣
#ifdef _WIN64
        boSuccess = __vm_call(((PVMCALLINFO)vmcallinfo)->command, (unsigned __int64)vmcallinfo, 0, 0);
#else
        boSuccess = __vm_call(((PVMCALLINFO)vmcallinfo)->command, vmcallinfo);
#endif // _WIN64

    }
    __except (ecode = GetExceptionCode(), 1) {
        logger.Log("ִ��vmcallʱ�����˴��� (error: 0x%x)", ecode);
    }
    return boSuccess;
}

//��㲥�������߼�������
bool vmcall(PVOID vmcallinfo)
{
    bool boSuccess = false;
    LONG status = 0;
    SYSTEM_INFO SysInfo = { 0 };
    GetSystemInfo(&SysInfo);
    for (int i = 0; i < SysInfo.dwNumberOfProcessors; i++)
    {
        //����ǰ�߳�������ָ���Ĵ�������
        RunOnCPU(GetCurrentThread(), i);
        if (vmcall_internal(vmcallinfo))
        {            
            InterlockedIncrement(&status);
        }
    }
    return status == SysInfo.dwNumberOfProcessors;
}

//�����߼��������ҵ������¼��ɹ����Ǹ�
bool vmcall2(PVOID vmcallinfo)
{
    bool boSuccess = false;
    SYSTEM_INFO SysInfo = { 0 };
    GetSystemInfo(&SysInfo);
    for (int i = 0; i < SysInfo.dwNumberOfProcessors; i++)
    {
        //����ǰ�߳�������ָ���Ĵ�������
        RunOnCPU(GetCurrentThread(), i);
        if (vmcall_internal(vmcallinfo))
        {
            boSuccess = true;
            break;
        }
    }
    return boSuccess;
}


//ֻ����ǰ�߼���������������
bool current_vmcall(PVOID vmcallinfo)
{
    return vmcall_internal(vmcallinfo);
}