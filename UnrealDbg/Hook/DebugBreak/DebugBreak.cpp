#include "../dllmain.h"
#include "../Globals.h"
#include "../Channels/DispatchData.h"
#include "../vmx/vmx.h"
#include "../Log/Log.h"
#include "DebugBreak.h"

BOOL
WINAPI
NewSetThreadContext(
    _In_ HANDLE hThread,
    _In_ CONTEXT* lpContext
)
{
    //CE���״θ���ʱ�Ὣdrx�ڵ�ֵ��գ�������ƻᵼ����Ӳ���ϵ�ռ�ӵĳ����⵽
    if (lpContext->Dr0)
    {        
        //���ǿ���ͨ������dr7������û�����ͼ��������Ӷ�������д������ִ�С�
        //logger.Log("lpContext->Dr0: %p", lpContext->Dr0);

        //Vol3B[18.2 DEBUG REGISTERS]
        union {
            size_t flags;
            struct
            {
                size_t L0 : 1; //bit0
                size_t G0 : 1; //bit1
                size_t L1 : 1; //bit2
                size_t G1 : 1; //bit3
                size_t L2 : 1; //bit4
                size_t G2 : 1; //bit5
                size_t L3 : 1; //bit6
                size_t G3 : 1; //bit7
                size_t LE : 1; //bit8
                size_t GE : 1; //bit9
                size_t Reserved_1 : 1; //bit10
                size_t RTM : 1; //bit11
                size_t Reserved_2 : 1; //bit12
                size_t GD : 1; //bit13
                size_t Reserved_3 : 2; //bit15:14
                size_t RW_0 : 2; //bit17:16  dr0�Ķ���д��ִ�п���λ
                size_t LEN_0 : 2; //bit19:18 dr0�Ķϵ���ӵĳ���
            };
        }Dr7;

        Dr7.flags = lpContext->Dr7;

        int length = 1;  //��������1�ֽ�
        switch (Dr7.LEN_0)
        {
        case BYTE_1:
        {
            length = 1;
            break;
        }
        case BYTE_2:
        {
            length = 2;
            break;
        }
        case BYTE_4:
        {
            length = 4;
            break;
        }
        case BYTE_8:
        {
            length = 8;
            break;
        }
        }

        char szBuf[MAX_PATH] = { 0 };
        sprintf(szBuf, "[MyDebug] ����Ӳ���ϵ�  �ϵ㳤��: %d\n", length);
        OutputDebugStringA(szBuf);

        switch (Dr7.RW_0)
        {
        case WATCH_WRITE:
        {
            AddBreakpoint((PVOID)lpContext->Dr0, VMCALL_WATCH_WRITES, length); //����д
            break;
        }
        case WATCH_READWRITE:
        {
            AddBreakpoint((PVOID)lpContext->Dr0, VMCALL_WATCH_READS, length); //���Ӷ�д
            break;
        }
        default:
        {
            char szBuf[MAX_PATH] = { 0 };
            sprintf(szBuf, "[MyDebug] δ֪��ͼ dr7: %p\n", Dr7.flags);
            OutputDebugStringA(szBuf);
            break;
        }
        //case WATCH_EXECUTION_ONLY:
        //{
        //    AddBreakpoint((PVOID)lpContext->Dr0, VMCALL_WATCH_EXECUTES, length); //����ִ��
        //    break;
        //}
        }    
    }
    else
    {
        //������Ҫdr0
        RemoveBreakpoint();
    }

    //if (lpContext->Dr1 || lpContext->Dr2 || lpContext->Dr3)
    //{
    //    ReportSeriousError("���öϵ���࣬Ŀǰ��֧��һ��debugreg�ϵ�");
    //}


    //������Ϊ������dr6
    if (lpContext->Dr6 == 0)
    {
        InterlockedExchange(&g_debug_condition_detected, 0);
    }


    //����ԭ����
    CONTEXT Context = { 0 };
    Context.ContextFlags = CONTEXT_ALL | CONTEXT_EXTENDED_REGISTERS;
    BOOL boSuccess = Sys_GetThreadContext(hThread, &Context);

    if (boSuccess)
    {
        Context.EFlags = lpContext->EFlags;  //����������������ȥ���������ܱ�֤TF��־λ������
#ifdef _WIN64
        Context.Rip = lpContext->Rip;  //��Ҫ����rip�������ڵ���int3
#else
        Context.Eip = lpContext->Eip;
#endif
        Context.ContextFlags = lpContext->ContextFlags;
        //Context.Dr7 = 0xF0401;          
        Sys_SetThreadContext(hThread, &Context);  //����ϵͳ����   
    }
    return TRUE;
}

//��Ӷϵ�
//bool AddBreakpoint(_In_ CONST CONTEXT* lpContext, unsigned __int64 command)
//{
//    bool boSuccess = false;
//
//    // ���� DR0 �� DR3 �Ĵ���    
//    BreakpointList.Lock();
//    for (int i = 0; i < 4; ++i)
//    {
//        PVOID setAddress = nullptr;
//
//        switch (i)
//        {
//        case 0:
//            setAddress = (PVOID)lpContext->Dr0;
//            break;
//        case 1:
//            setAddress = (PVOID)lpContext->Dr1;
//            break;
//        case 2:
//            setAddress = (PVOID)lpContext->Dr2;
//            break;
//        case 3:
//            setAddress = (PVOID)lpContext->Dr3;
//            break;
//        default:
//            break;
//        }
//
//        // ����ַ�Ƿ���Ч�Ҳ��ڶϵ��б���
//        if (setAddress && std::find_if(BreakpointList.begin(), BreakpointList.end(), [setAddress](auto& bp) {
//            return bp.Address == (ULONG64)setAddress;
//        }) == BreakpointList.end()/*������ĩβ˵��������*/)
//        {
//            logger.Log("��Ӷϵ�: %p", setAddress);
//            if (BreakpointList.size() < 4)
//            {
//                // Add the breakpoint
//                BREAKPOINT_RECORD Breakpoint = { 0 };
//                Breakpoint.Address = (ULONG64)setAddress;
//                BreakpointList.push_back(Breakpoint);
//
//                // Apply the breakpoint
//                boSuccess = SetBreakpoint(setAddress, command);
//                if (!boSuccess)
//                {
//                    ReportSeriousError("���öϵ�ʧ��");
//                }
//            }
//            break; // ÿ�ε��ý����һ���ϵ�
//        }
//    }
//    BreakpointList.UnLock();
//
//    return boSuccess;
//}

bool RemoveBreakpoint()
{
    bool boSuccess = false;

    BreakpointList.Lock();

    //for (const auto& Breakpoint : BreakpointList)  //����б�Ϊ0����Ҳ���Զ������������forѭ����
    //{
    //    if (Breakpoint.Address)
    //    {
    //        VT_BREAK_POINT vmcallinfo = { 0 };
    //        vmcallinfo.cr3 = Breakpoint.cr3;
    //        vmcallinfo.VirtualAddress = Breakpoint.Address;
    //        vmcallinfo.Size = Breakpoint.length;
    //        vmcallinfo.command = VMCALL_WATCH_DELETE;
    //        vmcallinfo.LoopUserMode = (unsigned __int64)DbgUserBreakPoint;
    //        vmcallinfo.watchid = Breakpoint.watchid;

    //        logger.Log("Ҫ�Ƴ��ļ���id: %d", Breakpoint.watchid);

    //        SYSTEM_INFO SysInfo = { 0 };
    //        GetSystemInfo(&SysInfo);
    //        vmcallinfo.CPUCount = SysInfo.dwNumberOfProcessors;
    //        boSuccess = current_vmcall(&vmcallinfo);
    //        if (!boSuccess)
    //        {
    //            ReportSeriousError("�Ƴ��ϵ�ʧ��");
    //        }
    //    }
    //}

    DWORD BytesReturned = 0;

    for (auto& Breakpoint : BreakpointList)
    {
        if (Breakpoint.Address)
        {
            DWORD output = 520;
            if (SendUserDataToDriver(IOCTL_DEL_HARDWARE_BREAKPOINT,
                &Breakpoint,
                sizeof(BREAKPOINT_RECORD),
                &output,
                sizeof(DWORD),
                &BytesReturned))
            {
                if (output == 1998)
                {
                    boSuccess = true;                    
                    logger.Log("�Ƴ��ļ���id: %d", Breakpoint.watchid);
                }
                else
                {
                    ReportSeriousError("�Ƴ�Ӳ���ϵ�ʧ��");
                }
            }
            else
            {
                logger.Log("IOCTL_DEL_BREAKPOINT ʧ��!");
            }
        }
    }


    BreakpointList.clear();
    BreakpointList.UnLock();

    return boSuccess;
}

//��Ӷϵ�
bool AddBreakpoint(PVOID setAddress, unsigned __int64 command, int length)
{
    bool boSuccess = false;  

    // ����ַ�Ƿ���Ч�Ҳ��ڶϵ��б���
    if (setAddress && std::find_if(BreakpointList.begin(), BreakpointList.end(), [setAddress](auto& bp) {
        return bp.Address == (ULONG64)setAddress;
    }) == BreakpointList.end()/*������ĩβ˵��������*/)
    {
        logger.Log("��Ӷϵ�: %p", setAddress);
        if (BreakpointList.size() < BREAKPOINT_COUNT)
        {
            // Apply the breakpoint
            boSuccess = SetBreakpoint(setAddress, command, length);
            if (!boSuccess)
            {
                ReportSeriousError("����Ӳ���ϵ�ʧ��");
            }
        }
        else
        {
            ReportSeriousError("���öϵ���࣬Ŀǰ��֧��һ��debugreg�ϵ�");
        }
    }
    else
    {
        char szBuf[MAX_PATH] = { 0 };
        sprintf(szBuf, "[MyDebug] �ϵ��Ѿ�����: %p\n", setAddress);
        OutputDebugStringA(szBuf);
    }

    return boSuccess;
}

bool SetBreakpoint(PVOID lpBaseAddress, unsigned __int64 command, int length)
{
    bool boSuccess = false;
    DWORD BytesReturned = 0;

    if (!g_target_cr3 || !g_target_pid)
    {
        logger.Log("[%s] cr3 �� pidΪ��", __func__);
        return false;
    }

    SYSTEM_INFO SysInfo = { 0 };
    GetSystemInfo(&SysInfo);
    BREAKPOINT_RECORD Breakpoint = { 0 };
    Breakpoint.Address = (unsigned __int64)lpBaseAddress;
    Breakpoint.length = length;
    Breakpoint.cr3 = g_target_cr3;
    Breakpoint.command = command;
    Breakpoint.CPUCount = SysInfo.dwNumberOfProcessors;
    Breakpoint.LoopUserMode = (unsigned __int64)DbgUserBreakPoint;
    Breakpoint.pid = g_target_pid;
    Breakpoint.watchid = -1;
    BreakpointList.Lock();
    BreakpointList.push_back(Breakpoint);
    BreakpointList.UnLock();

    BREAKPOINT_RECORD output = { 0 };
    if (SendUserDataToDriver(IOCTL_SET_HARDWARE_BREAKPOINT,
        &Breakpoint, 
        sizeof(BREAKPOINT_RECORD),
        &output,
        sizeof(BREAKPOINT_RECORD),
        &BytesReturned))
    {
        logger.Log("���صļ���id: %d", output.watchid);
        if (output.watchid != -1)
        {
            boSuccess = true;
            logger.Log("SetBreakpoint �ɹ�!");            

            for (auto& Breakpoint : BreakpointList)
            {
                if ((Breakpoint.Address == output.Address) &&
                    (Breakpoint.command == output.command))
                {
                    Breakpoint.watchid = output.watchid;
                    break;
                }
            }

        }
        else
        {
            logger.Log("SetBreakpoint ʧ��!");
        }
    }
    else
    {
        logger.Log("IOCTL_SET_BREAKPOINT ����ʧ��!");
    }





    //if (!g_target_cr3)
    //{
    //    logger.Log("[%s] g_target_cr3 ��ָ��", __func__);
    //    return false;
    //}
    //VT_BREAK_POINT vmcallinfo = { 0 };
    //vmcallinfo.cr3 = g_target_cr3;
    //vmcallinfo.VirtualAddress = (unsigned __int64)lpBaseAddress;
    //vmcallinfo.Size = length;
    //vmcallinfo.command = command;
    //vmcallinfo.LoopUserMode = (unsigned __int64)DbgUserBreakPoint;

    //SYSTEM_INFO SysInfo = { 0 };
    //GetSystemInfo(&SysInfo);
    //vmcallinfo.CPUCount = SysInfo.dwNumberOfProcessors;
    //boSuccess = current_vmcall(&vmcallinfo);
    //if (boSuccess)
    //{
    //    logger.Log("���صļ���id: %d", vmcallinfo.watchid);
    //    // Add the breakpoint
    //    BREAKPOINT_RECORD Breakpoint = { 0 };
    //    Breakpoint.Address = vmcallinfo.VirtualAddress;
    //    Breakpoint.length = vmcallinfo.Size;
    //    Breakpoint.cr3 = vmcallinfo.cr3;
    //    Breakpoint.watchid = vmcallinfo.watchid;
    //    BreakpointList.Lock();
    //    BreakpointList.push_back(Breakpoint);
    //    BreakpointList.UnLock();
    //}
    //else
    //{
    //    logger.Log("current_vmcall ʧ��!  errorCode:%d", vmcallinfo.errorCode);
    //}
    return boSuccess;
}

BOOL WINAPI NewGetThreadContext(
    _In_ HANDLE    hThread,
    _Inout_ LPCONTEXT lpContext
)
{
    //����ԭ����
    BOOL boSuccess = Sys_GetThreadContext(hThread, lpContext);

    //�������Լ��Ķϵ��б���ϵ�
    if (boSuccess)
    {
        int i = 0;

        //logger.Log("lpContext->Dr6: %p", lpContext->Dr6);

        lpContext->Dr0 = 0;
        lpContext->Dr1 = 0;
        lpContext->Dr2 = 0;
        lpContext->Dr3 = 0;
        lpContext->Dr6 = 0;

        BreakpointList.Lock();
        for (const auto& Breakpoint : BreakpointList)  //��ʹ����б�Ϊ0����Ҳ���Զ������������forѭ����
        {
            if (Breakpoint.Address)
            {
                switch (i)
                {
                case 0:
                {
                    //ֻҪ��#DB�¼����������Ǿ���������
                    //��Ϊ�����Ѿ���Ŀ������#DB�����˹���
                    //ֻ��vt�׵�#DB�쳣�ᱻ���͸�������
                    lpContext->Dr0 = Breakpoint.Address;

                    //�жϴ���ԭ��
                    if (g_debug_condition_detected == 1)  //debugreg
                    {
                        lpContext->Dr6 = 1 << 0;
                    }
                    else if (g_debug_condition_detected == 2)  //����ִ��
                    {
                        lpContext->Dr6 = 1 << 14; //����bsλ
                        logger.Log("lpContext->Dr6: %p", lpContext->Dr6);
                    }
                    break;
                }
                case 1:
                {
                    lpContext->Dr1 = Breakpoint.Address;
                    break;
                }
                case 2:
                {
                    lpContext->Dr2 = Breakpoint.Address;
                    break;
                }
                case 3:
                {
                    lpContext->Dr3 = Breakpoint.Address;
                    break;
                }
                default:
                {
                    ReportSeriousError("�����ϵ��������࣡");
                    break;
                }
                }
                i++;
            }
        }
        BreakpointList.UnLock();      

        //if (BreakpointList.size() > 0)
        //{
        //    DWORD dwThreadId = GetThreadId(hThread);
        //    if (dwThreadId == 0)
        //    {
        //        ReportSeriousError("�޷���ȡ�߳�id��");
        //        return boSuccess;
        //    }

        //    BREAKPOINT_DETECTED vmcallinfo = { 0 };
        //    vmcallinfo.command = VMCALL_GET_BREAKPOINT;
        //    vmcallinfo.Cid.UniqueThread = (HANDLE)dwThreadId;

        //    if (vmcall2(&vmcallinfo))
        //    {
        //        logger.Log("breakpoint_detected: %p", vmcallinfo.breakpoint_detected);
        //        if (vmcallinfo.breakpoint_detected == lpContext->Dr0)
        //        {
        //            lpContext->Dr6 = 1 << 0;
        //        }
        //        else if (vmcallinfo.breakpoint_detected == lpContext->Dr1)
        //        {
        //            lpContext->Dr6 = 1 << 1;
        //        }
        //        else if (vmcallinfo.breakpoint_detected == lpContext->Dr2)
        //        {
        //            lpContext->Dr6 = 1 << 2;
        //        }
        //        else if (vmcallinfo.breakpoint_detected == lpContext->Dr3)
        //        {
        //            lpContext->Dr6 = 1 << 3;
        //        }
        //        logger.Log("lpContext->Dr6: %p", lpContext->Dr6);
        //    }
        //}
    }
    return boSuccess;
}


bool __stdcall GetPhysicalAddress(HANDLE hProcess, PVOID lpBaseAddress, ULONG64 Address)
{
    return 0;
}