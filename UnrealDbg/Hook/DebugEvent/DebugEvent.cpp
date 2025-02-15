#include "../dllmain.h"
#include "../HookCallSet/functionSet.h"
#include "../Globals.h"
#include "../Log/Log.h"
#include "DebugEvent.h"

#ifdef _WIN64

BOOL
WINAPI
NewWaitForDebugEvent(
    __in LPDEBUG_EVENT lpDebugEvent,
    __in DWORD dwMilliseconds
)
{
    BOOL bRet = FALSE;
    BOOL bFlag;
    DWORD dwOldProtect;
    DWORD error = 0;
    BOOL boWow64Process = FALSE;

    if (lpDebugEvent)
    {
        bRet = Sys_WaitForDebugEvent(lpDebugEvent, dwMilliseconds);
        if (bRet)
        {
            //����Ǹ��ӵ��Ե����
            if (g_process_info.isCreate)
            {
                logger.Log("%s[%d] g_process_info.isCreate�� %d", __func__, __LINE__, g_process_info.isCreate);
                switch (lpDebugEvent->dwDebugEventCode)
                {
                case LOAD_DLL_DEBUG_EVENT:
                {
                    if (!g_SetDbgBreakPoint.boBaseThreadInitThunk)
                    {
                        assert(BaseThreadInitThunk);
                        if (BaseThreadInitThunk)
                        {
                            //����int3�ж�
                            UCHAR chBuffer[3] = { 0x90,0xCC,0xEB };
                            PVOID BreakPointAddr = (PVOID)((ULONG_PTR)BaseThreadInitThunk + 4);
                            bFlag = VirtualProtectEx(g_process_info.ProcessHandle, BreakPointAddr, sizeof(chBuffer), PAGE_EXECUTE_READWRITE, &dwOldProtect);
                            if (bFlag)
                            {
                                bFlag = WriteProcessMemory(g_process_info.ProcessHandle, BreakPointAddr, &chBuffer, sizeof(chBuffer), NULL);
                                if (!bFlag)
                                {
                                    error = GetLastError();
                                    outDebug((TCHAR*)_T("[LOAD_DLL_DEBUG_EVENT] ���öϵ�ʧ�ܣ�(error:%d)"), error);
                                }
                                else
                                {
                                    //outDebug((TCHAR*)_T("����int3�жϳɹ���"));
                                    g_SetDbgBreakPoint.boBaseThreadInitThunk = TRUE;
                                }
                                VirtualProtectEx(g_process_info.ProcessHandle, BreakPointAddr, sizeof(chBuffer), dwOldProtect, &dwOldProtect);
                            }
                            else
                            {
                                error = GetLastError();
                                outDebug((TCHAR*)_T("[LOAD_DLL_DEBUG_EVENT] �޸��ڴ�����ʧ�ܣ�(error:%d)"), error);
                            }
                        }
                        else
                        {
                            error = GetLastError();
                            outDebug((TCHAR*)_T("[LOAD_DLL_DEBUG_EVENT] BaseThreadInitThunk��ָ�룡(error:%d)"), error);
                        }
                    }
                    break;
                }
                case EXCEPTION_DEBUG_EVENT:
                {
                    if ((lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)((ULONG_PTR)BaseThreadInitThunk + 5)) &&
                        (lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT))
                    {
                        g_first_breakpoint = TRUE;
                    }
                    break;
                }
                }
            }
            else
            {
                //�����ӵ����
                if (lpDebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                {
                    if ((lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) ||
                        (lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_SINGLE_STEP))
                    {
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, lpDebugEvent->dwThreadId);
                        if (hThread)
                        {
                            //����ԭ����
                            CONTEXT Context = { 0 };
                            Context.ContextFlags = CONTEXT_ALL | CONTEXT_EXTENDED_REGISTERS;
                            BOOL boSuccess = Sys_GetThreadContext(hThread, &Context);
                            if (boSuccess)
                            {
                                Dr6 dr6;
                                dr6.flags = Context.Dr6;
                                if (dr6.BS)  //����ִ��
                                {
                                    InterlockedExchange(&g_debug_condition_detected, 2);
                                }
                                else
                                {
                                    InterlockedExchange(&g_debug_condition_detected, 1);
                                }
                            }
                            else
                            {
                                logger.Log("��ȡContextʧ��! (error: %d)", GetLastError());
                            }
                            CloseHandle(hThread);                            
                        }
                    }
                }
            }
        }
    }
    else
    {
        outDebug((TCHAR*)_T("WaitForDebugEvent������Ч��"));
    }
    return bRet;
}

BOOL
WINAPI
NewContinueDebugEvent(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwThreadId,
    _In_ DWORD dwContinueStatus
)
{
    BOOL bFlag;
    DWORD dwOldProtect;
    DWORD error = 0;

    //����Ǹ��ӵ��Ե����
    if (g_process_info.isCreate)
    {
        logger.Log("%s[%d] g_process_info.isCreate�� %d", __func__, __LINE__, g_process_info.isCreate);
        if (dwContinueStatus == DBG_CONTINUE)
        {
            if (g_first_breakpoint)
            {
                g_first_breakpoint = FALSE;
                assert(BaseThreadInitThunk);
                if (BaseThreadInitThunk)
                {
                    UCHAR chOldBytes[3] = { 0 };
                    PVOID BreakPointAddr = (PVOID)((ULONG_PTR)BaseThreadInitThunk + 4);
                    bFlag = VirtualProtectEx(g_process_info.ProcessHandle, BreakPointAddr, sizeof(chOldBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    if (bFlag)
                    {
                        bFlag = ReadProcessMemory(g_process_info.ProcessHandle, BreakPointAddr, &chOldBytes, sizeof(chOldBytes), NULL);
                        if (bFlag)
                        {
                            if (chOldBytes[1] == 0xCC)
                            {
                                UCHAR chBuffer[3] = { 0x85,0xC9,0x75 };
                                bFlag = WriteProcessMemory(g_process_info.ProcessHandle, BreakPointAddr, &chBuffer, sizeof(chBuffer), NULL);
                                if (!bFlag)
                                {
                                    error = GetLastError();
                                    outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] �Ƴ��ϵ�ʧ�ܣ�(error:%d)"), error);
                                }
                            }
                            VirtualProtectEx(g_process_info.ProcessHandle, BreakPointAddr, sizeof(chOldBytes), dwOldProtect, &dwOldProtect);
                        }
                        else
                        {
                            error = GetLastError();
                            outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] ����ڴ�ʱʧ�ܣ�(error:%d)"), error);
                        }
                    }
                    else
                    {
                        error = GetLastError();
                        outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] �޸��ڴ�����ʧ�ܣ�(error:%d)"), error);
                    }
                }
                else
                {
                    error = GetLastError();
                    outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] BaseThreadInitThunk��ָ�룡(error:%d)"), error);
                }
            }
        }
    }
    return Sys_ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus);
}

#else

BOOL
WINAPI
NewWaitForDebugEvent(
    __in LPDEBUG_EVENT lpDebugEvent,
    __in DWORD dwMilliseconds
)
{
    BOOL bRet = FALSE;
    BOOL bFlag;
    DWORD dwOldProtect;
    DWORD error = 0;

    if (lpDebugEvent)
    {
        bRet = Sys_WaitForDebugEvent(lpDebugEvent, dwMilliseconds);
        if (bRet)
        {
            //����Ǹ��ӵ��Ե����
            if (g_process_info.isCreate)
            {
                //Debug event
                switch (lpDebugEvent->dwDebugEventCode)
                {
                case LOAD_DLL_DEBUG_EVENT:
                {
                    if (!g_SetDbgBreakPoint.boBaseThreadInitThunk)
                    {
                        assert(BaseThreadInitThunk);
                        if (BaseThreadInitThunk)
                        {
                            //����int3�ж�
                            UCHAR chBuffer[2] = { 0x90,0xCC };
                            bFlag = VirtualProtectEx(g_process_info.ProcessHandle, BaseThreadInitThunk, sizeof(chBuffer), PAGE_EXECUTE_READWRITE, &dwOldProtect);
                            if (bFlag)
                            {
                                bFlag = WriteProcessMemory(g_process_info.ProcessHandle, BaseThreadInitThunk, &chBuffer, sizeof(chBuffer), NULL);
                                if (!bFlag)
                                {
                                    error = GetLastError();
                                    outDebug((TCHAR*)_T("[LOAD_DLL_DEBUG_EVENT] ���öϵ�ʧ�ܣ�(error:%d)"), error);
                                }
                                else
                                {
                                    //outDebug((TCHAR*)_T("����int3�жϳɹ���"));
                                    g_SetDbgBreakPoint.boBaseThreadInitThunk = TRUE;
                                }
                                VirtualProtectEx(g_process_info.ProcessHandle, BaseThreadInitThunk, sizeof(chBuffer), dwOldProtect, &dwOldProtect);
                            }
                            else
                            {
                                error = GetLastError();
                                outDebug((TCHAR*)_T("[LOAD_DLL_DEBUG_EVENT] �޸��ڴ�����ʧ�ܣ�(error:%d)"), error);
                            }
                        }
                        else
                        {
                            error = GetLastError();
                            outDebug((TCHAR*)_T("[LOAD_DLL_DEBUG_EVENT] BaseThreadInitThunk��ָ�룡(error:%d)"), error);
                        }
                    }
                    break;
                }
                case EXCEPTION_DEBUG_EVENT:
                {
                    if ((lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)((ULONG_PTR)BaseThreadInitThunk + 1)) &&
                        (lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT))
                    {
                        g_first_breakpoint = TRUE;
                    }
                    break;
                }
                }
            }
            else
            {
                //�����ӵ����
                if (lpDebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                {
                    if (lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
                    {
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, lpDebugEvent->dwThreadId);
                        if (hThread)
                        {
                            //����ԭ����
                            CONTEXT Context = { 0 };
                            Context.ContextFlags = CONTEXT_ALL | CONTEXT_EXTENDED_REGISTERS;
                            BOOL boSuccess = Sys_GetThreadContext(hThread, &Context);
                            if (boSuccess)
                            {
                                Dr6 dr6;
                                dr6.flags = Context.Dr6;
                                if (dr6.BS)  //����ִ��
                                {
                                    InterlockedExchange(&g_debug_condition_detected, 2);
                                }
                                else
                                {
                                    InterlockedExchange(&g_debug_condition_detected, 1);
                                }
                            }
                            CloseHandle(hThread);
                        }
                    }
                }
            }
        }
    }
    else
    {
        outDebug((TCHAR*)_T("WaitForDebugEvent������Ч��"));
    }
    return bRet;
}

BOOL
WINAPI
NewContinueDebugEvent(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwThreadId,
    _In_ DWORD dwContinueStatus
)
{
    BOOL bFlag;
    DWORD dwOldProtect;
    DWORD error = 0;

    //����Ǹ��ӵ��Ե����
    if (g_process_info.isCreate)
    {
        if (dwContinueStatus == DBG_CONTINUE)
        {
            if (g_first_breakpoint)
            {
                g_first_breakpoint = FALSE;
                assert(BaseThreadInitThunk);
                if (BaseThreadInitThunk)
                {
                    UCHAR chOldBytes[2] = { 0,0 };
                    bFlag = VirtualProtectEx(g_process_info.ProcessHandle, BaseThreadInitThunk, sizeof(chOldBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    if (bFlag)
                    {
                        bFlag = ReadProcessMemory(g_process_info.ProcessHandle, BaseThreadInitThunk, &chOldBytes, sizeof(chOldBytes), NULL);
                        if (bFlag)
                        {
                            if (chOldBytes[1] == 0xCC)
                            {
                                UCHAR chBuffer[2] = { 0x8B,0xFF };
                                bFlag = WriteProcessMemory(g_process_info.ProcessHandle, BaseThreadInitThunk, &chBuffer, sizeof(chBuffer), NULL);
                                if (!bFlag)
                                {
                                    error = GetLastError();
                                    outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] �Ƴ��ϵ�ʧ�ܣ�(error:%d)"), error);
                                }
                            }
                            VirtualProtectEx(g_process_info.ProcessHandle, BaseThreadInitThunk, sizeof(chOldBytes), dwOldProtect, &dwOldProtect);
                        }
                        else
                        {
                            error = GetLastError();
                            outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] ����ڴ�ʱʧ�ܣ�(error:%d)"), error);
                        }
                    }
                    else
                    {
                        error = GetLastError();
                        outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] �޸��ڴ�����ʧ�ܣ�(error:%d)"), error);
                    }
                }
                else
                {
                    error = GetLastError();
                    outDebug((TCHAR*)_T("[EXCEPTION_DEBUG_EVENT] BaseThreadInitThunk��ָ�룡(error:%d)"), error);
                }
            }
        }
    }
    return Sys_ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus);
}

#endif // _WIN64