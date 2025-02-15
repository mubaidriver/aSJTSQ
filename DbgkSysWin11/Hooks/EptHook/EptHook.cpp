#include "../../Driver.h"
#include "../../ntos/inc/extypes.h"
#include "../../ntos/inc/ketypes.h"
#include "../../ntos/inc/ntosdef.h"
#include "../../ntos/inc/amd64.h"
#include "../../ntos/inc/mi.h"
#include "../../ntos/inc/pstypes.h"
#include "../../ntos/inc/obtypes.h"
#include "../../ntos/inc/mmtypes.h"
#include "../../ntos/inc/ntdbg.h"
#include "../../ntos/inc/peb_teb.h"
#include "../../List/MyList.h"
#include "../../ntos/inc/ntlpcapi.h"
#include "../../Log/log.h"
#include "../../ntos/inc/ki.h"
#include "../../ntos/inc/psp.h"
#include "../../Globals.h"
#include "../../DbgkApi/DbgkApi.h"
#include "../../Protect/Windows/BypassFindWnd.h"
#include "../../Protect/Thread/ProtectDrx.h"
#include "../../Protect/Process/ProtectProcess.h"
#include "../../Memory/ReadWrite.h"
#include "../../ntos/inc/ntexapi.h"
#include "../../Hvm/hypervisor_gateway.h"
#include "../../Init/Symbolic/InitWin32kbase.h"
#include "../../Init/Symbolic/InitWin32kfull.h"
#include "../../Process/process.h"
#include "EptHook.h"

EXTERN_C
VOID UnEptHook()
{
    //ж������ept����
    if (hvgt::ept_unhook())
    {
        outLog("ж������ept����.");
    }
    else
    {
        outLog("ж��ept����ʧ��.");
    }
}

EXTERN_C
VOID SetupEptHook()
{
    if (g_IsInitGlobalVariable)
    {
        //ntos
        Hook_NtCreateDebugObject();    //�˺����Ǵ������Զ��� �����һ����hook
        Hook_PspInsertProcess();        
        Hook_NtSetInformationDebugObject();
        Hook_NtRemoveProcessDebug();
        Hook_NtDebugActiveProcess();
        Hook_NtWaitForDebugEvent();
        Hook_NtDebugContinue();
        Hook_DbgkMapViewOfSection();
        Hook_DbgkUnMapViewOfSection();
        Hook_DbgkCreateThread();
        Hook_DbgkExitThread();
        Hook_DbgkExitProcess();
        Hook_DbgkForwardException();
        Hook_DbgkpQueueMessage();
        
        Hook_PspCallThreadNotifyRoutines();
        Hook_PspExitThread();
        Hook_ObpReferenceObjectByHandleWithTag();


        //win32k.sys
        Hook_ValidateHwnd();  //win32k�д˺���������hook
        Hook_NtUserFindWindowEx();        
        Hook_NtUserWindowFromPoint();
    }
}


EXTERN_C
VOID Hook_DbgkOpenProcessDebugPort()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkOpenProcessDebugPort);
        if (Sys_DbgkOpenProcessDebugPort)
        {
            if (hvgt::hook_function(Sys_DbgkOpenProcessDebugPort, DbgkOpenProcessDebugPort, NULL))
            {
                outLog("hook DbgkOpenProcessDebugPort�ɹ�.");
            }
            else
            {
                outLog("hook DbgkOpenProcessDebugPortʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkOpenProcessDebugPortΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtCreateDebugObject()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtCreateDebugObject);
        if (Sys_NtCreateDebugObject)
        {
            if (hvgt::hook_function(Sys_NtCreateDebugObject, NtCreateDebugObject, NULL))
            {
                outLog("hook NtCreateDebugObject�ɹ�.");
            }
            else
            {
                outLog("hook NtCreateDebugObjectʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtCreateDebugObjectΪ��ָ��.");
        }
    }
    else
    {
        outLog("Hook_NtCreateDebugObject ʧ��");
    }
}

EXTERN_C
VOID Hook_NtSetInformationDebugObject()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtSetInformationDebugObject);
        if (Sys_NtSetInformationDebugObject)
        {
            if (hvgt::hook_function(Sys_NtSetInformationDebugObject, NtSetInformationDebugObject, NULL))
            {
                outLog("hook NtSetInformationDebugObject�ɹ�.");
            }
            else
            {
                outLog("hook NtSetInformationDebugObjectʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtSetInformationDebugObjectΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtRemoveProcessDebug()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtRemoveProcessDebug);
        if (Sys_NtRemoveProcessDebug)
        {
            if (hvgt::hook_function(Sys_NtRemoveProcessDebug, NtRemoveProcessDebug, NULL))
            {
                outLog("hook NtRemoveProcessDebug�ɹ�.");
            }
            else
            {
                outLog("hook NtRemoveProcessDebugʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtRemoveProcessDebugΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtDebugActiveProcess()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtDebugActiveProcess);
        if (Sys_NtDebugActiveProcess)
        {
            if (hvgt::hook_function(Sys_NtDebugActiveProcess, NtDebugActiveProcess, NULL))
            {
                outLog("hook NtDebugActiveProcess�ɹ�.");
            }
            else
            {
                outLog("hook NtDebugActiveProcessʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtDebugActiveProcessΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtWaitForDebugEvent()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtWaitForDebugEvent);
        if (Sys_NtWaitForDebugEvent)
        {
            if (hvgt::hook_function(Sys_NtWaitForDebugEvent, NtWaitForDebugEvent, NULL))
            {
                outLog("hook NtWaitForDebugEvent�ɹ�.");
            }
            else
            {
                outLog("hook NtWaitForDebugEventʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtWaitForDebugEventΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_KiDispatchException()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_KiDispatchException);
        if (Sys_KiDispatchException)
        {
            if (hvgt::hook_function(Sys_KiDispatchException, KiDispatchException, (PVOID*)&Original_KiDispatchException))
            {
                outLog("hook KiDispatchException�ɹ�.");
            }
            else
            {
                outLog("hook KiDispatchExceptionʧ��.");
            }
        }
        else
        {
            outLog("Sys_KiDispatchExceptionΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_PspInsertProcess()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_PspInsertProcess);
        if (Sys_PspInsertProcess)
        {
            if (hvgt::hook_function(Sys_PspInsertProcess, PspInsertProcess, NULL))
            {
                outLog("hook PspInsertProcess�ɹ�.");
            }
            else
            {
                outLog("hook PspInsertProcessʧ��.");
            }
        }
        else
        {
            outLog("Sys_PspInsertProcessΪ��ָ��.");
        }
    }
}

//EXTERN_C
//VOID Hook_PspInsertThread()
//{
//    if (g_IsInitGlobalVariable)
//    {
//        ASSERT(Sys_PspInsertThread);
//        if (Sys_PspInsertThread)
//        {
//            if (hvgt::hook_function(Sys_PspInsertThread, PspInsertThread, NULL))
//            {
//                outLog("hook PspInsertThread�ɹ�.");
//            }
//            else
//            {
//                outLog("hook PspInsertThreadʧ��.");
//            }
//        }
//        else
//        {
//            outLog("Sys_PspInsertThreadΪ��ָ��.");
//        }
//    }
//}

EXTERN_C
VOID Hook_NtDebugContinue()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtDebugContinue);
        if (Sys_NtDebugContinue)
        {
            if (hvgt::hook_function(Sys_NtDebugContinue, NtDebugContinue, NULL))
            {
                outLog("hook NtDebugContinue�ɹ�.");
            }
            else
            {
                outLog("hook NtDebugContinueʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtDebugContinueΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_DbgkMapViewOfSection()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkMapViewOfSection);
        if (Sys_DbgkMapViewOfSection)
        {
            if (hvgt::hook_function(Sys_DbgkMapViewOfSection, DbgkMapViewOfSection, NULL))
            {
                outLog("hook DbgkMapViewOfSection�ɹ�.");
            }
            else
            {
                outLog("hook DbgkMapViewOfSectionʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkMapViewOfSectionΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_DbgkUnMapViewOfSection()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkUnMapViewOfSection);
        if (Sys_DbgkUnMapViewOfSection)
        {
            if (hvgt::hook_function(Sys_DbgkUnMapViewOfSection, DbgkUnMapViewOfSection, NULL))
            {
                outLog("hook DbgkUnMapViewOfSection�ɹ�.");
            }
            else
            {
                outLog("hook DbgkUnMapViewOfSectionʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkUnMapViewOfSectionΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtQueryInformationThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtQueryInformationThread);
        if (Sys_NtQueryInformationThread)
        {
            if (hvgt::hook_function(Sys_NtQueryInformationThread, NewNtQueryInformationThread, (PVOID*)&Original_NtQueryInformationThread))
            {
                outLog("hook NtQueryInformationThread�ɹ�.");
            }
            else
            {
                outLog("hook NtQueryInformationThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtQueryInformationThreadΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtSuspendThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtSuspendThread);
        if (Sys_NtSuspendThread)
        {
            if (hvgt::hook_function(Sys_NtSuspendThread, NewNtSuspendThread, (PVOID*)&Original_NtSuspendThread))
            {
                outLog("hook NtSuspendThread�ɹ�.");
            }
            else
            {
                outLog("hook NtSuspendThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtSuspendThreadΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtResumeThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtResumeThread);
        if (Sys_NtResumeThread)
        {
            if (hvgt::hook_function(Sys_NtResumeThread, NewNtResumeThread, (PVOID*)&Original_NtResumeThread))
            {
                outLog("hook NtResumeThread�ɹ�.");
            }
            else
            {
                outLog("hook NtResumeThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtResumeThreadΪ��ָ��.");
        }
    }
}

//EXTERN_C
//VOID Hook_DbgkCreateThread()
//{
//    if (g_IsInitGlobalVariable)
//    {
//        ASSERT(Sys_DbgkCreateThread);
//        if (Sys_DbgkCreateThread)
//        {
//            if (hvgt::hook_function(Sys_DbgkCreateThread, DbgkCreateThread, (PVOID*)&Original_DbgkCreateThread))
//            {
//                outLog("hook DbgkCreateThread�ɹ�.");
//            }
//            else
//            {
//                outLog("hook DbgkCreateThreadʧ��.");
//            }
//        }
//        else
//        {
//            outLog("Sys_DbgkCreateThreadΪ��ָ��.");
//        }
//        SetupHook_DbgkCreateThread_CMP_Debugport();
//    }
//}


EXTERN_C
VOID Hook_DbgkCreateThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkCreateThread);
        if (Sys_DbgkCreateThread)
        {
            if (hvgt::hook_function(Sys_DbgkCreateThread, DbgkCreateThread, NULL))
            {
                outLog("hook DbgkCreateThread�ɹ�.");
            }
            else
            {
                outLog("hook DbgkCreateThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkCreateThreadΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_DbgkExitThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkExitThread);
        if (Sys_DbgkExitThread)
        {
            if (hvgt::hook_function(Sys_DbgkExitThread, DbgkExitThread, NULL))
            {
                outLog("hook DbgkExitThread�ɹ�.");
            }
            else
            {
                outLog("hook DbgkExitThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkExitThreadΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_DbgkExitProcess()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkExitProcess);
        if (Sys_DbgkExitProcess)
        {
            if (hvgt::hook_function(Sys_DbgkExitProcess, DbgkExitProcess, NULL))
            {
                outLog("hook DbgkExitProcess�ɹ�.");
            }
            else
            {
                outLog("hook DbgkExitProcessʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkExitProcessΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_DbgkForwardException()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkForwardException);
        if (Sys_DbgkForwardException)
        {
            if (hvgt::hook_function(Sys_DbgkForwardException, DbgkForwardException, NULL))
            {
                outLog("hook DbgkForwardException�ɹ�.");
            }
            else
            {
                outLog("hook DbgkForwardExceptionʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkForwardExceptionΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_DbgkpQueueMessage()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_DbgkpQueueMessage);
        if (Sys_DbgkpQueueMessage)
        {
            if (hvgt::hook_function(Sys_DbgkpQueueMessage, DbgkpQueueMessage, NULL))
            {
                outLog("hook DbgkpQueueMessage�ɹ�.");
            }
            else
            {
                outLog("hook DbgkpQueueMessageʧ��.");
            }
        }
        else
        {
            outLog("Sys_DbgkpQueueMessageΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_KeStackAttachProcess()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_KeStackAttachProcess);
        if (Sys_KeStackAttachProcess)
        {
            if (hvgt::hook_function(Sys_KeStackAttachProcess, NewKeStackAttachProcess, (PVOID*)&Original_KeStackAttachProcess))
            {
                outLog("hook KeStackAttachProcess�ɹ�.");
            }
            else
            {
                outLog("hook KeStackAttachProcessʧ��.");
            }
        }
        else
        {
            outLog("Sys_KeStackAttachProcessΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_KiStackAttachProcess()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_KiStackAttachProcess);
        if (Sys_KiStackAttachProcess)
        {
            if (hvgt::hook_function(Sys_KiStackAttachProcess, NewKiStackAttachProcess, (PVOID*)&Original_KiStackAttachProcess))
            {
                outLog("hook KiStackAttachProcess�ɹ�.");
            }
            else
            {
                outLog("hook KiStackAttachProcessʧ��.");
            }
        }
        else
        {
            outLog("Sys_KiStackAttachProcessΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtProtectVirtualMemory()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtProtectVirtualMemory);
        if (Sys_NtProtectVirtualMemory)
        {
            if (hvgt::hook_function(Sys_NtProtectVirtualMemory, NtProtectVirtualMemory, (PVOID*)&Original_NtProtectVirtualMemory))
            {
                outLog("hook NtProtectVirtualMemory�ɹ�.");
            }
            else
            {
                outLog("hook NtProtectVirtualMemoryʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtProtectVirtualMemoryΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_MiObtainReferencedVadEx()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_MiObtainReferencedVadEx);
        if (Sys_MiObtainReferencedVadEx)
        {
            if (hvgt::hook_function(Sys_MiObtainReferencedVadEx, MiObtainReferencedVadEx, (PVOID*)&Original_MiObtainReferencedVadEx))
            {
                outLog("hook MiObtainReferencedVadEx�ɹ�.");
            }
            else
            {
                outLog("hook MiObtainReferencedVadExʧ��.");
            }
        }
        else
        {
            outLog("Sys_MiObtainReferencedVadExΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_MmProtectVirtualMemory()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_MmProtectVirtualMemory);
        if (Sys_MmProtectVirtualMemory)
        {
            if (hvgt::hook_function(Sys_MmProtectVirtualMemory, MmProtectVirtualMemory, (PVOID*)&Original_MmProtectVirtualMemory))
            {
                outLog("hook MmProtectVirtualMemory�ɹ�.");
            }
            else
            {
                outLog("hook MmProtectVirtualMemoryʧ��.");
            }
        }
        else
        {
            outLog("Sys_MmProtectVirtualMemoryΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtGetContextThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtGetContextThread);
        if (Sys_NtGetContextThread)
        {
            if (hvgt::hook_function(Sys_NtGetContextThread, NtGetContextThread, (PVOID*)&Original_NtGetContextThread))
            {
                outLog("hook NtGetContextThread�ɹ�.");
            }
            else
            {
                outLog("hook NtGetContextThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtGetContextThreadΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtSetContextThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtSetContextThread);
        if (Sys_NtSetContextThread)
        {
            if (hvgt::hook_function(Sys_NtSetContextThread, NtSetContextThread, (PVOID*)&Original_NtSetContextThread))
            {
                outLog("hook NtSetContextThread�ɹ�.");
            }
            else
            {
                outLog("hook NtSetContextThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtSetContextThreadΪ��ָ��.");
        }
    }
}

//EXTERN_C
//VOID Hook_NtShutdownSystem()
//{
//    if (g_IsInitGlobalVariable)
//    {
//        ASSERT(Sys_NtShutdownSystem);
//        if (Sys_NtShutdownSystem)
//        {
//            if (hvgt::hook_function(Sys_NtShutdownSystem, NtShutdownSystem, NULL))
//            {
//                outLog("hook NtShutdownSystem�ɹ�.");
//            }
//            else
//            {
//                outLog("hook NtShutdownSystemʧ��.");
//            }
//        }
//        else
//        {
//            outLog("Sys_NtShutdownSystemΪ��ָ��.");
//        }
//    }
//}

EXTERN_C
VOID Hook_NtOpenProcess()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtOpenProcess);
        if (Sys_NtOpenProcess)
        {
            if (hvgt::hook_function(Sys_NtOpenProcess, NewNtOpenProcess, (PVOID*)&Original_NtOpenProcess))
            {
                outLog("hook NtOpenProcess�ɹ�.");
            }
            else
            {
                outLog("hook NtOpenProcessʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtOpenProcessΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtReadVirtualMemory()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtReadVirtualMemory);
        if (Sys_NtReadVirtualMemory)
        {
            if (hvgt::hook_function(Sys_NtReadVirtualMemory, NtReadVirtualMemory, (PVOID*)&Original_NtReadVirtualMemory))
            {
                outLog("hook NtReadVirtualMemory�ɹ�.");
            }
            else
            {
                outLog("hook NtReadVirtualMemoryʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtReadVirtualMemoryΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtWriteVirtualMemory()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtWriteVirtualMemory);
        if (Sys_NtWriteVirtualMemory)
        {
            if (hvgt::hook_function(Sys_NtWriteVirtualMemory, NtWriteVirtualMemory, (PVOID*)&Original_NtWriteVirtualMemory))
            {
                outLog("hook NtWriteVirtualMemory�ɹ�.");
            }
            else
            {
                outLog("hook NtWriteVirtualMemoryʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtWriteVirtualMemoryΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_ObReferenceObjectByHandle()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_ObReferenceObjectByHandle);
        if (Sys_ObReferenceObjectByHandle)
        {
            if (hvgt::hook_function(Sys_ObReferenceObjectByHandle, NewObReferenceObjectByHandle, (PVOID*)&Original_ObReferenceObjectByHandle))
            {
                outLog("hook ObReferenceObjectByHandle�ɹ�.");
            }
            else
            {
                outLog("hook ObReferenceObjectByHandleʧ��.");
            }
        }
        else
        {
            outLog("Sys_ObReferenceObjectByHandleΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_ObReferenceObjectByHandleWithTag()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_ObReferenceObjectByHandleWithTag);
        if (Sys_ObReferenceObjectByHandleWithTag)
        {
            if (hvgt::hook_function(Sys_ObReferenceObjectByHandleWithTag, NewObReferenceObjectByHandleWithTag, (PVOID*)&Original_ObReferenceObjectByHandleWithTag))
            {
                outLog("hook ObReferenceObjectByHandleWithTag�ɹ�.");
            }
            else
            {
                outLog("hook ObReferenceObjectByHandleWithTagʧ��.");
            }
        }
        else
        {
            outLog("Sys_ObReferenceObjectByHandleWithTagΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_ObpReferenceObjectByHandleWithTag()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_ObpReferenceObjectByHandleWithTag);
        if (Sys_ObpReferenceObjectByHandleWithTag)
        {
            if (hvgt::hook_function(Sys_ObpReferenceObjectByHandleWithTag, NewObpReferenceObjectByHandleWithTag, (PVOID*)&Original_ObpReferenceObjectByHandleWithTag))
            {
                outLog("hook ObpReferenceObjectByHandleWithTag�ɹ�.");
            }
            else
            {
                outLog("hook ObpReferenceObjectByHandleWithTagʧ��.");
            }
        }
        else
        {
            outLog("Sys_ObpReferenceObjectByHandleWithTagΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_ObfDereferenceObjectWithTag()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_ObfDereferenceObjectWithTag);
        if (Sys_ObfDereferenceObjectWithTag)
        {
            if (hvgt::hook_function(Sys_ObfDereferenceObjectWithTag, NewObfDereferenceObjectWithTag, (PVOID*)&Original_ObfDereferenceObjectWithTag))
            {
                outLog("hook ObfDereferenceObjectWithTag�ɹ�.");
            }
            else
            {
                outLog("hook ObfDereferenceObjectWithTagʧ��.");
            }
        }
        else
        {
            outLog("Sys_ObfDereferenceObjectWithTagΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_ObfDereferenceObject()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_ObfDereferenceObject);
        if (Sys_ObfDereferenceObject)
        {
            if (hvgt::hook_function(Sys_ObfDereferenceObject, NewObfDereferenceObject, (PVOID*)&Original_ObfDereferenceObject))
            {
                outLog("hook ObfDereferenceObject�ɹ�.");
            }
            else
            {
                outLog("hook ObfDereferenceObjectʧ��.");
            }
        }
        else
        {
            outLog("Sys_ObfDereferenceObjectΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_MmCopyVirtualMemory()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_MmCopyVirtualMemory);
        if (Sys_MmCopyVirtualMemory)
        {
            if (hvgt::hook_function(Sys_MmCopyVirtualMemory, NewMmCopyVirtualMemory, (PVOID*)&Original_MmCopyVirtualMemory))
            {
                outLog("hook MmCopyVirtualMemory�ɹ�.");
            }
            else
            {
                outLog("hook MmCopyVirtualMemoryʧ��.");
            }
        }
        else
        {
            outLog("Sys_MmCopyVirtualMemoryΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_PspCreateUserContext()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_PspCreateUserContext);
        if (Sys_PspCreateUserContext)
        {
            if (hvgt::hook_function(Sys_PspCreateUserContext, NewPspCreateUserContext, (PVOID*)&Original_PspCreateUserContext))
            {
                outLog("hook PspCreateUserContext�ɹ�.");
            }
            else
            {
                outLog("hook PspCreateUserContextʧ��.");
            }
        }
        else
        {
            outLog("Sys_PspCreateUserContextΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_PspCallThreadNotifyRoutines()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_PspCallThreadNotifyRoutines);
        if (Sys_PspCallThreadNotifyRoutines)
        {
            if (hvgt::hook_function(Sys_PspCallThreadNotifyRoutines, NewPspCallThreadNotifyRoutines, (PVOID*)&Original_PspCallThreadNotifyRoutines))
            {
                outLog("hook PspCallThreadNotifyRoutines�ɹ�.");
            }
            else
            {
                outLog("hook PspCallThreadNotifyRoutinesʧ��.");
            }
        }
        else
        {
            outLog("Sys_PspCallThreadNotifyRoutinesΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtTerminateProcess()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtTerminateProcess);
        if (Sys_NtTerminateProcess)
        {
            if (hvgt::hook_function(Sys_NtTerminateProcess, NewNtTerminateProcess, (PVOID*)&Original_NtTerminateProcess))
            {
                outLog("hook NtTerminateProcess�ɹ�.");
            }
            else
            {
                outLog("hook NtTerminateProcessʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtTerminateProcessΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_PspExitThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_PspExitThread);
        if (Sys_PspExitThread)
        {
            if (hvgt::hook_function(Sys_PspExitThread, PspExitThread, (PVOID*)&Original_PspExitThread))
            {
                outLog("hook PspExitThread�ɹ�.");
            }
            else
            {
                outLog("hook PspExitThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_PspExitThreadΪ��ָ��.");
        }
        SetupHook_PspExitThread_CMP_Debugport();
    }
}

EXTERN_C
VOID Hook_PspCreateThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_PspCreateThread);
        if (Sys_PspCreateThread)
        {
            if (hvgt::hook_function(Sys_PspCreateThread, PspCreateThread, (PVOID*)&Original_PspCreateThread))
            {
                outLog("hook PspCreateThread�ɹ�.");
            }
            else
            {
                outLog("hook PspCreateThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_PspCreateThreadΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtCreateThreadEx()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtCreateThreadEx);
        if (Sys_NtCreateThreadEx)
        {
            if (hvgt::hook_function(Sys_NtCreateThreadEx, NtCreateThreadEx, (PVOID*)&Original_NtCreateThreadEx))
            {
                outLog("hook NtCreateThreadEx�ɹ�.");
            }
            else
            {
                outLog("hook NtCreateThreadExʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtCreateThreadExΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_PspAllocateThread()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_PspAllocateThread);
        if (Sys_PspAllocateThread)
        {
            if (hvgt::hook_function(Sys_PspAllocateThread, NewPspAllocateThread, (PVOID*)&Original_PspAllocateThread))
            {
                outLog("hook PspAllocateThread�ɹ�.");
            }
            else
            {
                outLog("hook PspAllocateThreadʧ��.");
            }
        }
        else
        {
            outLog("Sys_PspAllocateThreadΪ��ָ��.");
        }
    }
}

//EXTERN_C
//VOID Hook_DbgkpCloseObject()
//{
//    if (g_IsInitGlobalVariable)
//    {
//        ASSERT(Sys_DbgkpCloseObject);
//        if (Sys_DbgkpCloseObject)
//        {
//            if (hvgt::hook_function(Sys_DbgkpCloseObject, DbgkpCloseObject, NULL))
//            {
//                outLog("hook DbgkpCloseObject�ɹ�.");
//            }
//            else
//            {
//                outLog("hook DbgkpCloseObjectʧ��.");
//            }
//        }
//        else
//        {
//            outLog("Sys_DbgkpCloseObjectΪ��ָ��.");
//        }
//    }
//}
//


//win32k.sys
EXTERN_C
VOID Hook_NtUserFindWindowEx()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtUserFindWindowEx);
        if (Sys_NtUserFindWindowEx)
        {
            if (hvgt::hook_function(Sys_NtUserFindWindowEx, NewNtUserFindWindowEx, (PVOID*)&Original_NtUserFindWindowEx))
            {
                outLog("hook NtUserFindWindowEx�ɹ�.");
            }
            else
            {
                outLog("hook NtUserFindWindowExʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtUserFindWindowExΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_ValidateHwnd()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_ValidateHwnd);
        if (Sys_ValidateHwnd)
        {
            if (hvgt::hook_function(Sys_ValidateHwnd, NewValidateHwnd, (PVOID*)&Original_ValidateHwnd))
            {
                outLog("hook ValidateHwnd�ɹ�.");
            }
            else
            {
                outLog("hook ValidateHwndʧ��.");
            }
        }
        else
        {
            outLog("Sys_ValidateHwndΪ��ָ��.");
        }
    }
}

EXTERN_C
VOID Hook_NtUserWindowFromPoint()
{
    if (g_IsInitGlobalVariable)
    {
        ASSERT(Sys_NtUserWindowFromPoint);
        if (Sys_NtUserWindowFromPoint)
        {
            if (hvgt::hook_function(Sys_NtUserWindowFromPoint, NewNtUserWindowFromPoint, (PVOID*)&Original_NtUserWindowFromPoint))
            {
                outLog("hook NtUserWindowFromPoint�ɹ�.");
            }
            else
            {
                outLog("hook NtUserWindowFromPointʧ��.");
            }
        }
        else
        {
            outLog("Sys_NtUserWindowFromPointΪ��ָ��.");
        }
    }
}