#include "Driver.h"
#include "ntos/inc/ntosdef.h"
#include "ntos/inc/ketypes.h"
#include "ntos/inc/amd64.h"
#include "ntos/inc/mmtypes.h"
#include "ntos/inc/ntdbg.h"
#include "ntos/inc/extypes.h"
#include "ntos/inc/mi.h"
#include "ntos/inc/pstypes.h"
#include "ntos/inc/obtypes.h"
#include "ntos/inc/peb_teb.h"
#include "List/MyList.h"
#include "ntos/inc/ntlpcapi.h"
#include "ntos/inc/pecoff.h"
#include "Log/log.h"
#include "Hooks/EptHook/EptHook.h"
#include "Init/Symbolic/InitSymbolic.h"
#include "ntos/inc/ki.h"
#include "ntos/inc/psp.h"
#include "Globals.h"
#include "DbgkApi/DbgkApi.h"
#include "Protect/Callbacks.h"
#include "Encrypt/Blowfish/Blowfish.h"
#include "ntos/inc/ke.h"
#include "ntos/inc/ntexapi.h"
#include "Hvm/AsmCallset.h"
#include "Asm/AsmVar.h"
#include "Hvm/hypervisor_gateway.h"
#include "DebugBreak/DebugBreak.h"

PWCHAR PassProcessList[12] = {
    _T("system"),
    _T("Registry"),
    _T("csrss.exe"),
    _T("svchost.exe"),
    _T("services.exe"),
    _T("lsass.exe"),    
    _T("explorer.exe"),
    _T("dwm.exe"),
    _T("dllhost.exe"),
    _T("smss.exe"),
    _T("WmiPrvSE.exe"),
    _T("ctfmon.exe"),
};

EXTERN_C
VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    //UnloadProtect();
    RemoveHooks();
    //DbgkUnInitialize();
    //ReleaseMemoryResources();
    //_RemoveDevice(DriverObject);
    DbgPrint("Driver Unload!!!\n");
}

EXTERN_C
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    LogFile::InitDriverLog();    

    //DbgBreakPoint();
    //ApcCreateRemoteThread((HANDLE)7572, NULL);
    DbgPrint("Ѫ������������ɹ�!!!\n");

    InitGlobalVariable(DriverObject);
    //InitProtect(DriverObject);
    NTSTATUS ntStatus = CreateDevice(DriverObject);
    if (!NT_SUCCESS(ntStatus))
    {
        outLog("�����豸����ʧ��.");
    }
    else
    {
        outLog("�����豸����ɹ�.");
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = InitDispatchRoutin;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = InitDispatchRoutin;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandlerDispatchRoutin;
    /* Initialize the User-Mode Debugging Subsystem */
    //DbgBreakPoint();    
    //TestVMM();
    DriverObject->DriverUnload = Unload;
    return STATUS_SUCCESS;
}

EXTERN_C
PVOID DbgkCreateThread_CMP_Debugport_01()
{
    PDEBUG_OBJECT Port;
    PDEBUG_PROCESS DebugProcess;
    _EPROCESS* Process = (_EPROCESS*)PsGetCurrentProcess();

    DbgBreakPoint();
    if (IsDebugTargetProcess(Process, &DebugProcess))
    {        
        //DbgBreakPoint();
        Port = DebugProcess->DebugObject;
    }
    else
    {
        size_t ptr_DebugPort = (size_t)Process + eprocess_offset::DebugPort;
        Port = *(PDEBUG_OBJECT*)ptr_DebugPort;
    }
    return Port;
}

VOID SetupHook_DbgkCreateThread_CMP_Debugport()
{
    BYTE code[] = { 0x48, 0x83,'?','?','?','?' };  //cmpָ��


    BYTE* startaddr = (BYTE*)Sys_DbgkCreateThread;
    for (;;)
    {
        BYTE* hookAddr = (BYTE*)SearchCode(code, sizeof(code), startaddr, 0x100);

        //�ж�ָ���Ƿ���cmp
        if ((hookAddr[0] == 0x48) &&
            (hookAddr[1] == 0x83) &&
            (*(WORD*)&hookAddr[3] == eprocess_offset::DebugPort))
        {
            //�õ�cmp����һ��ָ��
            DbgkCreateThread_jcc_instruction = (unsigned __int64)((unsigned __int64)hookAddr + (unsigned __int64)(LDE((unsigned __int8*)hookAddr, 64)));
            if (hvgt::hook_function(hookAddr, Asm_DbgkCreateThread_CMP_Debugport_01, NULL))
            {
                outLog("hook DbgkCreateThread_CMP_Debugport_01�ɹ�.");
            }
            else
            {
                outLog("hook DbgkCreateThread_CMP_Debugport_01ʧ��.");
            }
            break;
        }
        else
        {
            //outLog("û��ƥ�䵽 cmp qword ptr [rdi+578h]");
            startaddr = (BYTE*)((unsigned __int64)hookAddr + (unsigned __int64)(LDE((unsigned __int8*)hookAddr, 64)));
        }
    }
}

VOID SetupHook_PspExitThread_CMP_Debugport()
{
    BYTE code[] = { 0x49, 0x39,'?','?','?','?' };  //cmpָ��
    BYTE* hookAddr = (BYTE*)SearchCode(code, sizeof(code), (BYTE*)Sys_PspExitThread, 0x200);

    //�ж�ָ���Ƿ���cmp
    if ((hookAddr[0] == 0x49) &&
        (hookAddr[1] == 0x39) &&
        (*(WORD*)&hookAddr[3] == eprocess_offset::DebugPort))  /*if ( Process->DebugPort )*/
    {
        //�õ�cmp����һ��ָ��
        PspExitThread_jcc_instruction = (unsigned __int64)((unsigned __int64)hookAddr + (unsigned __int64)(LDE((unsigned __int8*)hookAddr, 64)));
        if (hvgt::hook_function(hookAddr, Asm_PspExitThread_CMP_Debugport_01, NULL))
        {
            outLog("hook PspExitThread_CMP_Debugport_01�ɹ�.");
        }
        else
        {
            outLog("hook PspExitThread_CMP_Debugport_01ʧ��.");
        }
    }
    else
    {
        outLog("û��ƥ�䵽 cmp [r14+578h]");
    }
}


/*��������  ע���ҵ����������Ǹ����ĵ�0���������ʵ�ʵ�ַ
��������ʽ: CHAR EtwHostStateShellcode[] = { 0xB8,0x08,0x00,0x00,0xC0,0xE9,'?','?','?','?',0x48,0x8B,0x15 };
����:
    code: ��ʾ������ �� EtwHostStateShellcode  UCHAR ����
    codeLenth: ��ʾ�����볤��
    startaddr: �����������ʼ��ַ;
    addrlenth: ����ȷ���������������ַ,������ʼ��ַƫ�Ƴ��Ⱥ����
    ����ֵ: �������0 ��ʾδ�ҵ�,����ֵ��ʾ�ҵ���һ���������ʵ�ʵ�ַ ע����ʵ�ʵ�ַ ��startaddr ��(startaddr+addrlenth)�ⷶΧ�м��ĳ����ַ,����ƫ��ֵ,��ʵ�ʵ�ַ
*/
EXTERN_C
ULONG_PTR SearchCode(unsigned char* code, ULONG_PTR codeLenth, unsigned char* startaddr, ULONG_PTR addrlenth)
{
    ULONG_PTR Ret = 0;
    ULONG_PTR Index = 0;
    unsigned char x = '?';
    BOOLEAN Isfind = 0;
    if ((!code) | (!codeLenth) | (!startaddr) | (!addrlenth))return 0;
    while (Index < (addrlenth - codeLenth + 1))
    {
        if (!MmIsAddressValid((PVOID)&startaddr[Index]))continue;

        if (code[0] == startaddr[Index])
        {
            Isfind = 1;
            for (ULONG_PTR i = 0; i < codeLenth; i++)
            {
                if (!MmIsAddressValid((PVOID)&startaddr[Index + i]))continue;
                if ((code[i] != x) && (code[i] != startaddr[Index + i]))
                {
                    Isfind = 0;
                    break;
                }
            }
            if (Isfind)
            {
                Ret = (ULONG_PTR)&startaddr[Index];
                break;
            }
        }
        Index++;
    }
    return Ret;
}


//
//VOID ReleaseFileList()
//{
//    PLIST_ENTRY ListHead, NextEntry, DelEntry;
//    PFILEDATA fileData;
//
//    __try
//    {
//        //DbgBreakPoint();
//        ListHead = &g_ProtectFileObjList.ProtectList;
//        NextEntry = ListHead->Flink;
//        while (ListHead != NextEntry)
//        {
//            fileData = CONTAINING_RECORD(NextEntry,
//                FILEDATA,
//                ProtectList);
//
//            FreeMemAllocate(fileData->fileName.Buffer, TAG_PRO);
//            FreeMemAllocate(fileData->filePath.Buffer, TAG_PRO);
//
//            DelEntry = NextEntry;
//
//            /* Move to the next entry */
//            NextEntry = NextEntry->Flink;
//
//            RemoveEntryList(DelEntry);
//            FreeMemAllocate(fileData, TAG_PRO);
//        }
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//        outLog("�ͷ��ļ��б� ����.");
//    }
//}
//
//VOID ReleaseWindowList()
//{
//    PLIST_ENTRY ListHead, NextEntry, DelEntry;
//    PWINDOW_DATA fileData;
//
//    __try
//    {
//        //DbgBreakPoint();
//        ListHead = &g_ProtectWndObjList.ProtectList;
//        NextEntry = ListHead->Flink;
//        while (ListHead != NextEntry)
//        {
//            fileData = CONTAINING_RECORD(NextEntry,
//                WINDOW_DATA,
//                ProtectList);
//
//            FreeMemAllocate(fileData->WindowName.Buffer, TAG_PRO);
//
//            DelEntry = NextEntry;
//
//            /* Move to the next entry */
//            NextEntry = NextEntry->Flink;
//
//            RemoveEntryList(DelEntry);
//            FreeMemAllocate(fileData, TAG_PRO);
//        }
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//        outLog("�ͷŴ����б� ����.");
//    }
//}

////�����ڴ���Դ
//VOID ReleaseMemoryResources()
//{
//    ReleaseFileList();
//    ReleaseWindowList();
//    ReleaseDebuggerList();
//    ReleaseDebugProcessList();
//}
//
////��ʼ������
//VOID InitProtect(IN PDRIVER_OBJECT DriverObject)
//{
//    RegisterCallbacks(DriverObject);
//}
//
////ж�ر���
//VOID UnloadProtect()
//{
//    UnCallbacks();
//}
//
EXTERN_C
VOID RemoveHooks()
{
    UnEptHook();
}
//
//EXTERN_C
//NTSTATUS TestVMM()
//{
//    __try
//    {
//        if (hvgt::test_vmcall() == FALSE)  //�����Ƿ��ܹ��ɹ�ִ��vmxָ��
//        {
//            outLog("vt����û�а�װ!!!");
//            return STATUS_UNSUCCESSFUL;
//        }
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//        outLog("��֧��vmxָ��!!!");
//        return STATUS_UNSUCCESSFUL;
//    }
//    outLog("VT�����Ѱ�װ�ɹ�!!!");
//    return STATUS_SUCCESS;
//}
//
//EXTERN_C
//NTSTATUS
//ProxyDbgkOpenProcessDebugPort(
//    IN PEPROCESS Process,
//    IN KPROCESSOR_MODE PreviousMode,
//    OUT HANDLE* pHandle
//)
///*++
//
//Routine Description:
//
//    References the target processes debug port.
//
//Arguments:
//
//    Process - Process to reference debug port
//
//Return Value:
//
//    PDEBUG_OBJECT - Referenced object or NULL
//
//--*/
//{
//    NTSTATUS Status;
//
//    PAGED_CODE();
//
//    Status = STATUS_PORT_NOT_SET;
//    *pHandle = NULL;
//    return Status;
//
//}
//
//EXTERN_C
////�ر�д����
//KIRQL WriteProtectDisable()
//{
//    KIRQL Irql = KeRaiseIrqlToDpcLevel();
//    UINT64 cr0 = __readcr0();
//    cr0 &= 0xFFFFFFFFFFFEFFFF;
//    __writecr0(cr0);
//    _disable();
//    return Irql;
//}
//
//EXTERN_C
////����д����
//VOID WriteProtectEnable(KIRQL Irql)
//{
//    UINT64 cr0 = __readcr0();
//    cr0 |= 0x10000;
//    _enable();
//    __writecr0(cr0);
//    KeLowerIrql(Irql);
//}
//
//EXTERN_C
//BOOLEAN SafeCopyMemory(PVOID pDest, PVOID pSrc, ULONG dwSize)
//{
//    BOOLEAN bRet;
//    KIRQL Irql;
//
//    __try
//    {
//        Irql = WriteProtectDisable();
//        RtlCopyMemory(pDest, pSrc, dwSize);
//        WriteProtectEnable(Irql);
//        bRet = TRUE;
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//        bRet = FALSE;
//    }
//    return bRet;
//}
//

KPROCESSOR_MODE KeGetPreviousMode()
{
    _ETHREAD* Thread = (_ETHREAD*)KeGetCurrentThread();
    size_t kthread_base = (size_t)Thread + ethread_offset::Tcb;
    size_t ptr_PreviousMode = kthread_base + kthread_offset::PreviousMode;
    return *(KPROCESSOR_MODE*)ptr_PreviousMode;
}

KPROCESSOR_MODE KeSetPreviousMode(KPROCESSOR_MODE PreviousMode)
{
    KPROCESSOR_MODE Old_PreviousMode;
    _ETHREAD* Thread = (_ETHREAD*)KeGetCurrentThread();
    size_t kthread_base = (size_t)Thread + ethread_offset::Tcb;
    size_t ptr_PreviousMode = kthread_base + kthread_offset::PreviousMode;
    Old_PreviousMode = *(KPROCESSOR_MODE*)ptr_PreviousMode;
    *(KPROCESSOR_MODE*)ptr_PreviousMode = PreviousMode;
    return Old_PreviousMode;
}

LONG
ExSystemExceptionFilter(VOID)
{
    return (KeGetPreviousMode() != KernelMode ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH);
}

EXTERN_C
VOID KiDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PKTRAP_FRAME TrapFrame,
    IN KPROCESSOR_MODE PreviousMode,
    IN BOOLEAN FirstChance)
{
    Original_KiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
}


//
//EXTERN_C
//VOID KiDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
//    IN PMY_KEXCEPTION_FRAME ExceptionFrame,
//    IN PMY_KTRAP_FRAME TrapFrame,
//    IN KPROCESSOR_MODE PreviousMode,
//    IN BOOLEAN FirstChance)
//{
//    PCONTEXT ContextFrame;
//    EXCEPTION_RECORD LocalExceptRecord;
//    PDEBUG_OBJECT DebugObject = NULL;
//    ULONG_PTR FaultingRsp;
//    PKTHREAD Thread;
//    PVOID InsCallback;
//    PMACHINE_FRAME MachineFrame;
//    ULONG_PTR UserStack_0;
//    ULONG_PTR UserStack_1;
//    ULONG_PTR UserStack_2;
//    PEXCEPTION_RECORD UserExceptionRecord;
//    PCONTEXT_EX UserContextEx;
//    PCONTEXT UserContext;
//    PCONTEXT_EX ContextEx;
//    CONTEXT_EX TempContextEx;
//    ULONG ContextFlags;
//    ULONG ContextLength;
//    BOOLEAN DebugService;
//    PDEBUG_PROCESS DebugProcess;
//
//    PAGED_CODE();
//
//
//    /* Increase number of Exception Dispatches */
//    KeGetCurrentPrcb()->KeExceptionDispatchCount += 1;
//
//    /* Set the context flags */
//    ContextFlags = CONTEXT_ALL;
//
//    /* Check if User Mode or if the kernel debugger is enabled */
//    if ((PreviousMode == UserMode) && (*KeFeatureBits & KF_XSTATE))
//    {
//        if (*KeEnabledXStateFeatures & ~KF_XSTATEFEATURES)
//            ContextFlags = CONTEXT_ALL | CONTEXT_XSTATE;
//    }
//
//    RtlGetExtendedContextLength(ContextFlags, &ContextLength);
//    ContextFrame = (PCONTEXT)alloca(ContextLength);                            // ����ջ�ڴ�ռ�
//
//    RtlInitializeExtendedContext(ContextFrame, ContextFlags, &ContextEx);
//
//
//    if ((ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE)
//    {
//        ((PMY_XSAVE_AREA_HEADER)((UCHAR*)ContextEx + ContextEx->XState.Offset))->Mask = (ULONG_PTR)(*KeEnabledXStateFeatures & ~KF_XSTATEFEATURES);
//    }
//
//    /* Get a Context */
//    KeContextFromKframes(TrapFrame, ExceptionFrame, ContextFrame);
//
//    /* Look at our exception code */
//    switch (ExceptionRecord->ExceptionCode)
//    {
//        /* Breakpoint */
//    case STATUS_BREAKPOINT:
//
//        /* Decrement RIP by one */
//        ContextFrame->Rip--;
//        break;
//    }
//
//    //
//    // If the exception is an internal general protect fault, invalid opcode,
//    // or integer divide by zero, then attempt to resolve the problem without
//    // actually raising an exception.
//    // 
//
//    if (KiPreprocessFault(ExceptionRecord, TrapFrame, ContextFrame, PreviousMode))
//    {
//        goto Handled;
//    }
//
//    /* Handle kernel-mode first, it's simpler */
//    if (PreviousMode == KernelMode)
//    {
//        /* Check if this is a first-chance exception */
//        if (FirstChance)
//        {
//            /* Break into the debugger for the first time */
//            if (KiDebugRoutine(TrapFrame,
//                ExceptionFrame,
//                ExceptionRecord,
//                ContextFrame,
//                PreviousMode,
//                FALSE))
//            {
//                /* Exception was handled */
//                goto Handled;
//            }
//
//            DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//            /* If the Debugger couldn't handle it, dispatch the exception */
//            if (RtlDispatchException(ExceptionRecord, ContextFrame)) goto Handled;
//        }
//        DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//
//        /* This is a second-chance exception, only for the debugger */
//        if (KiDebugRoutine(TrapFrame,
//            ExceptionFrame,
//            ExceptionRecord,
//            ContextFrame,
//            PreviousMode,
//            TRUE))
//        {
//            /* Exception was handled */
//            goto Handled;
//        }
//
//        /* Third strike; you're out */
//        KeBugCheckEx(KMODE_EXCEPTION_NOT_HANDLED,
//            ExceptionRecord->ExceptionCode,
//            (ULONG_PTR)ExceptionRecord->ExceptionAddress,
//            ExceptionRecord->ExceptionInformation[0],
//            ExceptionRecord->ExceptionInformation[1]);
//    }
//    else
//    {
//        //�����û�����쳣
//
//        if ((((_EPROCESS*)PsGetCurrentProcess())->WoW64Process)/*�жϵ�ǰ�����Ƿ�Ϊ32λ����*/ &&
//            (ExceptionRecord->ExceptionCode == STATUS_DATATYPE_MISALIGNMENT)/*�쳣����Ϊ�������*/ &&
//            (TrapFrame->EFlags & EFLAGS_AC_MASK)/*�ж϶������Ƿ񱻿���*/)
//        {
//            DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//            TrapFrame->EFlags &= ~EFLAGS_AC_MASK;  //�رն�����
//            return;
//        }
//        else
//        {
//            if ((ContextFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
//            {
//                DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//                switch (ExceptionRecord->ExceptionCode)
//                {
//                case STATUS_BREAKPOINT:
//                    ExceptionRecord->ExceptionCode = STATUS_WX86_BREAKPOINT;
//                    break;
//
//                case STATUS_SINGLE_STEP:
//                    ExceptionRecord->ExceptionCode = STATUS_WX86_SINGLE_STEP;
//                    break;
//                }
//
//                //
//                // Clear the upper 32-bits of the stack address and 16-byte
//                // align the stack address.
//                //
//
//                //32λ���봦��  ���ջ��ַ��32λ������16�ֽڶ���ջ��ַ
//
//                FaultingRsp = (ContextFrame->Rsp & 0xFFFFFFF0);
//
//            }
//            else
//            {
//                FaultingRsp = ContextFrame->Rsp;
//            }
//
//            if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
//            {
//                Thread = KeGetCurrentThread();
//                //if (Thread->Header.TimerMiscFlags & 0x40)
//                //    Thread->Ucb->Flags |= 0x10u;
//            }
//        }
//
//        memset(&ExceptionRecord->ExceptionInformation[ExceptionRecord->NumberParameters],
//            0,
//            (sizeof(ULONG_PTR) * EXCEPTION_MAXIMUM_PARAMETERS) - (ExceptionRecord->NumberParameters * sizeof(ULONG_PTR)));
//
//        /* User mode exception, was it first-chance? */
//        if (FirstChance)
//        {
//            /*
//             * Break into the kernel debugger unless a user mode debugger
//             * is present or user mode exceptions are ignored, except if this
//             * is a debug service which we must always pass to KD
//             */
//
//            if (IsDebugTargetProcess((_EPROCESS*)PsGetCurrentProcess(), &DebugProcess))
//            {
//                //outLog(("%s\n", PsGetCurrentProcess()->ImageFileName));
//                DebugObject = DebugProcess->DebugObject;
//            }
//            else
//            {
//                DebugObject = NULL;
//            }
//            DebugService = KdIsThisAKdTrap(ExceptionRecord,
//                ContextFrame,
//                UserMode);
//
//            if (!(((_EPROCESS*)PsGetCurrentProcess())->DebugPort) &&
//                !(*KdIgnoreUmExceptions/*����user mode�쳣*/) &&
//                !DebugObject || (DebugService == TRUE))
//            {
//                /* Call the kernel debugger */
//                if (KiDebugRoutine(TrapFrame,  //���쳣ת����Ring0������
//                    ExceptionFrame,
//                    ExceptionRecord,
//                    ContextFrame,
//                    PreviousMode,
//                    FALSE))
//                {
//                    /* Exception was handled */
//                    DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//                    goto Handled;
//                }
//                DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//            }
//
//            DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//
//            /* Forward exception to user mode debugger */
//            if (DbgkForwardException(ExceptionRecord, TRUE, FALSE)) return;  //���쳣ת����Ring3������
//
//
//            //ȡ��TFλ
//            TrapFrame->EFlags &= ~EFLAGS_TF_MASK;  //�����ӵ��������� ����Ҫ����ִ��
//            LocalExceptRecord.ExceptionCode = STATUS_ACCESS_VIOLATION;  //���쳣��������ΪAV����        
//
//            // ���û�е��������쳣�ɷ��������Լ�����
//            /* Set up the user-stack */
//        DispatchToUser:
//            _SEH2_TRY
//            {
//                DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//
//            //�����û�ջ�洢CONTEXT�ṹ����
//            UserStack_0 = FaultingRsp;
//            if ((ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE)// CONTEXT_XSTATE
//            {
//                UserStack_0 = (FaultingRsp - ContextEx->XState.Length) & ~XSTATE_STACK_ROUND;
//            }
//
//            UserStack_1 = (UserStack_0 - sizeof(MACHINE_FRAME)) & ~STACK_ROUND;
//            MachineFrame = (PMACHINE_FRAME)UserStack_1;  //MACHINE_FRAME
//            UserExceptionRecord = (PEXCEPTION_RECORD)(UserStack_1 - EXCEPTION_RECORD_LENGTH);  //EXCEPTION_RECORD
//            UserContextEx = (PCONTEXT_EX)(UserStack_1 - (CONTEXT_EX_LENGTH + EXCEPTION_RECORD_LENGTH));  //CONTEXT_EX
//            UserContext = (PCONTEXT)(UserStack_1 - (CONTEXT_LENGTH + CONTEXT_EX_LENGTH + EXCEPTION_RECORD_LENGTH));  //CONTEXT
//
//            TempContextEx.All.Offset = (LONG)((UCHAR*)UserContext - (UCHAR*)UserContextEx);
//            TempContextEx.All.Length = (ULONG)((UCHAR*)FaultingRsp - (UCHAR*)UserContext);
//            TempContextEx.Legacy.Offset = (LONG)((UCHAR*)UserContext - (UCHAR*)UserContextEx);
//            TempContextEx.Legacy.Length = sizeof(CONTEXT);
//            TempContextEx.XState.Offset = (LONG)((UCHAR*)UserStack_0 - (UCHAR*)UserContextEx);
//            TempContextEx.XState.Length = (ULONG)(FaultingRsp - UserStack_0);
//
//            //̽��ջ�Ƿ��д
//            ProbeForWriteSmallStructure(UserContext,
//                FaultingRsp - (UserStack_1 - (CONTEXT_LENGTH + CONTEXT_EX_LENGTH + EXCEPTION_RECORD_LENGTH)),
//                STACK_ALIGN2);
//
//            MachineFrame->Rsp = FaultingRsp;
//            MachineFrame->Rip = ContextFrame->Rip;
//            *UserExceptionRecord = *ExceptionRecord;
//
//            //����CONTEXT��������XState��
//            RtlpCopyExtendedContext(TRUE, UserContextEx, &TempContextEx, ContextFlags, ContextEx, NULL);
//            *UserContextEx = TempContextEx;
//            TrapFrame->Rsp = (ULONG_PTR)UserContext;
//
//            _disable();                             // ���ж�
//            TrapFrame->SegCs = KGDT64_R3_CODE | RPL_MASK;
//            TrapFrame->Rip = *(ULONG_PTR*)KeUserExceptionDispatcher;
//            InsCallback = ((_EPROCESS*)PsGetCurrentProcess())->Pcb.InstrumentationCallback;
//            if (InsCallback)
//            {
//                TrapFrame->R10 = TrapFrame->Rip;
//                TrapFrame->Rip = (ULONG_PTR)InsCallback;
//            }
//            _enable();                              // ���ж�
//
//            DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//
//            /* Dispatch exception to user-mode */
//            _SEH2_YIELD(return);
//            }
//                _SEH2_EXCEPT((RtlCopyMemory(&LocalExceptRecord, _SEH2_GetExceptionInformation()->ExceptionRecord, sizeof(EXCEPTION_RECORD)), EXCEPTION_EXECUTE_HANDLER))
//            {
//                /* Check if we got a stack overflow and raise that instead */
//                if ((NTSTATUS)LocalExceptRecord.ExceptionCode == STATUS_STACK_OVERFLOW)
//                {
//                    /* Copy the exception address and record */
//                    LocalExceptRecord.ExceptionAddress = ExceptionRecord->ExceptionAddress;
//                    *ExceptionRecord = LocalExceptRecord;
//
//                    /* Do the exception again */
//                    _SEH2_YIELD(goto DispatchToUser);
//                }
//            }
//            _SEH2_END;
//
//            DPRINT("First chance exception in %.16s, ExceptionCode: %lx, ExceptionAddress: %p, P0: %lx, P1: %lx\n",
//                ((_EPROCESS*)PsGetCurrentProcess())->ImageFileName,
//                ExceptionRecord->ExceptionCode,
//                ExceptionRecord->ExceptionAddress,
//                ExceptionRecord->ExceptionInformation[0],
//                ExceptionRecord->ExceptionInformation[1]);
//        }
//        else
//        {
//            DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//        }
//
//        /* Try second chance */
//        if (DbgkForwardException(ExceptionRecord, TRUE, TRUE))
//        {
//            /* Handled, get out */
//            return;
//        }
//        else if (DbgkForwardException(ExceptionRecord, FALSE, TRUE))
//        {
//            /* Handled, get out */
//            return;
//        }
//
//        //UnEptHook();
//        //DbgBreakPoint();
//        DBGKTRACE(DBGK_EXCEPTION_DEBUG, "��ǲ�쳣..\n");
//
//        /* 3rd strike, kill the process */
//        DPRINT1("Kill %.16s, ExceptionCode: %lx, ExceptionAddress: %p, BaseAddress: %p, P0: %lx, P1: %lx\n",
//            ((_EPROCESS*)PsGetCurrentProcess())->ImageFileName,
//            ExceptionRecord->ExceptionCode,
//            ExceptionRecord->ExceptionAddress,
//            ((_EPROCESS*)PsGetCurrentProcess())->SectionBaseAddress,
//            ExceptionRecord->ExceptionInformation[0],
//            ExceptionRecord->ExceptionInformation[1]);
//
//        ZwTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
//        KeBugCheckEx(KMODE_EXCEPTION_NOT_HANDLED,
//            ExceptionRecord->ExceptionCode,
//            (ULONG_PTR)ExceptionRecord->ExceptionAddress,
//            ExceptionRecord->ExceptionInformation[0],
//            ExceptionRecord->ExceptionInformation[1]);
//    }
//
//Handled:
//    /* Convert the context back into Trap/Exception Frames */
//    KeContextToKframes(TrapFrame,
//        ExceptionFrame,
//        ContextFrame,
//        ContextFrame->ContextFlags,
//        PreviousMode);
//}
//
//
//NTSTATUS
//PsSuspendThread(
//    IN _ETHREAD* Thread,
//    OUT PULONG PreviousSuspendCount OPTIONAL)
//{
//    NTSTATUS Status;
//    ULONG OldCount = 0;
//    PAGED_CODE();
//
//    /* Assume success */
//    Status = STATUS_SUCCESS;
//
//    /* Check if we're suspending ourselves */
//    if (Thread == (_ETHREAD*)PsGetCurrentThread())
//    {
//        /* Guard with SEH because KeSuspendThread can raise an exception */
//        _SEH2_TRY
//        {
//            /* Do the suspend */
//            OldCount = KeSuspendThread(&Thread->Tcb);
//        }
//            _SEH2_EXCEPT(_SEH2_GetExceptionCode() == STATUS_SUSPEND_COUNT_EXCEEDED)
//        {
//            /* Get the exception code */
//            Status = _SEH2_GetExceptionCode();
//        }
//        _SEH2_END;
//    }
//    else
//    {
//        /* Acquire rundown protection */
//        if (ExAcquireRundownProtection(&Thread->RundownProtect))
//        {
//            /* Make sure the thread isn't terminating */
//            if (Thread->Terminated)
//            {
//                /* Fail */
//                Status = STATUS_THREAD_IS_TERMINATING;
//            }
//            else
//            {
//                /* Guard with SEH because KeSuspendThread can raise an exception */
//                _SEH2_TRY
//                {
//                    /* Do the suspend */
//                    OldCount = KeSuspendThread(&Thread->Tcb);
//                }
//                    _SEH2_EXCEPT(_SEH2_GetExceptionCode() == STATUS_SUSPEND_COUNT_EXCEEDED)
//                {
//                    /* Get the exception code */
//                    Status = _SEH2_GetExceptionCode();
//                }
//                _SEH2_END;
//
//                /* Check if it was terminated during the suspend */
//                if (Thread->Terminated)
//                {
//                    /* Wake it back up and fail */
//                    KeForceResumeThread(&Thread->Tcb);
//                    Status = STATUS_THREAD_IS_TERMINATING;
//                    OldCount = 0;
//                }
//            }
//
//            /* Release rundown protection */
//            ExReleaseRundownProtection(&Thread->RundownProtect);
//        }
//        else
//        {
//            /* Thread is terminating */
//            Status = STATUS_THREAD_IS_TERMINATING;
//        }
//    }
//
//    /* Write back the previous count */
//    if (PreviousSuspendCount) *PreviousSuspendCount = OldCount;
//    return Status;
//}
//
//NTSTATUS
//PsResumeThread(IN _ETHREAD* Thread,
//    OUT PULONG PreviousSuspendCount OPTIONAL)
//{
//    ULONG OldCount;
//    PAGED_CODE();
//
//    /* Resume the thread */
//    OldCount = KeResumeThread(&Thread->Tcb);
//
//    /* Return the count if asked */
//    if (PreviousSuspendCount) *PreviousSuspendCount = OldCount;
//    return STATUS_SUCCESS;
//}
//

//
////�ж�Ŀ������Ƿ��������Լ�
//BOOLEAN IsSelf(_EPROCESS* Process)
//{
//    BOOLEAN result = FALSE;
//    if (Process == g_SelfProcess)
//    {
//        result = TRUE;
//    }
//    return result;
//}

//�ж�Ŀ������Ƿ��������Լ��ĵ�����
BOOLEAN IsDebugger(PEPROCESS Process)
{
    BOOLEAN result = FALSE;

    PLIST_ENTRY ListHead, NextEntry;
    PDEBUGGER_TABLE_ENTRY entry;


    //if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    //{
    //    ExAcquireFastMutex(&g_DebuggerList.Mutex);
    //}    

    ASSERT(Process);

    HANDLE pid = PsGetProcessId(Process);

    ListHead = &g_DebuggerList.list_entry.ListHead;
    NextEntry = ListHead->Flink;
    while (ListHead != NextEntry)
    {
        entry = CONTAINING_RECORD(NextEntry,
            DEBUGGER_TABLE_ENTRY,
            list_entry);

        if (entry)
        {            
            if (entry->dwPid == (DWORD)pid)
            {
                result = TRUE;
                break;
            }
        }

        /* Move to the next entry */
        NextEntry = NextEntry->Flink;
    }
/*    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        ExReleaseFastMutex(&g_DebuggerList.Mutex);
    }  */  
    return result;
}
//
//BOOLEAN SetDebugTargetProcess(_EPROCESS* Process, PDEBUG_OBJECT DebugObject)
//{
//    BOOLEAN result = FALSE;
//
//    g_DebugProcessList->Lock();
//    __try
//    {
//        if (IsDebugger(NULL))
//        {
//            PDEBUG_PROCESS tmp = new DEBUG_PROCESS;
//            RtlZeroMemory(tmp, sizeof(DEBUG_PROCESS));
//            tmp->Process = Process;
//            tmp->DebugObject = DebugObject;
//            g_DebugProcessList->Add(tmp);
//            result = TRUE;
//        }
//        return result;
//    }
//    __finally
//    {
//        g_DebugProcessList->UnLock();
//    }
//}
//
BOOLEAN IsProtectTargetProcess(_EPROCESS* Process)
{
    BOOLEAN result = FALSE;
    if (Process == g_ProtectTargetProcess)
    {
        result = TRUE;
    }
    return result;
}

//�����豸 �������ӵ�
NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriver_Object)
{
    NTSTATUS ntStatus;
    PDEVICE_OBJECT pDevObj;
    PDEVICE_EXTENSION pDevExt;

    //�����豸����
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, L"\\Device\\DbgkSysDevice");

    //�����豸
    ntStatus = IoCreateDevice(pDriver_Object,
        sizeof(DEVICE_EXTENSION),
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &pDevObj);

    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    //����ֱ�Ӷ�д�豸
    pDevObj->Flags |= DO_BUFFERED_IO;
    pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
    pDevExt->pDevice = pDevObj;
    pDevExt->ustrDeviceName = devName;

    //������������
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, L"\\??\\UnrealDbg");
    pDevExt->ustrSymLinkName = symLinkName;
    ntStatus = IoCreateSymbolicLink(&symLinkName, &devName);
    if (!NT_SUCCESS(ntStatus))
    {
        IoDeleteDevice(pDevObj);  //����ʧ��ɾ���豸
        return ntStatus;
    }
    return STATUS_SUCCESS;
}

////ɾ���豸
//VOID _RemoveDevice(IN PDRIVER_OBJECT pDriver_Object)
//{
//    PDEVICE_OBJECT	pNextObj;
//    pNextObj = pDriver_Object->DeviceObject;
//    while (pNextObj != NULL)
//    {
//        PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pNextObj->DeviceExtension;
//
//        //ɾ����������
//        UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
//        IoDeleteSymbolicLink(&pLinkName);
//        pNextObj = pNextObj->NextDevice;
//        IoDeleteDevice(pDevExt->pDevice);
//    }
//}

NTSTATUS InitDispatchRoutin(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    //�õ���ǰ��ջ
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    //�õ����뻺������С
    ULONG cbin = stack->Parameters.DeviceIoControl.InputBufferLength;
    //�õ������������С
    ULONG cbout = stack->Parameters.DeviceIoControl.OutputBufferLength;
    //�õ�IOCTL��
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    //switch (code)
    //{
    //case IOCTL_READ:
    //{
    //    //PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
    //    PUser_Data pBuffer = pIrp->AssociatedIrp.SystemBuffer;
    //    KdPrint(("Pid:%d\n", pBuffer->Pid));
    //    KdPrint(("pAddress:0x%08X\n", pBuffer->pAddress));
    //    //KdPrint(("%d\n", pIrp->MdlAddress));
    //    KdPrint(("User Addr:0x%08X\n", MmGetMdlVirtualAddress(pIrp->MdlAddress)));
    //    POutput_Data pRtnAddr = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
    //    KdPrint(("MdlAddr:0x%08X\n", pRtnAddr));
    //    //memmove(pRtnAddr, pBuffer, cbout);
    //    ReadFunc((HANDLE)pBuffer->Pid, (PVOID)pBuffer->pAddress, &pRtnAddr->Value);
    //    break;
    //}
    //default:
    //{
    //    ntStatus = STATUS_INVALID_VARIANT;
    //    break;
    //}
    //}

    pIrp->IoStatus.Status = ntStatus;
    pIrp->IoStatus.Information = cbin;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return ntStatus;
}

NTSTATUS HandlerDispatchRoutin(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    //�õ���ǰ��ջ
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    //�õ����뻺������С
    ULONG cbin = stack->Parameters.DeviceIoControl.InputBufferLength;
    //�õ������������С
    ULONG cbout = stack->Parameters.DeviceIoControl.OutputBufferLength;
    //�õ�IOCTL��
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code)
    {
    case IOCTL_LOAD_SYMBOLS_TABLE:
    {
        //�����߳�����gui�߳�
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        InitSymbolsTable(userData, pIrp);
        break;
    }
    case IOCTL_LOAD_DEBUGGER_STATE:
    {
        //PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        //InitDebuggerState((PDEBUGGER_STATE)userData->pUserData);
        break;
    }
    case IOCTL_LOAD_PROTECT_OBJ_DATA:
    {
        //PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        //InitProtectList(userData, pIrp);
        break;
    }
    case IOCTL_LOAD_DEBUGGER_DATA:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        InitDebuggerInfo(userData);
        break;
    }
    case IOCTL_CREATE_REMOTE_THREAD:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        CreateRemoteThread(userData);
        break;
    }
    case IOCTL_GET_PROCESS_INFO:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        GetProcessInfo(userData, pIrp);
        break;
    }
    case IOCTL_TL_BLOCK_RESUME_THREAD:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        TL_BlockGameResumeThread(userData, pIrp);
        break;
    }
    case IOCTL_SET_HARDWARE_BREAKPOINT:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        SetHardwareBreakpoint(userData, pIrp);
        break;
    }
    case IOCTL_DEL_HARDWARE_BREAKPOINT:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        RemoveHardwareBreakpoint(userData, pIrp);
        break;
    }
    case IOCTL_SET_SOFTWARE_BREAKPOINT:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        SetSoftwareBreakpoint(userData, pIrp);
        break;
    }
    case IOCTL_DEL_SOFTWARE_BREAKPOINT:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        RemoveSoftwareBreakpoint(userData, pIrp);
        break;
    }
    case IOCTL_READ_SOFTWARE_BREAKPOINT:
    {
        PUSER_DATA userData = (PUSER_DATA)pIrp->AssociatedIrp.SystemBuffer;
        ReadSoftwareBreakpoint(userData, pIrp);
        break;
    }
    default:
    {
        ntStatus = STATUS_INVALID_VARIANT;
        break;
    }
    }

    pIrp->IoStatus.Status = ntStatus;
    pIrp->IoStatus.Information = cbout;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return ntStatus;
}

USER_DATA GetUserData(PUSER_DATA userData)
{
    USER_DATA user = { 0 };
    if (userData)
    {
        user.Count = userData->Count;
        user.uSize = userData->uSize;
        user.pUserData = userData->pUserData;
    }
    return user;
}

void GetProcessInfo(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PRING3_PROCESS_INFO output = (PRING3_PROCESS_INFO)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(RING3_PROCESS_INFO));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(RING3_PROCESS_INFO);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PRING3_PROCESS_INFO pInfo = reinterpret_cast<PRING3_PROCESS_INFO>(aucPlainText + i * sizeof(RING3_PROCESS_INFO));

        if (pInfo->ProcessHandle)
        {
            _EPROCESS* Process;
            NTSTATUS Status = ObReferenceObjectByHandle((HANDLE)pInfo->ProcessHandle,
                PROCESS_ALL_ACCESS,
                *PsProcessType,
                KernelMode,
                (PVOID*)&Process,
                NULL);
            if (!NT_SUCCESS(Status)) {
                break;
            }

            size_t ptr_DirectoryTableBase = (size_t)Process + kprocess_offset::DirectoryTableBase;
            if (ptr_DirectoryTableBase)
            {
                output->cr3 = *(size_t*)ptr_DirectoryTableBase;
            }
            ObDereferenceObject(Process);
        }
    }
    free_pool(aucPlainText);
}


void TL_BlockGameResumeThread(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PRING3_TL_GAME_TABLE_ENTRY output = (PRING3_TL_GAME_TABLE_ENTRY)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(RING3_TL_GAME_TABLE_ENTRY));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(RING3_TL_GAME_TABLE_ENTRY);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PRING3_TL_GAME_TABLE_ENTRY pInfo = reinterpret_cast<PRING3_TL_GAME_TABLE_ENTRY>(aucPlainText + i * sizeof(RING3_TL_GAME_TABLE_ENTRY));

        if (pInfo->dwPid)
        {
            InterlockedExchange(&g_TL_Game_pid, pInfo->dwPid);
            break;
        }
    }
    free_pool(aucPlainText);
}

void CreateRemoteThread(IN PUSER_DATA userData)
{
    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(userData->uSize);
    DecryptData((PVOID)userData->pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = userData->uSize / sizeof(RING3_REMOTE_THREAD);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PRING3_REMOTE_THREAD pInfo = reinterpret_cast<PRING3_REMOTE_THREAD>(aucPlainText + i * sizeof(RING3_REMOTE_THREAD));

        if (pInfo->hProcess > 0)
        {
            ApcCreateRemoteThread((HANDLE)pInfo->hProcess, (PVOID)pInfo->pUserFunc);
        }
    }
    free_pool(aucPlainText);    
}

//VOID TestProtectList()
//{
//    PLIST_ENTRY ListHead, NextEntry;
//    PFILEDATA fileData;
//
//
//    ListHead = &g_ProtectFileObjList.ProtectList;
//    NextEntry = ListHead->Flink;
//    while (ListHead != NextEntry)
//    {
//        fileData = CONTAINING_RECORD(NextEntry,
//            FILEDATA,
//            ProtectList);
//        outLog("�������ļ���: %wZ", fileData->fileName);
//        outLog("�������ļ�·��: %wZ", fileData->filePath);
//
//        /* Move to the next entry */
//        NextEntry = NextEntry->Flink;
//    }
//}

VOID InsertProtectFileList(PFILEDATA fileData)
{
    if (fileData)
    {
        ExAcquireFastMutex(&g_ProtectFileObjList.Mutex);
        InsertNode(&g_ProtectFileObjList.list_entry, &fileData->list_entry);
        ExReleaseFastMutex(&g_ProtectFileObjList.Mutex);
    }
}

VOID InsertProtectWndList(PWINDOW_DATA fileData)
{
    if (fileData)
    {
        ExAcquireFastMutex(&g_ProtectWndObjList.Mutex);
        InsertNode(&g_ProtectWndObjList.list_entry, &fileData->list_entry);
        ExReleaseFastMutex(&g_ProtectWndObjList.Mutex);
    }
}

VOID InitFileList(PRING3_PROTECT_OBJECT pProtectObj)
{
    WCHAR* sText;
    WCHAR* SubStr;
    WCHAR* SubStr2;
    PFILEDATA fileData;

    __try
    {
        //DbgBreakPoint();
        sText = (WCHAR*)pProtectObj->fileData;

        for (;;)
        {
            if (sText == NULL)
                break;

            SubStr = (WCHAR*)MemAllocate(256 * sizeof(WCHAR), FALSE, TAG_PRO);
            SubStr2 = (WCHAR*)MemAllocate(256 * sizeof(WCHAR), FALSE, TAG_PRO);
            fileData = (PFILEDATA)MemAllocate(sizeof(FILEDATA), FALSE, TAG_PRO);

            sText = SplitString(sText, SubStr, '&');  //��ȡ�ļ���
            if (StrIsValid(SubStr))
            {
                RtlInitUnicodeString(&fileData->fileName, SubStr);
            }
            if (sText == NULL)
                break;

            sText = SplitString(sText, SubStr2, '%'); //��ȡ�ļ�·��
            if (StrIsValid(SubStr2))
            {
                RtlInitUnicodeString(&fileData->filePath, SubStr2);
            }
            if (StrIsValid2(fileData->fileName) && StrIsValid2(fileData->filePath))
            {
                InsertProtectFileList(fileData);
            }
        }
        //TestProtectList();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        outLog("��ʼ���ļ��б� ����.");
    }
}

VOID InitWindowList(PRING3_PROTECT_OBJECT pProtectObj)
{
    WCHAR* sText;
    WCHAR* SubStr;
    PWINDOW_DATA fileData;

    __try
    {
        sText = (WCHAR*)pProtectObj->fileData;

        for (;;)
        {
            if (sText == NULL)
                break;

            SubStr = (WCHAR*)MemAllocate(256 * sizeof(WCHAR), FALSE, TAG_PRO);
            fileData = (PWINDOW_DATA)MemAllocate(sizeof(WINDOW_DATA), FALSE, TAG_PRO);

            sText = SplitString(sText, SubStr, '&');  //��ȡ���ڱ��������
            if (StrIsValid(SubStr))
            {
                RtlInitUnicodeString(&fileData->WindowName, SubStr);
            }
            if (StrIsValid2(fileData->WindowName))
            {
                InsertProtectWndList(fileData);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        outLog("��ʼ�������б� ����.");
    }
}


//��ʼ�������б�
VOID InitProtectList(IN PUSER_DATA userData, IN PIRP pIrp)
{

    USER_DATA user = GetUserData(userData);

    PRING3_PROTECT_OBJECT output = (PRING3_PROTECT_OBJECT)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(RING3_PROTECT_OBJECT));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(RING3_PROTECT_OBJECT);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PRING3_PROTECT_OBJECT pInfo = reinterpret_cast<PRING3_PROTECT_OBJECT>(aucPlainText + i * sizeof(RING3_PROTECT_OBJECT));

        ULONG dataType = pInfo->dataType;
        if (dataType == PROTECT_FILE)
        {
            InitFileList(pInfo);
        }
        else if (dataType == PROTECT_WINDOW)
        {
            InitWindowList(pInfo);
        }
    }
    free_pool(aucPlainText);
}

//VOID InitDebuggerState(PDEBUGGER_STATE pDbgState)
//{
//
//}
//
//VOID DecryptDebuggerInfo(PDEBUGGER_DATA pDbgInfo)
//{
//
//}

VOID InitDebuggerInfo(IN PUSER_DATA userData)
{
    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(userData->uSize);
    DecryptData((PVOID)userData->pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = userData->uSize / sizeof(RING3_DEBUGGER_TABLE_ENTRY);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PRING3_DEBUGGER_TABLE_ENTRY pInfo = reinterpret_cast<PRING3_DEBUGGER_TABLE_ENTRY>(aucPlainText + i * sizeof(RING3_DEBUGGER_TABLE_ENTRY));

        if (pInfo->dwPid > 0)
        {
            PDEBUGGER_TABLE_ENTRY debugger = allocate_pool<DEBUGGER_TABLE_ENTRY>();
            if (debugger)
            {
                debugger->dwPid = pInfo->dwPid;
                debugger->fileData = pInfo->fileData;
                debugger->fileData2 = pInfo->fileData2;
                InsertDebuggerList(debugger);
            }
        }
    }
    free_pool(aucPlainText);
}


VOID InitGlobalVariable(PDRIVER_OBJECT DriverObject)
{
    g_IsInitGlobalVariable = FALSE;
    ExInitializeFastMutex(&LongFlagsMutex);
    InitializeList(&g_ProtectFileObjList.list_entry, &g_ProtectFileObjList.Mutex);
    InitializeList(&g_ProtectWndObjList.list_entry, &g_ProtectWndObjList.Mutex);
    InitializeList(&g_DebuggerList.list_entry, &g_DebuggerList.Mutex);
    InitializeList(&g_DebugProcessList.list_entry, &g_DebugProcessList.Mutex);
    InitializeList(&g_BreakpointList.list_entry,&g_BreakpointList.Mutex);
    InitializeList(&g_VirtualHandleList.list_entry, &g_VirtualHandleList.Mutex);        
    //SetProcessCallbacks(DriverObject);
}
//
//VOID InitSymbolicVariable()
//{
//
//}
//
//EXTERN_C
//NTSTATUS PspInsertThread(_ETHREAD* Thread, //rcx
//    _EPROCESS* CurrentProcess, //rdx
//    PINITIAL_TEB InitialTeb, //r8
//    PUCHAR ProcessFlags, //r9
//    ACCESS_MASK DesiredAccess,
//    PUCHAR Flag,
//    PPSP_CREATE_PROCESS_CONTEXT CreateProcessContext,
//    PPSP_OBJECT_CREATION_STATE AccessState,
//    PGROUP_AFFINITY GroupAffinity,
//    HANDLE* ThreadHandle,
//    PCLIENT_ID ClientID)
//{
//    PTEB Teb;
//    PTEB* RetTeb;
//    _EPROCESS* Process;
//    PULONG IdealProcessor;
//    PEJOB Job;
//    ULONG_PTR AffinityMask;
//    UCHAR AffinityMask2;
//    UCHAR ProcessFlags2;
//    ULONG CrossThreadFlags;
//    PPSP_CPU_QUOTA_APC Apc;
//    NTSTATUS Status;
//    ULONG a5;
//    KAPC_STATE ApcState;
//    PVOID tmpInitialTeb;
//    char v42;
//    ULONG Processa;
//    PVOID Object;
//    BOOLEAN boReferenceProcess;
//    NTSTATUS CreationStatus, ExitStatus;
//    PS_CREATE_NOTIFY_INFO CreateInfo;
//    PPS_CREATE_NOTIFY_INFO pCreateInfo;
//    CLIENT_ID ClientId;
//    PFILE_OBJECT FileObject;
//    PUNICODE_STRING FileName;
//    PUNICODE_STRING CommandLine;
//    PRTL_USER_PROCESS_PARAMETERS CapturedProcessParameters;
//    ULONG i;
//    PEX_CALLBACK_ROUTINE_BLOCK CallBack;
//    PCREATE_PROCESS_NOTIFY_ROUTINE_EX ProcessCallBackEx;
//    PCREATE_PROCESS_NOTIFY_ROUTINE ProcessCallBack;
//    PCREATE_THREAD_NOTIFY_ROUTINE ThreadCallBack;
//    PEX_CALLBACK Ex_CallBack;
//    ULONG_PTR ExCallBackPointer;
//    ULONG_PTR v51;
//
//    PAGED_CODE();
//
//    //DbgBreakPoint();
//    AffinityMask2 = 0;
//    ExitStatus = STATUS_SUCCESS;
//    Process = (_EPROCESS*)PsGetCurrentProcess();
//    Teb = (PTEB)Thread->Tcb.Teb;
//    IdealProcessor = NULL;
//
//    if (CreateProcessContext)
//    {
//        RetTeb = CreateProcessContext->RetTeb;
//        if (CreateProcessContext->PresentFlags & 0x4000)
//        {
//            IdealProcessor = (PULONG)&CreateProcessContext->IdealProcessor;
//        }
//    }
//    else
//    {
//        RetTeb = NULL;
//    }
//
//    if (!(*ProcessFlags & 0x40))
//    {
//        ExAcquirePushLockExclusive((PULONG_PTR)&CurrentProcess->ProcessLock);
//    }
//
//    if (GroupAffinity)
//    {
//        Job = CurrentProcess->Job;
//        if (Job)
//        {
//            ExAcquireResourceSharedLite(&Job->JobLock, 1u);
//            if (Job->LimitFlags & 0x10)
//            {
//                AffinityMask = Job->Affinity.Bitmap[GroupAffinity->Group];
//                if (!AffinityMask || (AffinityMask & GroupAffinity->Mask) != GroupAffinity->Mask)
//                {
//                    AffinityMask2 = 4;
//                }
//            }
//        }
//    }
//    else
//    {
//        Job = NULL;
//    }
//
//    if (!(AffinityMask2 & 4)
//        && (CurrentProcess->Flags & PS_PROCESS_FLAGS_CREATE_FAILED)
//        && !(CurrentProcess->Flags & PS_PROCESS_FLAGS_PROCESS_DELETE)
//        && (!(CurrentProcess->Flags & PS_PROCESS_FLAGS_EXECUTE_SPARE1)
//            || Thread->Tcb.MiscFlags & PS_MISC_FLAGS_SYSTEM_THREAD
//            || *ProcessFlags & 2))
//    {
//        KeStartThread(Thread, GroupAffinity, IdealProcessor);
//        if (Job)
//            ExReleaseResourceLite(&Job->JobLock);
//        if (CurrentProcess->Flags & PS_PROCESS_FLAGS_EXECUTE_SPARE1)
//        {
//            ProcessFlags2 = *ProcessFlags;
//            if (*ProcessFlags & 2)
//                Thread->SameThreadPassiveFlags |= 0x80u;
//        }
//        else
//        {
//            ProcessFlags2 = *ProcessFlags;
//        }
//
//        CrossThreadFlags = (CurrentProcess->Flags >> 17) & 0x1C00;
//        Thread->CrossThreadFlags &= 0xFFFFE3FF;
//        Thread->CrossThreadFlags |= CrossThreadFlags;
//        CrossThreadFlags = 2 * (CurrentProcess->Flags2 & 0x7000);
//        Thread->CrossThreadFlags &= 0xFFFF1FFF;
//        Thread->CrossThreadFlags |= CrossThreadFlags;
//        if (++CurrentProcess->ActiveThreads > CurrentProcess->ActiveThreadsHighWatermark)
//            CurrentProcess->ActiveThreadsHighWatermark = CurrentProcess->ActiveThreads;
//        if (CurrentProcess->ActiveThreads == 1)
//        {
//            AffinityMask2 |= 2u;
//        }
//        else if (CurrentProcess->ActiveThreads == 2
//            && !(CurrentProcess->Flags2 & PS_PROCESS_FLAGS2_STACK_RANDOMIZATION_DISABLED))
//        {
//            _interlockedbittestandset((LONG*)(&CurrentProcess->Flags2), 15u);
//        }
//        //���̲߳��뵽���̵��߳��б�
//        InsertTailList(&CurrentProcess->ThreadListHead, &Thread->ThreadListEntry);
//
//        if (CurrentProcess->Pcb.InstrumentationCallback)
//            _interlockedbittestandset(&Thread->Tcb.Header.Lock, 0x19u);
//        //if (CurrentProcess->CpuQuotaBlock && !(Thread->SameThreadPassiveFlags & 0x60))
//        //{
//        //    AffinityMask2 |= 1u;
//        //}
//        //if (Thread->Tcb.Header.TimerMiscFlags & 0x40)
//        //    ++CurrentProcess->UmsScheduledThreads;
//
//        ExReleasePushLockExclusive((PULONG_PTR)&CurrentProcess->ProcessLock);
//
//        ObReferenceObjectEx(Thread, 2);
//        if (ProcessFlags2 & 1)
//        {
//            __try
//            {
//                KeSuspendThread(&Thread->Tcb);
//            }
//            __except (1)
//            {
//            }
//            if (Thread->CrossThreadFlags & 1)
//                KeForceResumeThread(&Thread->Tcb);
//        }
//
//        if (AffinityMask2 & 1)
//        {
//            while (1)
//            {
//                Apc = (PPSP_CPU_QUOTA_APC)ExAllocatePoolWithQuotaTag((POOL_TYPE)(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE), sizeof(PSP_CPU_QUOTA_APC), 'pAsP');
//                if (Apc)
//                    break;
//                KeDelayExecutionThread(0, 0, PspShortTime);
//            }
//            PspInitializeCpuQuotaApc(Apc, &Thread->Tcb);
//            //Thread->CpuQuotaApc = Apc;
//            Thread->SameThreadPassiveFlags &= 0xFFFFFFDF;
//            Thread->SameThreadPassiveFlags |= 0x40u;
//            _interlockedbittestandset(&Thread->Tcb.Header.Lock, 0x10u);
//        }
//
//        //DbgBreakPoint();
//        a5 = 0;
//        if (!AccessState->PreviousMode || ProcessFlags2 & 0x20)
//        {
//            Process = CurrentProcess;
//            a5 = 1;
//            Status = SeCreateAccessStateEx(
//                NULL,
//                CurrentProcess,
//                &AccessState->AccessState,
//                &AccessState->AuxData,
//                DesiredAccess,
//                &((*(POBJECT_TYPE*)PsThreadType)->TypeInfo.GenericMapping));
//        }
//        else
//        {
//            Status = SeCreateAccessStateEx(
//                NULL,
//                Process,
//                &AccessState->AccessState,
//                &AccessState->AuxData,
//                DesiredAccess,
//                &((*(POBJECT_TYPE*)PsThreadType)->TypeInfo.GenericMapping));
//        }
//
//        if (!NT_SUCCESS(Status))
//        {
//            ObDereferenceObject(Thread);
//        }
//        else
//        {
//            Status = ObInsertObjectEx(Thread, &AccessState->AccessState, DesiredAccess, 0, a5, NULL, NULL);
//            if (NT_SUCCESS(Status))
//            {
//                ObDereferenceObject(Thread);
//                if (Process != CurrentProcess && !(*ProcessFlags & 0x10))
//                    Status = PspAdjustThreadSecurityDescriptor(Thread);
//                if (NT_SUCCESS(Status) && RetTeb)
//                {
//                    __try
//                    {
//                        *RetTeb = Teb;
//                    }
//                    __except (1)
//                    {
//                    }
//                }
//                if (NT_SUCCESS(Status) && ClientID)
//                {
//                    __try
//                    {
//                        *ClientID = Thread->Cid;
//                    }
//                    __except (1)
//                    {
//                    }
//                }
//            }
//            if (!NT_SUCCESS(Status))
//                SeDeleteAccessState(&AccessState->AccessState);
//        }
//
//        if (!NT_SUCCESS(Status))
//        {
//            ExReleasePushLockExclusive((PULONG_PTR)&Thread->ThreadLock);
//            if (*ProcessFlags & 1)
//                KeForceResumeThread(&Thread->Tcb);
//            if (Flag && *Flag)
//            {
//                KeStackAttachProcess(&CurrentProcess->Pcb, &ApcState);
//                if (*Flag & 2)
//                {
//                    tmpInitialTeb = InitialTeb;
//                    RtlFreeUserStack(((PINITIAL_TEB)tmpInitialTeb)->StackAllocationBase);
//                }
//                else
//                {
//                    tmpInitialTeb = (PPS_INITIAL_TEB)InitialTeb;
//                }
//                if (*Flag & 4)
//                    RtlFreeUserStack(((PPS_INITIAL_TEB)tmpInitialTeb)->Wow64StackAllocationBase);
//                KeUnstackDetachProcess(&ApcState);
//            }
//        }
//        else
//        {
//            PspSetCrossThreadFlag(Thread, PS_CROSS_THREAD_FLAGS_DEADTHREAD);
//            ExReleasePushLockExclusive((PULONG_PTR)&Thread->ThreadLock);
//        }
//
//        CreationStatus = STATUS_SUCCESS;
//        ExitStatus = STATUS_SUCCESS;
//        if (AffinityMask2 & 2)
//        {
//            EtwTraceProcess(CurrentProcess, 0x301u);
//            ExitStatus = STATUS_SUCCESS;
//            v42 = (*PspNotifyEnableMask >> 2) & 1;
//            Processa = (*PspNotifyEnableMask >> 2) & 1;
//            if (*PspNotifyEnableMask & 2 || v42)
//            {
//                Object = NULL;
//                boReferenceProcess = FALSE;
//                if (v42)
//                {
//                    CreateInfo.Size = sizeof(PS_CREATE_NOTIFY_INFO);
//                    CreateInfo.Flags = 0;
//                    CreateInfo.ParentProcessId = CurrentProcess->InheritedFromUniqueProcessId;
//                    CreateInfo.CreatingThreadId = ((_ETHREAD*)PsGetCurrentThread())->Cid;
//                    CreateInfo.CreationStatus = STATUS_SUCCESS;
//                    if (CreateProcessContext)
//                    {
//                        FileObject = CreateProcessContext->FileObject;
//                        if (FileObject)
//                        {
//                            Object = CreateProcessContext->FileObject;
//                        }
//                    }
//                    else
//                    {
//                        boReferenceProcess = TRUE;
//                        PsReferenceProcessFilePointer(CurrentProcess, (PVOID*)&Object);
//                        FileObject = (PFILE_OBJECT)Object;
//                    }
//                    CreateInfo.FileObject = FileObject;
//                    if (CreateProcessContext && CreateProcessContext->PresentFlags & 0x20)
//                    {
//                        CreateInfo.ImageFileName = &CreateProcessContext->FileName;
//                        CreateInfo.Flags |= 1u;
//                    }
//                    else
//                    {
//                        CreateInfo.ImageFileName = &FileObject->FileName;
//                    }
//                    if (CreateProcessContext)
//                    {
//                        CapturedProcessParameters = CreateProcessContext->CapturedProcessParameters;
//                        if (CapturedProcessParameters)
//                        {
//                            CreateInfo.CommandLine = &CapturedProcessParameters->CommandLine;
//                        }
//                    }
//                    else
//                    {
//                        CreateInfo.CommandLine = NULL;
//                    }
//                    pCreateInfo = &CreateInfo;
//                }
//                else
//                {
//                    pCreateInfo = NULL;
//                }
//
//
//
//                for (i = 0; i < PSP_MAX_CREATE_PROCESS_NOTIFY; i++)
//                {
//                    Ex_CallBack = &PspCreateProcessNotifyRoutine[i];
//                    CallBack = ExReferenceCallBackBlock(&PspCreateProcessNotifyRoutine[i]);
//                    if (CallBack)
//                    {
//                        if (CallBack->Context)
//                        {
//                            if (Processa)
//                            {
//                                ProcessCallBackEx = (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ExGetCallBackBlockRoutine(CallBack);
//                                //���ý���֪ͨ�ص�
//                                ProcessCallBackEx((PEPROCESS)CurrentProcess,
//                                    CurrentProcess->UniqueProcessId,
//                                    pCreateInfo);
//                            }
//                        }
//                        else
//                        {
//                            ProcessCallBack = (PCREATE_PROCESS_NOTIFY_ROUTINE)ExGetCallBackBlockRoutine(CallBack);
//                            //���ý���֪ͨ�ص�
//                            ProcessCallBack(CurrentProcess->InheritedFromUniqueProcessId,
//                                CurrentProcess->UniqueProcessId,
//                                TRUE);
//                        }
//
//                        //DbgBreakPoint();
//                        ExCallBackPointer = ReadForWriteAccess(&Ex_CallBack->RoutineBlock.Value);
//                        if (((ULONG_PTR)CallBack ^ ExCallBackPointer) >= 0xF)
//                        {
//                            ExReleaseRundownProtection(&CallBack->RundownProtect);
//                        }
//                        else
//                        {
//                            while (1)
//                            {
//                                v51 = ExCallBackPointer;
//                                ExCallBackPointer = _InterlockedCompareExchange64((LONG64*)Ex_CallBack, ExCallBackPointer + 1, ExCallBackPointer);
//                                if (v51 == ExCallBackPointer)
//                                    break;
//                                if (((ULONG_PTR)CallBack ^ ExCallBackPointer) >= 0xF)
//                                {
//                                    ExReleaseRundownProtection(&CallBack->RundownProtect);
//                                }
//                            }
//                        }
//
//                        if (pCreateInfo)
//                        {
//                            if (!NT_SUCCESS(pCreateInfo->CreationStatus))
//                            {
//                                //CreationStatus = pCreateInfo->CreationStatus;
//                                ExitStatus = pCreateInfo->CreationStatus;
//                                PsTerminateProcess(CurrentProcess, pCreateInfo->CreationStatus);
//                                goto LABEL_84;
//                            }
//                        }
//                    }
//                }
//                CreationStatus = ExitStatus;
//            LABEL_84:
//                if (boReferenceProcess)
//                    ObDereferenceObject(Object);
//            }
//        }
//
//        EtwTraceThread(Thread, InitialTeb, TRUE);
//        if (*PspNotifyEnableMask & 8)
//        {
//            for (i = 0; i < PSP_MAX_CREATE_THREAD_NOTIFY; i++)
//            {
//                CallBack = ExReferenceCallBackBlock(&PspCreateThreadNotifyRoutine[i]);
//                if (CallBack != NULL)
//                {
//                    ThreadCallBack = (PCREATE_THREAD_NOTIFY_ROUTINE)ExGetCallBackBlockRoutine(CallBack);
//                    ThreadCallBack(((_EPROCESS*)Thread->Tcb.Process)->UniqueProcessId,
//                        Thread->Cid.UniqueThread,
//                        TRUE);
//                    ExDereferenceCallBackBlock(&PspCreateThreadNotifyRoutine[i], CallBack);
//                }
//            }
//            CreationStatus = ExitStatus;
//        }
//
//        if (NT_SUCCESS(Status))
//        {
//            if (!NT_SUCCESS(CreationStatus))
//            {
//                Status = CreationStatus;
//            }
//            else
//            {
//                Status = PspCreateObjectHandle(Thread, AccessState, *PsThreadType);
//            }
//            SeDeleteAccessState(&AccessState->AccessState);
//            if (NT_SUCCESS(Status))
//            {
//                __try
//                {
//                    *ThreadHandle = AccessState->NewHandle;
//                }
//                __except (1)
//                {
//                    if (AccessState->HandleAttributes & 0x200)
//                    {
//                        ObCloseHandle(AccessState->NewHandle, KernelMode);
//                    }
//                    else
//                    {
//                        if (PsInitialSystemProcess == PsGetCurrentProcess())
//                        {
//                            ObCloseHandle(AccessState->NewHandle, KernelMode);
//                        }
//                        else
//                        {
//                            ObCloseHandle(AccessState->NewHandle, UserMode);
//                        }
//                    }
//                    if (Flag)
//                    {
//                        if (*Flag & 1)
//                        {
//                            KeRaiseUserException(Status);
//                        }
//                    }
//                }
//            }
//            if (!NT_SUCCESS(Status))
//            {
//                if (Thread->Tcb.MiscFlags & PS_MISC_FLAGS_SYSTEM_THREAD)
//                {
//                    _interlockedbittestandset((LONG*)&Thread->CrossThreadFlags, 0);
//                    if (*ProcessFlags & 1)
//                        KeForceResumeThread(&Thread->Tcb);
//                }
//                else
//                {
//                    PspTerminateThreadByPointer(Thread, Status, FALSE);
//                }
//            }
//        }
//        KeReadyThread(&Thread->Tcb);
//    }
//    else
//    {
//        if (Job)
//            ExReleaseResourceLite(&Job->JobLock);
//        ExReleasePushLockExclusive((PULONG_PTR)&CurrentProcess->ProcessLock);
//        ExReleasePushLockExclusive((PULONG_PTR)&Thread->ThreadLock);
//        MmDeleteKernelStack(Thread->Tcb.StackBase, FALSE);
//        Thread->Tcb.InitialStack = NULL;
//        if (Flag)
//        {
//            if (Teb)
//                MmDeleteTeb(CurrentProcess, Teb);
//            if (*Flag)
//            {
//                KeStackAttachProcess(&CurrentProcess->Pcb, &ApcState);
//                if (*Flag & 2)
//                {
//                    tmpInitialTeb = InitialTeb;
//                    RtlFreeUserStack(InitialTeb->StackAllocationBase);
//                }
//                else
//                {
//                    tmpInitialTeb = (PPS_INITIAL_TEB)InitialTeb;
//                }
//                if (*Flag & 4)
//                    RtlFreeUserStack(((PPS_INITIAL_TEB)tmpInitialTeb)->Wow64StackAllocationBase);
//                KeUnstackDetachProcess(&ApcState);
//            }
//        }
//        Status = (CurrentProcess->Flags & 0x40000008) != 0 ? STATUS_PROCESS_IS_TERMINATING : STATUS_UNSUCCESSFUL;
//    }
//    return Status;
//}
//
//BOOLEAN
//KeReadStateThread(
//    IN PKTHREAD Thread
//)
//{
//    //
//    // Return current signal state of thread object.
//    //
//
//    return (BOOLEAN)Thread->Header.SignalState;
//}
//
//EXTERN_C
//NTSTATUS PspCreateThread(_Out_ HANDLE* ThreadHandle,
//    _In_ ACCESS_MASK DesiredAccess,
//    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
//    _In_ HANDLE ProcessHandle,
//    _In_ _EPROCESS* ProcessPointer,
//    _In_ PPSP_CREATE_PROCESS_CONTEXT CreateProcessContext,
//    _In_ PGROUP_AFFINITY GroupAffinity,
//    _Out_ PCLIENT_ID ClientID,
//    _In_ POBJECT_ATTRIBUTES ObjectAttributes2,
//    _In_ PINITIAL_TEB InitialTeb,
//    _In_ ULONG_PTR ProcessFlags,
//    _In_ PKSTART_ROUTINE StartRoutine,
//    _In_ PVOID StartContext,
//    _In_ PUCHAR Flag)
//{
//    NTSTATUS Status = STATUS_SUCCESS;
//
//    outLog("PspCreateThread Process: %s", ((_EPROCESS*)PsGetCurrentProcess())->ImageFileName);
//    outLog("PspCreateThread StartRoutine: %p", StartRoutine);
//    ASSERT(Original_PspCreateThread);
//    Status = Original_PspCreateThread(ThreadHandle,
//        DesiredAccess,
//        ObjectAttributes,
//        ProcessHandle,
//        ProcessPointer,
//        CreateProcessContext,
//        GroupAffinity,
//        ClientID,
//        ObjectAttributes2,
//        InitialTeb,
//        ProcessFlags,
//        StartRoutine,
//        StartContext,
//        Flag);
//    return Status;
//}
//
EXTERN_C
NTSTATUS NtCreateThreadEx(unsigned __int64 a1,
    int a2,
    __int64 a3,
    ULONG_PTR a4,
    __int64 _StartAddress,
    __int64 a6,
    unsigned int a7,
    __int64 a8,
    __int64 a9,
    __int64 a10,
    __int64 a11)
{
    NTSTATUS Status = STATUS_SUCCESS;

    //outLog("NtCreateThreadEx StartRoutine: %p", _StartAddress);

    //if (PsGetCurrentProcessId() == (HANDLE)6480)
    //{
    //    _disable(); //���ж�
    //    game_cr3 = __readcr3();
    //    *(ULONG64*)((UCHAR*)PsGetCurrentProcess() + 0x28) = game_cr3;
    //    _enable();  //���ж�
    //}

    ASSERT(Original_NtCreateThreadEx);
    Status = Original_NtCreateThreadEx(a1,
        a2,
        a3,
        a4,
        _StartAddress,
        a6,
        a7,
        a8,
        a9,
        a10,
        a11);
    return Status;
}

EXTERN_C
NTSTATUS PspCreateThread(HANDLE* ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    _EPROCESS* arg_Process,
    __int64 CreateProcessContext,
    __int64 a7,
    __int64 a8,
    __int64 a9,
    unsigned int a10,
    PKSTART_ROUTINE StartRoutine,
    __int64 a12,
    __int64 a13)
{
    NTSTATUS Status = Original_PspCreateThread(ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        arg_Process,
        CreateProcessContext,
        a7, a8, a9, a10, StartRoutine, a12, a13);
    return Status;
}

NTSTATUS NewPspAllocateThread(_EPROCESS* Process,
    POBJECT_ATTRIBUTES ObjectAttributes,
    unsigned __int8 a3,
    __int64 a4,
    __int64 a5,
    __int64 a6,
    PKSTART_ROUTINE StartRoutine,
    __int64 a8,
    __int64 a9,
    __int64 a10,
    __int64 a11,
    __int64 a12)
{
    NTSTATUS Status = Original_PspAllocateThread(Process, ObjectAttributes, a3, a4, a5, a6, StartRoutine, a8, a9, a10, a11, a12);
    return Status;
}

VOID InsertVirtualHandleList(PVIRTUAL_HANDLE_TABLE_ENTRY entry)
{
    if (entry)
    {
        ExAcquireFastMutex(&g_VirtualHandleList.Mutex);
        InsertNode(&g_VirtualHandleList.list_entry, &entry->list_entry);
        ExReleaseFastMutex(&g_VirtualHandleList.Mutex);
    }
}

VOID CreateVirtualHandleTable(PCLIENT_ID ClientId, _EPROCESS* Process)
{
    PVIRTUAL_HANDLE_TABLE_ENTRY entry = allocate_pool<VIRTUAL_HANDLE_TABLE_ENTRY>();
    entry->id = 0x8bf13889f4bc9949;  //VIRTUAL_HANDLE_TABLE md5��ϣժҪ
    entry->handle = ClientId->UniqueProcess;
    entry->UniqueProcessId = ClientId->UniqueProcess;
    entry->Object = Process;
    InsertVirtualHandleList(entry);
}

NTSTATUS GetVirtualHandleTableByHandle(HANDLE Handle, PVIRTUAL_HANDLE_TABLE_ENTRY handle_table)
{
    PLIST_ENTRY ListHead, NextEntry;
    PVIRTUAL_HANDLE_TABLE_ENTRY entry;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        ExAcquireFastMutex(&g_VirtualHandleList.Mutex);
    }
    
    ListHead = &g_VirtualHandleList.list_entry.ListHead;
    NextEntry = ListHead->Flink;
    while (ListHead != NextEntry)
    {
        entry = CONTAINING_RECORD(NextEntry,
            VIRTUAL_HANDLE_TABLE_ENTRY,
            list_entry);

        if (entry)
        {
            if (entry->handle == Handle)
            {
                *handle_table = *entry;
                status = STATUS_SUCCESS;
                break;
            }
        }

        /* Move to the next entry */
        NextEntry = NextEntry->Flink;
    }

    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        ExReleaseFastMutex(&g_VirtualHandleList.Mutex);
    }
    
    return status;
}


NTSTATUS GetVirtualHandleTableByObject(PVOID Object, PVIRTUAL_HANDLE_TABLE_ENTRY handle_table)
{
    PLIST_ENTRY ListHead, NextEntry;
    PVIRTUAL_HANDLE_TABLE_ENTRY entry;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ExAcquireFastMutex(&g_VirtualHandleList.Mutex);
    ListHead = &g_VirtualHandleList.list_entry.ListHead;
    NextEntry = ListHead->Flink;
    while (ListHead != NextEntry)
    {
        entry = CONTAINING_RECORD(NextEntry,
            VIRTUAL_HANDLE_TABLE_ENTRY,
            list_entry);

        if (entry)
        {
            if (entry->Object == Object)
            {
                *handle_table = *entry;
                status = STATUS_SUCCESS;
                break;
            }
        }

        /* Move to the next entry */
        NextEntry = NextEntry->Flink;
    }
    ExReleaseFastMutex(&g_VirtualHandleList.Mutex);
    return status;
}

NTSTATUS NewObReferenceObjectByHandle(HANDLE Handle, 
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID* Object, 
    POBJECT_HANDLE_INFORMATION HandleInformation)
{
    if (IsDebugger(PsGetCurrentProcess()) /*&&
        (ObjectType == *PsProcessType)*/)
    {
        AccessMode = KernelMode;
        //*Object = NULL;
        //VIRTUAL_HANDLE_TABLE_ENTRY handle_table = { 0 };
        //NTSTATUS status = GetVirtualHandleTableByHandle(Handle, &handle_table);
        //if (NT_SUCCESS(status))
        //{
        //    POBJECT_HEADER ObjectHeader;
        //    ObjectHeader = OBJECT_TO_OBJECT_HEADER(handle_table.Object);
        //    ObjectHeader->PointerCount++;
        //    *Object = handle_table.Object;
        //    return STATUS_SUCCESS;
        //}
    }

    //_EPROCESS* Process;

    //if (ObjectType == *PsProcessType)
    //{
    //    NTSTATUS Status = PsLookupProcessByProcessId(Handle, (PEPROCESS*)&Process);
    //    if (NT_SUCCESS(Status))
    //    {
    //        *Object = Process;
    //        return STATUS_SUCCESS;
    //    }
    //}

    return Original_ObReferenceObjectByHandle(Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation);
}

NTSTATUS NewObReferenceObjectByHandleWithTag(HANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    int a5,
    PVOID* Object,
    __int64 a7)
{
    if (IsDebugger(PsGetCurrentProcess()) /* &&
        (ObjectType == *PsProcessType)*/)
    {
        AccessMode = KernelMode;
    }

    return Original_ObReferenceObjectByHandleWithTag(Handle, DesiredAccess, ObjectType, AccessMode, a5, Object, a7);
}

//ObReferenceObjectByHandle��ObReferenceObjectByHandleWithTag�����ڲ�
//�����õ�ObpReferenceObjectByHandleWithTag
NTSTATUS NewObpReferenceObjectByHandleWithTag(HANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    ULONG Tag,
    PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation,
    __int64 a8)
{
    //�ж��Ƿ�Ϊ����������̵���
    if (IsDebugger(PsGetCurrentProcess()) /* &&
    (ObjectType == *PsProcessType)*/)
    {
        AccessMode = KernelMode;
    }

    NTSTATUS ntStatus = Original_ObpReferenceObjectByHandleWithTag(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, a8);
    if (NT_SUCCESS(ntStatus) && (ObjectType == *PsProcessType))
    {        
        // �жϵ�ǰ�������Ƿ��ǵ���������
        if (!IsDebugger(PsGetCurrentProcess()))
        {
            //�жϷ��ʵĶ����Ƿ������ǵĵ�����
            if (IsDebugger(*(PEPROCESS*)Object))
            {
                //��ȡ��ǰ���ý���
                WCHAR SubStr[256] = { 0 };
                UNICODE_STRING ImageFileName, PassImage;
                NTSTATUS Status = GetProcessName(PsGetCurrentProcess(), &SubStr[0]);
                if (NT_SUCCESS(Status))
                {
                    RtlInitUnicodeString(&ImageFileName, SubStr);
                    for (ULONG i = 0; i < sizeof(PassProcessList) / sizeof(PassProcessList[0]); i++)
                    {
                        RtlInitUnicodeString(&PassImage, PassProcessList[i]);
                        if (RtlEqualUnicodeString(&ImageFileName, &PassImage, TRUE))
                        {
                            //�����ǰ��������̾ͷ���
                            goto pass;
                        }
                    }

                    *(PEPROCESS*)Object = NULL;
                    ntStatus = STATUS_UNSUCCESSFUL;
                    //PrintProcessName((_EPROCESS*)PsGetCurrentProcess());
                }
            }
        }
    }
pass:
    return ntStatus;
}

LONG_PTR NewObfDereferenceObject(
    _In_ PVOID Object
)
{
    if (IsDebugger(PsGetCurrentProcess()))
    {
        //POBJECT_HEADER ObjectHeader;
        //ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
        //outLog("ָ�����: %d", ObjectHeader->PointerCount);
        //outLog("�������: %d", ObjectHeader->HandleCount);
        VIRTUAL_HANDLE_TABLE_ENTRY handle_table = { 0 };
        NTSTATUS status = GetVirtualHandleTableByObject(Object, &handle_table);
        if (NT_SUCCESS(status))
        {
            //DbgBreakPoint();
            return 0;
        }
    }
    return Original_ObfDereferenceObject(Object);
}

LONG_PTR NewObfDereferenceObjectWithTag(
    _In_ PVOID Object,
    _In_ ULONG Tag
)
{
    if (IsDebugger(PsGetCurrentProcess()))
    {
        //POBJECT_HEADER ObjectHeader;
        //ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
        //outLog("ָ�����: %d", ObjectHeader->PointerCount);
        //outLog("�������: %d", ObjectHeader->HandleCount);
        VIRTUAL_HANDLE_TABLE_ENTRY handle_table = { 0 };
        NTSTATUS status = GetVirtualHandleTableByObject(Object, &handle_table);
        if (NT_SUCCESS(status))
        {
            //DbgBreakPoint();
            return 0;
        }
    }
    return Original_ObfDereferenceObjectWithTag(Object, Tag);
}

NTSTATUS NewNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    if (IsDebugger(PsGetCurrentProcess()))
    {
//        _EPROCESS* Process;
//        NTSTATUS Status = PsLookupProcessByProcessId(ClientId->UniqueProcess, (PEPROCESS*)&Process);
//        if (NT_SUCCESS(Status))
//        {
//            Status = Original_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
//
///*            PrintProcessName(Process);
//            outLog("ProcessHandle: %d", ProcessHandle);    */        
//            if (Process)
//            {
//                ObDereferenceObject(Process);
//            }
//
//            return Status;
//
//            //VIRTUAL_HANDLE_TABLE_ENTRY handle_table = { 0 };
//            //Status = GetVirtualHandleTableByObject(Process, &handle_table);
//            //if (!NT_SUCCESS(Status))
//            //{
//            //    CreateVirtualHandleTable(ClientId, Process);
//            //}
//
//            //if (Process)
//            //{
//            //    ObDereferenceObject(Process);
//            //}
//
//            ////��Ŀ����̵�pid��Ϊ����������
//            //*ProcessHandle = ClientId->UniqueProcess;
//            //return STATUS_SUCCESS;
//        }
//        else
//        {
//            outLog("PsLookupProcessByProcessId ʧ��.");
//        }
    }
    return Original_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//���ApcFunc���õ���LdrInitializeThunk��
//a4��ContextRecord
//a5��ntdllģ���ַ
VOID NewPspCreateUserContext(_CONTEXT* context,
    char a2,
    PVOID ApcFunc,
    PVOID a4,
    __int64 a5)
{
    __try
    {
    }
    __except (1)
    {

    } 
    return Original_PspCreateUserContext(context, a2, ApcFunc, a4, a5);
}

VOID NewPspCallThreadNotifyRoutines(_ETHREAD* Thread, BOOLEAN Create, BOOLEAN a3)
{
    //DbgBreakPoint();
    if (IsDebugger(PsGetCurrentProcess()))
    {
        //�������Լ��ĵ�����Ҫ�����̣߳���ֱ�ӷ��ز����̻߳ص�
        return;
    }
    Original_PspCallThreadNotifyRoutines(Thread, Create, a3);
}

NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG flNewProtect, PULONG flOldProtect)
{
    NTSTATUS status = Original_NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, flNewProtect, flOldProtect); 
    return status;
}

size_t g_ptrLongFlags = NULL;

PMMVAD MiObtainReferencedVadEx(PVOID StartingAddress, char a2, PNTSTATUS status)
{
    PMMVAD FoundVad = Original_MiObtainReferencedVadEx(StartingAddress, a2, status);
    if (FoundVad)
    {
        PDEBUG_PROCESS DebugProcess;
        _EPROCESS* Process = (_EPROCESS*)PsGetCurrentProcess();

        if (IsDebugTargetProcess(Process, &DebugProcess))
        {
            //DbgBreakPoint();
            size_t ptr_LongFlags = (size_t)FoundVad + mmvad_short_offset::LongFlags;
            unsigned long LongFlags = *(unsigned long*)ptr_LongFlags;
            //DbgPrint("LongFlags: %X\n", LongFlags);
            if (LongFlags == 0x188)
            {
                //*(unsigned long*)ptr_LongFlags = 0x3A0;
                g_ptrLongFlags = ptr_LongFlags;
            }
            //if (LongFlags & 8)  //�ж�bit3 NoChange�Ƿ�����
            //{
            //    //���VadFlags.NoChange����������ر�
            //    unsigned long mask = ~(1UL << 3);  // �������룬bit3Ϊ0������λΪ1
            //    LongFlags &= mask;  // ��bit3����Ϊ0
            //    *(unsigned long*)ptr_LongFlags = LongFlags;
            //}
        }
    }
    return FoundVad;
}

NTSTATUS MmProtectVirtualMemory(_EPROCESS* sourceProcess,
    _EPROCESS* TargetProcess,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    WIN32_PROTECTION_MASK NewProtectWin32,
    PWIN32_PROTECTION_MASK LastProtect)
{
    //ExAcquireFastMutex(&LongFlagsMutex);
    
    NTSTATUS status = Original_MmProtectVirtualMemory(sourceProcess, TargetProcess, BaseAddress, RegionSize, NewProtectWin32, LastProtect);

    if (status == STATUS_INVALID_PAGE_PROTECTION)
    {
        if (IsDebugger((PEPROCESS)sourceProcess))
        {
            if (g_ptrLongFlags)
            {
                if (*(unsigned long*)g_ptrLongFlags == 0x188)
                {
                    *(unsigned long*)g_ptrLongFlags = 0x3A0;

                    status = Original_MmProtectVirtualMemory(sourceProcess, TargetProcess, BaseAddress, RegionSize, NewProtectWin32, LastProtect);
                    //��ԭ
                    *(unsigned long*)g_ptrLongFlags = 0x188;
                    g_ptrLongFlags = NULL;
                }
            }
        }
    }
    //ExReleaseFastMutex(&LongFlagsMutex);
    return status;
}

VOID
NewKeStackAttachProcess(
    _Inout_ PRKPROCESS PROCESS,
    _Out_ PRKAPC_STATE ApcState
)
{
    if (IsDebugger((PEPROCESS)PROCESS))
    {
        //��ȡ��ǰ���ý���
        WCHAR SubStr[256] = { 0 };
        UNICODE_STRING ImageFileName, PassImage;
        NTSTATUS Status = GetProcessName(PsGetCurrentProcess(), &SubStr[0]);
        if (NT_SUCCESS(Status))
        {
            RtlInitUnicodeString(&ImageFileName, SubStr);
            for (ULONG i = 0; i < sizeof(PassProcessList) / sizeof(PassProcessList[0]); i++)
            {
                RtlInitUnicodeString(&PassImage, PassProcessList[i]);
                if (RtlEqualUnicodeString(&ImageFileName, &PassImage, TRUE))
                {
                    //�����ǰ��������̾ͷ���
                    goto pass;
                }
            }
        }

        ApcState->Process = (PKPROCESS)1;
        return;
    }
pass:
    Original_KeStackAttachProcess(PROCESS, ApcState);
}

VOID NewKiStackAttachProcess(_KPROCESS* Process, BOOLEAN a2, _KAPC_STATE* ApcState)
{
    if (IsDebugger((PEPROCESS)Process))
    {
        //��ȡ��ǰ���ý���
        WCHAR SubStr[256] = { 0 };
        UNICODE_STRING ImageFileName, PassImage;
        NTSTATUS Status = GetProcessName(PsGetCurrentProcess(), &SubStr[0]);
        if (NT_SUCCESS(Status))
        {
            RtlInitUnicodeString(&ImageFileName, SubStr);
            for (ULONG i = 0; i < sizeof(PassProcessList) / sizeof(PassProcessList[0]); i++)
            {
                RtlInitUnicodeString(&PassImage, PassProcessList[i]);
                if (RtlEqualUnicodeString(&ImageFileName, &PassImage, TRUE))
                {
                    //�����ǰ��������̾ͷ���
                    goto pass;
                }
            }
        }

        ApcState->Process = (PKPROCESS)1;
        return;
    }
pass:
    Original_KiStackAttachProcess(Process, a2, ApcState);
}

NTSTATUS
NewNtTerminateProcess(
    __in_opt HANDLE ProcessHandle,
    __in NTSTATUS ExitStatus
)
{
    _EPROCESS* Process;
    NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle,
        PROCESS_ALL_ACCESS,
        *PsProcessType,
        KernelMode,
        (PVOID*)&Process,
        NULL);
    if (NT_SUCCESS(Status))
    {
        //DbgPrint("Ҫ��ֹ�Ľ���:\n");
        //PrintProcessName(Process);
        //DbgPrint("��ǰ����:\n");
        //PrintProcessName((_EPROCESS*)PsGetCurrentProcess());

        ObDereferenceObject(Process);
    }    
    return Original_NtTerminateProcess(ProcessHandle, ExitStatus);
}

NTSTATUS
NewNtSuspendThread(
    __in HANDLE ThreadHandle,
    __out_opt PULONG PreviousSuspendCount
)
{
    _ETHREAD* Thread;
    NTSTATUS ntStatus = Original_NtSuspendThread(ThreadHandle, PreviousSuspendCount);

    KPROCESSOR_MODE Mode = KeGetPreviousMode();

    __try {

        if (Mode != KernelMode) {
            if (ARGUMENT_PRESENT(PreviousSuspendCount)) {
                ProbeForRead(PreviousSuspendCount, sizeof(ULONG), sizeof(PULONG));

                NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle,
                    THREAD_ALL_ACCESS,
                    *PsThreadType,
                    KernelMode,
                    (PVOID*)&Thread,
                    NULL);
                if (NT_SUCCESS(Status))
                {
                    _EPROCESS* pProcess = (_EPROCESS*)PsGetThreadProcess((PETHREAD)Thread);
                    WCHAR SubStr[256] = { 0 };
                    UNICODE_STRING ImageFileName, PassImage;
                    NTSTATUS Status = GetProcessName((PEPROCESS)pProcess, &SubStr[0]);
                    if (NT_SUCCESS(Status))
                    {
                        RtlInitUnicodeString(&ImageFileName, SubStr);
                        RtlInitUnicodeString(&PassImage, L"TL.exe");
                        if (RtlEqualUnicodeString(&ImageFileName, &PassImage, TRUE))
                        {
                            size_t ptr_SuspendCount = (size_t)Thread + kthread_offset::SuspendCount;
                            DbgPrint("ptr_SuspendCount: %p    CurrentSuspendCount: %d\n", ptr_SuspendCount, *(char*)ptr_SuspendCount);
                            //DbgPrint("ntStatus: %x    PreviousSuspendCount: %d\n", ntStatus, *PreviousSuspendCount);
                        }
                    }


                    ObDereferenceObject(Thread);
                }                
            }
        }
    } 
    __except(EXCEPTION_EXECUTE_HANDLER) {

        return GetExceptionCode();
    }    
    return ntStatus;
}

NTSTATUS
NewNtResumeThread(
    __in HANDLE ThreadHandle,
    __out_opt PULONG PreviousSuspendCount
)
{
    _ETHREAD* Thread;

    //UNICODE_STRING ImageFileName, PassImage;
    //NTSTATUS Status = GetProcessName(PsGetCurrentProcess(), &ImageFileName);
    //if (NT_SUCCESS(Status))
    //{
    //    RtlInitUnicodeString(&PassImage, L"TL.exe");
    //    if (RtlEqualUnicodeString(&ImageFileName, &PassImage, TRUE))
    //    {
    //        DbgPrint("��ǰ��������TL  ��ǰ�����߳�: %d", PsGetCurrentThreadId());
    //        //return STATUS_SUCCESS;
    //    }
    //}


    if (PsGetCurrentProcessId() == (HANDLE)g_TL_Game_pid)
    {
        //��ֹTL Game�ָ���Ϸ�߳�
        DbgPrint("��ǰ��������TL  ��ǰ�����߳�: %d", PsGetCurrentThreadId());
        return STATUS_SUCCESS;
    }

    NTSTATUS ntStatus = Original_NtResumeThread(ThreadHandle, PreviousSuspendCount);

    //__try {

    //    KPROCESSOR_MODE Mode = KeGetPreviousMode();
    //    if (Mode != KernelMode) {
    //        if (ARGUMENT_PRESENT(PreviousSuspendCount)) {
    //            ProbeForRead(PreviousSuspendCount, sizeof(ULONG), sizeof(PULONG));

    //            NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle,
    //                THREAD_ALL_ACCESS,
    //                *PsThreadType,
    //                KernelMode,
    //                (PVOID*)&Thread,
    //                NULL);
    //            if (NT_SUCCESS(Status))
    //            {
    //                _EPROCESS* pProcess = (_EPROCESS*)PsGetThreadProcess((PETHREAD)Thread);
    //                UNICODE_STRING ImageFileName, PassImage;
    //                NTSTATUS Status = GetProcessName((PEPROCESS)pProcess, &ImageFileName);
    //                if (NT_SUCCESS(Status))
    //                {
    //                    RtlInitUnicodeString(&PassImage, L"TL.exe");
    //                    if (RtlEqualUnicodeString(&ImageFileName, &PassImage, TRUE))
    //                    {
    //                        *PreviousSuspendCount = 0;
    //                        DbgPrint("ntStatus: %x    PreviousSuspendCount: %d\n", ntStatus, *PreviousSuspendCount);
    //                        PrintProcessName((_EPROCESS*)PsGetCurrentProcess());
    //                    }
    //                }
    //                ObDereferenceObject(Thread);
    //            }

    //        }
    //    }
    //}
    //__except (EXCEPTION_EXECUTE_HANDLER) {
    //    return ntStatus;
    //}
    return ntStatus;
}


NTSTATUS
NewNtQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
)
{
    if (ThreadInformationClass == ThreadSuspendCount)
    {
        PrintProcessName((_EPROCESS*)PsGetCurrentProcess());
        return STATUS_UNSUCCESSFUL;
    }
    return Original_NtQueryInformationThread(ThreadHandle, 
        ThreadInformationClass, 
        ThreadInformation,
        ThreadInformationLength,
        ReturnLength);
}

HANDLE NewNtUserQueryWindow(
    IN HWND hwnd,
    IN WINDOWINFOCLASS WindowInfo)
{
    ////�жϵ�ǰ�������Ƿ��ǵ���������
    //if (!IsDebugger(PsGetCurrentProcess()))
    //{
    //    //���ݴ��ھ����ô��ڶ���
    //    PWND pwnd = Sys_ValidateHwnd(hwnd);
    //    if (pwnd)
    //    {
    //        //�����̶߳����ý��̶���
    //        PsGetThreadProcess((PETHREAD)pwnd->head.pti->pEThread);
    //    }
    //}
    //NtUserQueryWindow(hwnd, WindowInfo);
    return NULL;
}

VOID PrintProcessName(_EPROCESS* Process)
{
    size_t ptr_ImageFileName = (size_t)Process + eprocess_offset::ImageFileName;
    //outLog("��ӡ������: %s", ptr_ImageFileName);
    DbgPrint("��ӡ������: %s  pid: %d\n", ptr_ImageFileName, PsGetProcessId((PEPROCESS)Process));
}