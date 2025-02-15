#include "../Driver.h"
#include "../ntos/inc/ntosdef.h"
#include "../ntos/inc/ketypes.h"
#include "../ntos/inc/amd64.h"
#include "../ntos/inc/extypes.h"
#include "../ntos/inc/mi.h"
#include "../ntos/inc/pstypes.h"
#include "../ntos/inc/obtypes.h"
#include "../ntos/inc/peb_teb.h"
#include "../ntos/inc/mmtypes.h"
#include "../ntos/inc/ntdbg.h"
#include "../List/MyList.h"
#include "../ntos/inc/ntlpcapi.h"
#include "../ntos/inc/ke.h"
#include "../ntos/inc/ki.h"
#include "../ntos/inc/pecoff.h"
#include "../Log/log.h"
#include "../ntos/inc/psp.h"
#include "../Globals.h"
#include "../Encrypt/Blowfish/Blowfish.h"
#include "../Hvm/AsmCallset.h"
#include "../Hvm/vmcall_reason.h"
#include "DebugBreak.h"

bool vmcall_internal(PVOID vmcallinfo)
{
    unsigned long ecode = 0;
    bool boSuccess = false;
    __try {
        //����vmxģʽ���ָ��ᴥ��#UD�쳣
        boSuccess = __vm_call(((PVMCALLINFO)vmcallinfo)->command, (unsigned __int64)vmcallinfo, 0, 0);
    }
    __except (ecode = GetExceptionCode(), 1) {
        outToFile("ִ��vmcallʱ�����˴��� (error: 0x%X)", ecode);
    }
    return boSuccess;
}

//ֻ����ǰ�߼���������������
bool current_vmcall(PVOID vmcallinfo)
{
    return vmcall_internal(vmcallinfo);
}

bool AddHardwareBreakpoint(PBREAKPOINT_RECORD Breakpoint)
{
    bool boSuccess = false;
    VT_BREAK_POINT vmcallinfo = { 0 };
    vmcallinfo.cr3 = Breakpoint->cr3;
    vmcallinfo.VirtualAddress = Breakpoint->Address;
    vmcallinfo.Size = Breakpoint->length;
    vmcallinfo.command = Breakpoint->command;
    vmcallinfo.CPUCount = Breakpoint->CPUCount;
    vmcallinfo.LoopUserMode = Breakpoint->LoopUserMode;
    vmcallinfo.watchid = -1;

    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)Breakpoint->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);
            //outToFile("��ֵ: %X", *(BYTE*)Breakpoint->Address);
            //outToFile("��ַ: %p", Breakpoint->Address);
            //outToFile("cr3: %p", __readcr3());

            //apexʹ���˼�cr3��ͨ���˽���������Ի����ʵ��cr3
            //���Ƕ�Ŀ���ַ��ȡһ���ֽڵ����ݣ��Ӷ�ʹ��ϵͳ����#GP�쳣
            //eac�����쳣��ӹ�#GP�쳣���Ӷ��ָ���ʵ��cr3��cr3�Ĵ���
            //Ȼ��ص�����#GP�쳣��ָ�������ִ�У��ʶ����Ǳ��ڴ�ʱ�л�������ʵ��cr3
            *(volatile BYTE*)Breakpoint->Address;  //volatile�ؼ��ֿ��Բ���Release�Ż�
            _disable(); //���ж�
            vmcallinfo.cr3 = __readcr3();
            _enable();  //���ж�
            boSuccess = current_vmcall(&vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outToFile("����Ӳ���ϵ�ʱ������");
        }

        Breakpoint->watchid = vmcallinfo.watchid;

        if (!boSuccess)
        {
            outLog("current_vmcall ʧ��!");
        }
        else
        {
            outLog("current_vmcall �ɹ�!  errorCode:%d", vmcallinfo.errorCode);
        }
        ObDereferenceObject(Process);
    }
    return boSuccess;
}

void SetHardwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PBREAKPOINT_RECORD output = (PBREAKPOINT_RECORD)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(BREAKPOINT_RECORD));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(BREAKPOINT_RECORD);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PBREAKPOINT_RECORD pInfo = reinterpret_cast<PBREAKPOINT_RECORD>(aucPlainText + i * sizeof(BREAKPOINT_RECORD));

        if (AddHardwareBreakpoint(pInfo))
        {
            *output = *pInfo;
        }
        break;
    }
    free_pool(aucPlainText);
}

bool DeleteHardwareBreakpoint(PBREAKPOINT_RECORD Breakpoint)
{
    bool boSuccess = false;
    VT_BREAK_POINT vmcallinfo = { 0 };
    vmcallinfo.cr3 = Breakpoint->cr3;
    vmcallinfo.VirtualAddress = Breakpoint->Address;
    vmcallinfo.Size = Breakpoint->length;
    vmcallinfo.command = VMCALL_WATCH_DELETE;
    vmcallinfo.LoopUserMode = Breakpoint->LoopUserMode;
    vmcallinfo.watchid = Breakpoint->watchid;
    vmcallinfo.CPUCount = Breakpoint->CPUCount;

    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)Breakpoint->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);

            //apexʹ���˼�cr3��ͨ���˽���������Ի����ʵ��cr3
            //���Ƕ�Ŀ���ַ��ȡһ���ֽڵ����ݣ��Ӷ�ʹ��ϵͳ����#GP�쳣
            //eac�����쳣��ӹ�#GP�쳣���Ӷ��ָ���ʵ��cr3��cr3�Ĵ���
            //Ȼ��ص�����#GP�쳣��ָ�������ִ�У��ʶ����Ǳ��ڴ�ʱ�л�������ʵ��cr3
            *(volatile BYTE*)Breakpoint->Address;  //volatile�ؼ��ֿ��Բ���Release�Ż�
            _disable(); //���ж�
            vmcallinfo.cr3 = __readcr3();
            _enable();  //���ж�
            boSuccess = current_vmcall(&vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outToFile("ɾ��Ӳ���ϵ�ʱ������");
        }
        ObDereferenceObject(Process);
    }
    return boSuccess;
}

//�Ƴ�Ӳ���ϵ�
void RemoveHardwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    DWORD* output = (DWORD*)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(DWORD));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(BREAKPOINT_RECORD);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PBREAKPOINT_RECORD pInfo = reinterpret_cast<PBREAKPOINT_RECORD>(aucPlainText + i * sizeof(BREAKPOINT_RECORD));

        if (DeleteHardwareBreakpoint(pInfo))
        {
            *output = 1998;  //�ɹ�
        }
        else
        {
            *output = 520;   //ʧ��
        }
        break;
    }
    free_pool(aucPlainText);
}

//�������ϵ�
bool AddSoftwareBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    bool boSuccess = false;
    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)vmcallinfo->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);
            *(volatile BYTE*)vmcallinfo->VirtualAddress;  //volatile�ؼ��ֿ��Բ���Release�Ż�
            _disable(); //���ж�
            vmcallinfo->cr3 = __readcr3();
            _enable();  //���ж�
            boSuccess = current_vmcall(vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outToFile("��������ϵ�ʱ������");
        }
        ObDereferenceObject(Process);
    }
    return boSuccess;
}

void SetSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PVT_BREAK_POINT output = (PVT_BREAK_POINT)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(VT_BREAK_POINT));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(VT_BREAK_POINT);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PVT_BREAK_POINT pInfo = reinterpret_cast<PVT_BREAK_POINT>(aucPlainText + i * sizeof(VT_BREAK_POINT));

        if (AddSoftwareBreakpoint(pInfo))
        {
            *output = *pInfo;
        }
        break;
    }
    free_pool(aucPlainText);
}

bool DeleteSoftwareBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    bool boSuccess = false;
    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)vmcallinfo->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);
            *(volatile BYTE*)vmcallinfo->VirtualAddress;  //volatile�ؼ��ֿ��Բ���Release�Ż�
            _disable(); //���ж�
            vmcallinfo->cr3 = __readcr3();
            _enable();  //���ж�
            boSuccess = current_vmcall(vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outToFile("ɾ������ϵ�ʱ������");
        }
        ObDereferenceObject(Process);
    }
    return boSuccess;
}

//�Ƴ�����ϵ�
void RemoveSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    DWORD* output = (DWORD*)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(DWORD));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(VT_BREAK_POINT);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PVT_BREAK_POINT pInfo = reinterpret_cast<PVT_BREAK_POINT>(aucPlainText + i * sizeof(VT_BREAK_POINT));

        if (DeleteSoftwareBreakpoint(pInfo))
        {
            *output = 1998;  //�ɹ�
        }
        else
        {
            *output = 520;   //ʧ��
        }
        break;
    }
    free_pool(aucPlainText);
}

bool GetSoftwareBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    bool boSuccess = false;
    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)vmcallinfo->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);
            *(volatile BYTE*)vmcallinfo->VirtualAddress;  //volatile�ؼ��ֿ��Բ���Release�Ż�
            _disable(); //���ж�
            vmcallinfo->cr3 = __readcr3();
            _enable();  //���ж�
            boSuccess = current_vmcall(vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outToFile("������ϵ�ʱ������");
        }
        ObDereferenceObject(Process);
    }
    if (boSuccess)
    {
        vmcallinfo->errorCode = 1998;
    }
    return boSuccess;
}

//��int3�ϵ�
void ReadSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PVT_BREAK_POINT output = (PVT_BREAK_POINT)pIrp->AssociatedIrp.SystemBuffer;  //�ں˵Ļ�����������������õ����
    RtlZeroMemory(output, sizeof(VT_BREAK_POINT));

    //�������Ļ�����
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // �������Ļ������еĽṹ������
    size_t numElements = user.uSize / sizeof(VT_BREAK_POINT);

    // �������Ļ������еĽṹ��
    for (size_t i = 0; i < numElements; i++)
    {
        PVT_BREAK_POINT pInfo = reinterpret_cast<PVT_BREAK_POINT>(aucPlainText + i * sizeof(VT_BREAK_POINT));

        if (GetSoftwareBreakpoint(pInfo))
        {
            *output = *pInfo;  //�ɹ�
        }
        break;
    }
    free_pool(aucPlainText);
}