#include "Driver.h"
#include "poolmanager.h"
#include "Globals.h"
#include "mtrr.h"
#include "EPT.h"
#include "hypervisor_routines.h"
#include "vmm.h"
#include "hypervisor_gateway.h"
#include "interrupt.h"
#include "Init/Symbolic/InitNtoskrnl.h"
#include "AsmCallset.h"
#include "vmexit_handler.h"
#include "vmcs.h"

EXTERN_C
VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_vmm_context.vcpu[0].vcpu_status.vmm_launched == true)
    {
        hvgt::ept_unhook();
        hvgt::vmoff(g_vmm_context.processor_count);
    }

    hv::disable_vmx_operation();
    free_vmm_context();

    KdPrint(("Driver Unload!!!\n"));
}

//����vt����������ʹ��Windows�ں˵�api����
//��ο�vmexit_handler����
EXTERN_C
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = Unload;
    KdPrint(("DriverEntry!!!\n"));
    

    NTSTATUS nStatus = STATUS_SUCCESS;

    if (InitNtoskrnlSymbolsTable())
    {
        //
        // Check if our cpu support virtualization
        //
        if (!hv::virtualization_support()) {
            outDebug("VMX operation is not supported on this processor.\n");
            return STATUS_UNSUCCESSFUL;
        }

        //
        // Initialize and start virtual machine
        // If it fails turn off vmx and deallocate all structures
        // ��ʼ�� ����װvt
        //

        hv::InitGlobalVariables();
        if (vmm_init() == false)
        {
            hv::disable_vmx_operation();
            free_vmm_context();
            outDebug("Vmm initialization failed");
            return STATUS_UNSUCCESSFUL;
        }
        outDebug("�������سɹ�!!!\n");
    }
    else
    {
        nStatus = STATUS_UNSUCCESSFUL;
        outDebug("��������ʧ��!!!\n");
    }
    return nStatus;
}

bool InitOffset(PWINDOWS_STRUCT vmcallinfo)
{
    WINDOWS_STRUCT tmp_vmcallinfo = { 0 };

    if (sizeof(WINDOWS_STRUCT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(WINDOWS_STRUCT)))
    {
        //��ȡ���ݿ��ܲ�����
        return false;
    }

    hv::ghv.kpcr_pcrb_offset = 0x180;
    hv::ghv.kprcb_current_thread_offset = 0x8;
    ethread_offset::Cid = tmp_vmcallinfo.ethread_offset_Cid;
    return true;
}

PCLIENT_ID GuestCurrentThreadCid()
{
    size_t Thread = hv::current_guest_ethread();
    size_t ptr_Cid = Thread + ethread_offset::Cid;
    return (PCLIENT_ID)ptr_Cid;
}

bool SetBreakpoint(PVT_BREAK_POINT vmcallinfo, unsigned __int64 Type)
{
    int errorCode = 0;
    int status = 0;
    VT_BREAK_POINT tmp_vmcallinfo = { 0 };

    if (sizeof(VT_BREAK_POINT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
    {
        //��ȡ���ݿ��ܲ�����
        return false;
    }

    int outID = -1;
    if (ept::ept_watch_activate(tmp_vmcallinfo, Type, &outID, errorCode))
    {
        tmp_vmcallinfo.watchid = outID;

        if (sizeof(VT_BREAK_POINT) != hv::write_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
        {
            //д�����ݿ��ܲ�����
            return false;
        }
        return true;
    }
    else
    {
        tmp_vmcallinfo.errorCode = errorCode;

        if (sizeof(VT_BREAK_POINT) != hv::write_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
        {
            //д�����ݿ��ܲ�����
            return false;
        }
    }
    return false;
}

bool RemoveBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    VT_BREAK_POINT tmp_vmcallinfo = { 0 };

    if (sizeof(VT_BREAK_POINT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
    {
        //��ȡ���ݿ��ܲ�����
        return false;
    }

    if (ept::ept_watch_deactivate(tmp_vmcallinfo, tmp_vmcallinfo.watchid) == 0)
    {
        return true;
    }

    return false;
}

void MyKeBugCheck(
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR BugCheckParameter1,
    _In_ ULONG_PTR BugCheckParameter2,
    _In_ ULONG_PTR BugCheckParameter3,
    _In_ ULONG_PTR BugCheckParameter4
)
{
    //__vmx_off();                                  // �˳�vmxģʽ
    //__writecr3(g_guest_cr3);                      // ��ԭcr3
    //__reload_gdtr(g_gdtr.base_address, g_gdtr.limit); // ��ԭgdt
    //__lidt(&g_idtr);                                 // ��ԭidt 
    KeBugCheckEx(BugCheckCode, BugCheckParameter1, BugCheckParameter2, BugCheckParameter3, BugCheckParameter4);// ��������dump
}