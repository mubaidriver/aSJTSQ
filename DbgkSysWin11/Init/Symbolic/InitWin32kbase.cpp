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
#include "../../ntos/inc/psp.h"
#include "../../Globals.h"
#include "../../DbgkApi/DbgkApi.h"
#include "../../Log/log.h"
#include "../../Hooks/EptHook/EptHook.h"
#include "InitSymbolic.h"
#include "InitWin32kbase.h"
#include "../../Encrypt/Blowfish/Blowfish.h"
#include "../../Hvm/vmcall_reason.h"
#include "../../Hvm/hypervisor_gateway.h"

BOOLEAN InitWin32kbaseSymbolsTable()
{
    //��ǰ�̱߳�����gui�̲߳��ܷ���win32k���ڴ�
    symbolic_access::ModuleExtenderFactory extenderFactory{};
    const auto& moduleExtender = extenderFactory.Create(L"win32kbase.sys");
    if (!moduleExtender.has_value())
    {
        outLog("win32kbase.sys ���ų�ʼ��ʧ��..");
        return FALSE;
    }

    Sys_ValidateHwnd = (PFN_VALIDATEHWND)moduleExtender->GetPointer<PFN_VALIDATEHWND>("ValidateHwnd");

    return TRUE;
}


PWND NewValidateHwnd(_In_ HWND hwnd)
{
    //���ݴ��ھ����ô��ڶ���
    PWND pwnd = Original_ValidateHwnd(hwnd);
    if (pwnd)
    {
        //�жϵ�ǰ�������Ƿ��ǵ���������
        if (!IsDebugger(PsGetCurrentProcess()))
        {
            //�����̶߳����ý��̶���
            PEPROCESS Process = PsGetThreadProcess((PETHREAD)pwnd->head.pti->pEThread);

            //�ж�Ҫ���ʵ�Ŀ�괰���Ƿ������ǵ������Ĵ���
            if (IsDebugger(Process))
            {
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

                    //������ʵ������ǵ������Ĵ��ڣ���ܾ����ʡ�
                    pwnd = NULL;

                    //PrintProcessName((_EPROCESS*)PsGetCurrentProcess());
                }
            }
        }
    }
pass:
    return pwnd;
}