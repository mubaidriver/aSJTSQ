#pragma once

#ifndef _VMX_H
#define _VMX_H

enum vm_call_reasons
{
	VMCALL_TEST,
	VMCALL_VMXOFF,
	VMCALL_EPT_CC_HOOK,
	VMCALL_EPT_INT1_HOOK,
	VMCALL_EPT_RIP_HOOK,
	VMCALL_EPT_HOOK_FUNCTION,
	VMCALL_EPT_UNHOOK_FUNCTION,
	VMCALL_INVEPT_CONTEXT,
	VMCALL_DUMP_POOL_MANAGER,
	VMCALL_DUMP_VMCS_STATE,
	VMCALL_HIDE_HV_PRESENCE,
	VMCALL_UNHIDE_HV_PRESENCE,
	VMCALL_HIDE_SOFTWARE_BREAKPOINT,
	VMCALL_READ_SOFTWARE_BREAKPOINT,
	VMCALL_READ_EPT_FAKE_PAGE_MEMORY,
	VMCALL_WATCH_WRITES,
	VMCALL_WATCH_READS,
	VMCALL_WATCH_EXECUTES,
	VMCALL_WATCH_DELETE,
	VMCALL_GET_BREAKPOINT,
	VMCALL_INIT_OFFSET,
};

EXTERN_C
{

#ifdef _WIN64

	bool __vm_call(unsigned __int64 vmcall_reason, unsigned __int64 rdx, unsigned __int64 r8, unsigned __int64 r9);
	bool __vm_call_ex(unsigned __int64 vmcall_reason, unsigned __int64 rdx, unsigned __int64 r8, unsigned __int64 r9, unsigned __int64 r10, unsigned __int64 r11, unsigned __int64 r12, unsigned __int64 r13, unsigned __int64 r14, unsigned __int64 r15);

#else
	bool __stdcall __vm_call(DWORD vmcall_reason, PVOID vmcallinfo);
#endif // _WIN64
}

//���߳�������ָ��cpu����
//CPU������0��ʼ
void RunOnCPU(HANDLE hThread, int CpuNo);

//��㲥�������߼�������
bool vmcall(PVOID vmcallinfo);

//�����߼��������ҵ������¼��ɹ����Ǹ�
bool vmcall2(PVOID vmcallinfo);

//ֻ����ǰ�߼���������������
bool current_vmcall(PVOID vmcallinfo);


#endif // !_VMX_H
