#include "dllmain.h"
#include "HookCallSet/functionSet.h"
#include "Globals.h"

DWORD g_dwNumberOfProcessors;  //�߼�����������
LONG g_debug_condition_detected;  //��¼��TF����ִ�У�����drx�ϵ�
DWORD g_target_pid;  //Ŀ����̵�pid
ULONG64 g_target_cr3; //Ŀ����̵�cr3
vectorExt<BREAKPOINT_RECORD> BreakpointList;
vectorExt<VT_BREAK_POINT> INT3BreakpointList;
HANDLE g_hGeneralDriverDevice = INVALID_HANDLE_VALUE;
BOOL g_first_breakpoint = FALSE;  //�Ƿ��ǵ�һ�ζϵ�
PROCESS_INFO g_process_info = { 0 };
SET_DBG_BREAKPOINT g_SetDbgBreakPoint = { 0 };

PFN_LDRINITIALIZETHUNK LdrInitializeThunk;
PVOID BaseThreadInitThunk;
PVOID KiUserApcDispatcher;

//ע������: ������hook ϵͳ�ĺ���ת�������Զ���ĺ�����ʱ
//�����Զ���ĺ��������õĵ���Լ����������Ϊ__stdcall
//��Ϊ�����hook��Ŀ����Ϊ32λdllʱ����Ҫ�ϸ�ĺ�������Լ����
//������ܻᵼ��ջ��ƽ��
PFN_DEBUGACTIVEPROCESS Sys_DebugActiveProcess;
PFN_NTDEBUGACTIVEPROCESS Sys_NtDebugActiveProcess;
PFN_DBGUIISSUEREMOTEBREAKIN Sys_DbgUiIssueRemoteBreakin;
PFN_NTCREATEUSERPROCESS Sys_NtCreateUserProcess;
PFN_WAITFORDEBUGEVENT Sys_WaitForDebugEvent;
PFN_CONTINUEDEBUGEVENT Sys_ContinueDebugEvent;
PFN_OUTPUTDEBUGSTRINGA Sys_OutputDebugStringA;
PFN_OUTPUTDEBUGSTRINGW Sys_OutputDebugStringW;
PFN_DBGUIDEBUGACTIVEPROCESS Sys_DbgUiDebugActiveProcess;
PFN_SETTHREADCONTEXT Sys_SetThreadContext;
PFN_GETTHREADCONTEXT Sys_GetThreadContext;
PFN_VIRTUALPROTECTEX Sys_VirtualProtectEx;
PFN_WRITEPROCESSMEMORY Sys_WriteProcessMemory;
PFN_READPROCESSMEMORY Sys_ReadProcessMemory;
PFN_NTDEBUGCONTINUE Sys_NtDebugContinue;