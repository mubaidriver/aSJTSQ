#include "../Driver.h"
#include "../ntos/inc/mmtypes.h"
#include "../ntos/inc/ntdbg.h"
#include "../ntos/inc/ketypes.h"
#include "../ntos/inc/extypes.h"
#include "../ntos/inc/ntosdef.h"
#include "../ntos/inc/amd64.h"
#include "../ntos/inc/mi.h"
#include "../ntos/inc/pstypes.h"
#include "../ntos/inc/obtypes.h"
#include "../ntos/inc/peb_teb.h"
#include "../List/MyList.h"
#include "../ntos/inc/ntlpcapi.h"
#include "../ntos/inc/psp.h"
#include "../Globals.h"
#include "../DbgkApi/DbgkApi.h"
#include "Callbacks.h"

#define _Altitude_ L"321000"

//�ڱ��������б��в���pid  ����Ƿ��Ǳ������Ľ���
//BOOLEAN IsProtectProcess(HANDLE ProcessId)
//{
//	IsDebugger();
//	BOOLEAN boIs = FALSE;
//	PLIST_ENTRY ListHead, NextEntry;
//	PROTECT_OBJECT_ENTRY* protect_entry;
//
//	ExAcquireFastMutex(&g_ProtectObjectList.Mutex);
//	ListHead = &g_ProtectObjectList.EventList.ListHead;
//	NextEntry = ListHead->Flink;
//	while (ListHead != NextEntry)
//	{
//		protect_entry = CONTAINING_RECORD(NextEntry,
//			PROTECT_OBJECT_ENTRY,
//			EventList);
//
//		if (protect_entry)
//		{
//			if (ProcessId == (HANDLE)protect_entry->dwProcessId)
//			{
//				//�Ǳ����Ľ��̶���
//				boIs = TRUE;
//				break;
//			}
//		}
//
//		/* Move to the next entry */
//		NextEntry = NextEntry->Flink;
//	}
//	ExReleaseFastMutex(&g_ProtectObjectList.Mutex);
//	return boIs;
//}


//�̻߳ص�
//OB_PREOP_CALLBACK_STATUS preThreadCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
//{
//	UNREFERENCED_PARAMETER(RegistrationContext);
//	if (IsDebugger(PsGetThreadProcess((PETHREAD)pOperationInformation->Object)))
//	{
//		//PrintProcessName(PsGetCurrentProcess());
//
//		//��ȡ��ǰ���ý���
//		UNICODE_STRING ImageFileName, PassImage;
//		NTSTATUS Status = GetProcessName(PsGetCurrentProcess(), &ImageFileName);
//		if (NT_SUCCESS(Status))
//		{
//			for (ULONG i = 0; i < sizeof(PassProcessList) / sizeof(PassProcessList[0]); i++)
//			{
//				RtlInitUnicodeString(&PassImage, PassProcessList[i]);
//				if (RtlEqualUnicodeString(&ImageFileName, &PassImage, TRUE))
//				{
//					//�����ǰ��������̾��˳�
//					return OB_PREOP_SUCCESS;
//				}
//			}
//		}
//
//		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)  //�򿪾��
//		{
//			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
//			{
//				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
//			}
//
//			//if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_GET_CONTEXT) == THREAD_GET_CONTEXT)
//			//{
//			//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_GET_CONTEXT;
//			//}
//		}
//		else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)  //���ƾ��
//		{
//			if ((pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
//			{
//				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
//			}
//		}
//	}
//	return OB_PREOP_SUCCESS;
//}


//ע��˱��������޷�����FindWindow
OB_PREOP_CALLBACK_STATUS preProcessCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (IsDebugger((PEPROCESS)pOperationInformation->Object))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)  //�򿪾��
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
		else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)  //���ƾ��
		{
			if ((pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

//���ý��̻ص�
VOID SetProcessCallbacks(IN PDRIVER_OBJECT pDriver_Object)
{
	NTSTATUS Status;
	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ocr;

	PLDR_DATA_TABLE_ENTRY ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY)pDriver_Object->DriverSection;
	ldr->Flags |= 0x20;//����������ʱ����жϴ�ֵ������������ǩ�����У�����0x20���ɡ����򽫵���ʧ�� 

	oor.ObjectType = PsProcessType;
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	oor.PreOperation = (POB_PRE_OPERATION_CALLBACK)preProcessCallback;
	oor.PostOperation = NULL;

	ocr.Version = OB_FLT_REGISTRATION_VERSION;
	ocr.OperationRegistrationCount = 1;
	ocr.OperationRegistration = &oor;
	RtlInitUnicodeString(&ocr.Altitude, _Altitude_);
	ocr.RegistrationContext = NULL;

	Status = ObRegisterCallbacks(&ocr, &g_obProcessHandle);
	if (!NT_SUCCESS(Status))
	{
		ASSERT(FALSE);
	}
}

//ж�ؽ��̻ص�
VOID UnProcessCallbacks()
{
	ASSERT(g_obProcessHandle);
	if (g_obProcessHandle)
	{
		ObUnRegisterCallbacks(g_obProcessHandle);
	}
}