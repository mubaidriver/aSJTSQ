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
#include "../Hvm/hypervisor_gateway.h"
#include "../ntos/inc/ke.h"
#include "../Protect/Process/ProtectProcess.h"
#include "ReadWrite.h"


VOID InsertBreakpointList(PBREAKPOINT_TABLE_ENTRY entry)
{
	if (entry)
	{
		ExAcquireFastMutex(&g_BreakpointList.Mutex);
		InsertNode(&g_BreakpointList.list_entry, &entry->list_entry);
		ExReleaseFastMutex(&g_BreakpointList.Mutex);
	}
}

VOID TraceBreakpoint(_EPROCESS* Process, PVOID BaseAddress, PVOID Buffer)
{
	PBREAKPOINT_TABLE_ENTRY entry = allocate_pool<BREAKPOINT_TABLE_ENTRY>();
	if (entry)
	{
		entry->Process = Process;
		entry->BreakpointAddress = BaseAddress;
		//entry->firstByte = *(BYTE*)Buffer;
		//entry->originalByte = *(BYTE*)BaseAddress;
		InsertBreakpointList(entry);
	}	
}

//ӳ�������ַ
PVOID MDLMapVirtualAddress(IN PVOID VirtualAddress, IN SIZE_T BufferSize, OUT MDL_MAP &map_table)
{
	PMDL mdl = NULL;
	PVOID MappedAddress = NULL;
	BOOLEAN lockpage = FALSE;

	__try
	{
		SIZE_T tosize;

		if (BufferSize < PAGE_SIZE)
		{
			tosize = PAGE_SIZE;
		}
		else
		{
			tosize = BufferSize;
		}

		mdl = IoAllocateMdl(VirtualAddress, tosize, FALSE, FALSE, NULL);
		if (mdl)
		{
			//��ס����ҳ����������������������.
			MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
			lockpage = TRUE;

			//�� MDL ����������ҳ��ӳ�䵽�����ڴ�
			MappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (MappedAddress == NULL)
			{
				//ʧ�������ɨβ����
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);			
				map_table = { 0 };
			}
			else
			{
				map_table.mdl = mdl;
				map_table.MappedAddress = MappedAddress;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (MappedAddress)
		{
			MmUnmapLockedPages(MappedAddress, mdl);
		}
		if (lockpage)
		{
			MmUnlockPages(mdl);
		}
		if (mdl)
		{
			IoFreeMdl(mdl);
		}
		MappedAddress = NULL;
	}
	return MappedAddress;
}

VOID UnMDLMapVirtualAddress(MDL_MAP map_table)
{
	if (map_table.MappedAddress)
	{
		MmUnmapLockedPages(map_table.MappedAddress, map_table.mdl);
	}
	if (map_table.mdl)
	{
		MmUnlockPages(map_table.mdl);
		IoFreeMdl(map_table.mdl);
	}
}

NTSTATUS SetBreakpoint(HANDLE ProcessHandle, _EPROCESS* Process, PVOID BaseAddress /*Ŀ���ַ*/, PVOID Buffer, SIZE_T BufferSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	KAPC_STATE ApcState;
	BYTE tmpBuffer[256] = { 0 };
	MDL_MAP map_table = { 0 };
	PVOID MappedAddress = NULL;

	//DbgBreakPoint();
	size_t ptr_Pcb = (size_t)Process + eprocess_offset::Pcb;
	RtlCopyMemory(tmpBuffer, Buffer, BufferSize);
	KiStackAttachProcess((_KPROCESS*)ptr_Pcb, FALSE, &ApcState);
	//ͨ��vt����4KB����ҳ
	//���û�ָ��ϵ�
	__try
	{
		//DbgBreakPoint();
		SIZE_T RegionSize = BufferSize;
		ULONG flOldProtect;
		PVOID loc_BaseAddress = BaseAddress;
		//��ҳ���Ը�Ϊд����  �Ӷ���д��ֵʱ�����µ�����ҳ
		//KPROCESSOR_MODE Old_PreviousMode = KeSetPreviousMode(KernelMode);
		Status = ZwProtectVirtualMemory(NtCurrentProcess(), &loc_BaseAddress, &RegionSize, PAGE_EXECUTE_WRITECOPY, &flOldProtect);
		if (NT_SUCCESS(Status))
		{
			//����д���������µ�����ҳ
			RtlCopyMemory(BaseAddress, BaseAddress, BufferSize);

			//ͨ��mdl���·��������ҳ��ӳ�䵽�����ڴ�
			MappedAddress = MDLMapVirtualAddress(BaseAddress, BufferSize, map_table);
			if (MappedAddress)
			{
				map_table.VirtualAddress = BaseAddress;
				if (hvgt::set_hide_software_breakpoint(&map_table, &tmpBuffer, BufferSize))
				{
					TraceBreakpoint(Process, BaseAddress, tmpBuffer);
				}
				UnMDLMapVirtualAddress(map_table);
			}
			ZwProtectVirtualMemory(NtCurrentProcess(), &loc_BaseAddress, &RegionSize, flOldProtect, &flOldProtect);
		}
		//KeSetPreviousMode(Old_PreviousMode);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}
	KiUnstackDetachProcess(&ApcState, 0);
	return STATUS_SUCCESS;
}

VOID DeleteBreakpoint(_EPROCESS* Process, PVOID BaseAddress, PVOID Buffer)
{
	PLIST_ENTRY ListHead, NextEntry;
	PBREAKPOINT_TABLE_ENTRY entry;

	ExAcquireFastMutex(&g_BreakpointList.Mutex);
	ListHead = &g_BreakpointList.list_entry.ListHead;
	NextEntry = ListHead->Flink;
	while (ListHead != NextEntry)
	{
		entry = CONTAINING_RECORD(NextEntry,
			BREAKPOINT_TABLE_ENTRY,
			list_entry);

		if (entry)
		{
			if (entry->Process == Process &&
				entry->BreakpointAddress == BaseAddress /*&&
				entry->originalByte == *(BYTE*)Buffer*/)
			{
				RemoveEntryList(NextEntry);
				free_pool(entry);
				break;
			}
		}

		/* Move to the next entry */
		NextEntry = NextEntry->Flink;
	}
	ExReleaseFastMutex(&g_BreakpointList.Mutex);
}

NTSTATUS RemoveBreakpoint(HANDLE ProcessHandle, _EPROCESS* Process, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	KAPC_STATE ApcState;
	BYTE tmpBuffer[256] = { 0 };
	MDL_MAP map_table = { 0 };
	PVOID MappedAddress = NULL;

	//DbgBreakPoint();
	size_t ptr_Pcb = (size_t)Process + eprocess_offset::Pcb;
	RtlCopyMemory(tmpBuffer, Buffer, BufferSize);
	KiStackAttachProcess((_KPROCESS*)ptr_Pcb, FALSE, &ApcState);
	//ͨ��vt����4KB����ҳ
	//���û�ָ��ϵ�
	__try
	{
		//DbgBreakPoint();
		SIZE_T RegionSize = BufferSize;
		ULONG flOldProtect;
		PVOID loc_BaseAddress = BaseAddress;
		//��ҳ���Ը�Ϊд����  �Ӷ���д��ֵʱ�����µ�����ҳ
		//Status = NtProtectVirtualMemory(NtCurrentProcess(), &loc_BaseAddress, &RegionSize, PAGE_EXECUTE_WRITECOPY, &flOldProtect);
		//if (NT_SUCCESS(Status))
		{
			//����д���������µ�����ҳ
			//RtlCopyMemory(BaseAddress, BaseAddress, BufferSize);

			//ͨ��mdl���·��������ҳ��ӳ�䵽�����ڴ�
			MappedAddress = MDLMapVirtualAddress(BaseAddress, BufferSize, map_table);
			if (MappedAddress)
			{
				map_table.VirtualAddress = BaseAddress;
				if (hvgt::set_hide_software_breakpoint(&map_table, &tmpBuffer, BufferSize))
				{
					DeleteBreakpoint(Process, BaseAddress, tmpBuffer);
				}
				UnMDLMapVirtualAddress(map_table);
			}
			//NtProtectVirtualMemory(NtCurrentProcess(), &loc_BaseAddress, &RegionSize, flOldProtect, &flOldProtect);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}
	KiUnstackDetachProcess(&ApcState, 0);
	return STATUS_SUCCESS;
}

//���ϵ��Ƿ��Ѵ���
BOOLEAN exist_breakpoint(_EPROCESS* Process, PVOID BaseAddress)
{
	PLIST_ENTRY ListHead, NextEntry;
	PBREAKPOINT_TABLE_ENTRY entry;
	BOOLEAN exist = FALSE;

	ExAcquireFastMutex(&g_BreakpointList.Mutex);
	ListHead = &g_BreakpointList.list_entry.ListHead;
	NextEntry = ListHead->Flink;
	while (ListHead != NextEntry)
	{
		entry = CONTAINING_RECORD(NextEntry,
			BREAKPOINT_TABLE_ENTRY,
			list_entry);

		if (entry)
		{
			if (entry->Process == Process && 
				entry->BreakpointAddress == BaseAddress /*&&
				(entry->firstByte == *(BYTE*)Buffer || entry->originalByte == *(BYTE*)Buffer)*/)
			{
				exist = TRUE;
				break;
			}
		}

		/* Move to the next entry */
		NextEntry = NextEntry->Flink;
	}
	ExReleaseFastMutex(&g_BreakpointList.Mutex);
	return exist;
}


NTSTATUS NtWriteVirtualMemory(_In_ HANDLE ProcessHandle, 
	_In_opt_ PVOID BaseAddress, //target_addr
	_In_ PVOID Buffer,   //��ǰ�����Լ��Ļ�����
	_In_ SIZE_T BufferSize, 
	_Out_opt_ PSIZE_T NumberOfBytesWritten)
{
	NTSTATUS Status = STATUS_SUCCESS;
	_EPROCESS* Process;		

	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

	if (PreviousMode != KernelMode)
	{
		__try
		{
			ProbeForRead(Buffer, BufferSize, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}

	if (IsDebugger(PsGetCurrentProcess()))
	{
		if (BufferSize == 1)
		{
			//����int3�ϵ�
			if (Buffer && (*(UCHAR*)Buffer == 0xCC))
			{
				/* Reference the process */
				Status = ObReferenceObjectByHandle(ProcessHandle,
					PROCESS_ALL_ACCESS,
					*PsProcessType,
					KernelMode,
					(PVOID*)&Process,
					NULL);
				if (NT_SUCCESS(Status))
				{
					if (!exist_breakpoint(Process, BaseAddress))
					{
						Status = SetBreakpoint(ProcessHandle, Process, BaseAddress, Buffer, BufferSize);
					}				
					else
					{
						Status = STATUS_SUCCESS;
					}
					if (Process)
					{
						ObDereferenceObject(Process);
					}
					return Status;
				}
				return STATUS_UNSUCCESSFUL;
			}

			//�Ƴ�int3�ϵ�
			if (Buffer)
			{
				/* Reference the process */
				Status = ObReferenceObjectByHandle(ProcessHandle,
					PROCESS_ALL_ACCESS,
					*PsProcessType,
					KernelMode,
					(PVOID*)&Process,
					NULL);
				if (NT_SUCCESS(Status))
				{
					if (exist_breakpoint(Process, BaseAddress))
					{
						Status = RemoveBreakpoint(ProcessHandle, Process, BaseAddress, Buffer, BufferSize);
						if (Process)
						{
							ObDereferenceObject(Process);
						}
						return Status;
					}
					if (Process)
					{
						ObDereferenceObject(Process);
					}		
				}
				else
				{
					return STATUS_UNSUCCESSFUL;
				}				
			}
		}
	}
	ASSERT(Original_NtWriteVirtualMemory);
	return Original_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS GetBreakpoint(_EPROCESS* Process, PVOID BaseAddress/*Ҫ��ȡ��Ŀ���ַ*/, PVOID Buffer /*���������*/, SIZE_T BufferSize)
{
	KAPC_STATE ApcState;
	BYTE tmpBuffer[256] = { 0 };
	BOOLEAN boFound = FALSE;
	MDL_MAP map_table = { 0 };
	PVOID MappedAddress = NULL;

	//DbgBreakPoint();
	size_t ptr_Pcb = (size_t)Process + eprocess_offset::Pcb;
	KiStackAttachProcess((_KPROCESS*)ptr_Pcb, FALSE, &ApcState);
	__try
	{
		//�� MDL ����������ҳ��ӳ�䵽�����ڴ�
		MappedAddress = MDLMapVirtualAddress(BaseAddress, BufferSize, map_table);
		if (MappedAddress)
		{
			//��ȡEPT�ڴ�
			if (hvgt::get_hide_software_breakpoint(BaseAddress, &tmpBuffer, BufferSize))
			{
				boFound = TRUE;
			}
			UnMDLMapVirtualAddress(map_table);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}
	KiUnstackDetachProcess(&ApcState, 0);

	if (boFound)
	{
		RtlCopyMemory(Buffer, tmpBuffer, BufferSize);
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS MyReadVirtualMemory(_In_ HANDLE ProcessHandle,  //Ҫ��ȡ��Ŀ�����
	_In_opt_ PVOID BaseAddress, //Ҫ��ȡ��Ŀ���ַ
	_Out_opt_ PVOID Buffer,  //���������
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead)
{
	KAPC_STATE ApcState;
	BYTE *tmpBuffer = NULL;
	MDL_MAP map_table = { 0 };
	PVOID MappedAddress = NULL;
	_EPROCESS* Process;

	NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		(PVOID*)&Process,
		NULL);
	if (NT_SUCCESS(Status))
	{
		tmpBuffer = allocate_pool<BYTE*>(BufferSize);
		if (tmpBuffer)
		{
			//DbgBreakPoint();
			size_t ptr_Pcb = (size_t)Process + eprocess_offset::Pcb;
			KiStackAttachProcess((_KPROCESS*)ptr_Pcb, FALSE, &ApcState);
			__try
			{
				//�� MDL ����������ҳ��ӳ�䵽�����ڴ�
				MappedAddress = MDLMapVirtualAddress(BaseAddress, BufferSize, map_table);
				if (MappedAddress)
				{
					//�ȿ�����ϵͳ����ʱ������
					RtlCopyMemory(tmpBuffer, MappedAddress, BufferSize);
					UnMDLMapVirtualAddress(map_table);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
			KiUnstackDetachProcess(&ApcState, 0);


			RtlCopyMemory(Buffer, tmpBuffer, BufferSize);
			*NumberOfBytesRead = BufferSize;
			free_pool(tmpBuffer);
		}

		if (Process)
		{
			ObDereferenceObject(Process);
		}
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS EptReadVirtualMemory(_In_ HANDLE ProcessHandle,  //Ҫ��ȡ��Ŀ�����
	_In_opt_ PVOID BaseAddress, //Ҫ��ȡ��Ŀ���ַ
	_Out_opt_ PVOID Buffer,  //���������
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead)
{
	_EPROCESS* Process;
	BYTE* tmpBuffer = NULL;
	KAPC_STATE ApcState;
	BOOLEAN boFound = FALSE;

	NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		(PVOID*)&Process,
		NULL);
	if (NT_SUCCESS(Status))
	{
		tmpBuffer = allocate_contignous_memory<BYTE*>(BufferSize);
		if (tmpBuffer)
		{
			size_t ptr_Pcb = (size_t)Process + eprocess_offset::Pcb;
			KiStackAttachProcess((_KPROCESS*)ptr_Pcb, FALSE, &ApcState);
			__try
			{
				//��ȡEPT�ڴ�
				if (hvgt::read_ept_fake_page_memory(BaseAddress, tmpBuffer, BufferSize))
				{
					boFound = TRUE;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
			KiUnstackDetachProcess(&ApcState, 0);

			if (boFound)
			{
				RtlCopyMemory(Buffer, tmpBuffer, BufferSize);
				return STATUS_SUCCESS;
			}
		}
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS NtReadVirtualMemory(_In_ HANDLE ProcessHandle,  //Ҫ��ȡ��Ŀ�����
	_In_opt_ PVOID BaseAddress, //Ҫ��ȡ��Ŀ���ַ
	_Out_opt_ PVOID Buffer,  //���������
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead)
{
	NTSTATUS Status = STATUS_SUCCESS;
	_EPROCESS* Process;		
	BOOLEAN boFound = FALSE;

	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

	if (PreviousMode != KernelMode)
	{
		__try
		{
			ProbeForWrite(Buffer, BufferSize, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}

	//����Ƿ��ǰ���������
	//Status = IsWhiteListProcess(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);

	//if (NT_SUCCESS(Status))
	{
		if (IsDebugger(PsGetCurrentProcess()))
		{
			if (Buffer)
			{
				//��CC�ϵ�
				//if (BufferSize == 1)
				//{
				//	/* Reference the process */
				//	Status = ObReferenceObjectByHandle(ProcessHandle,
				//		PROCESS_ALL_ACCESS,
				//		*PsProcessType,
				//		KernelMode,
				//		(PVOID*)&Process,
				//		NULL);
				//	if (NT_SUCCESS(Status))
				//	{
				//		//PrintProcessName(Process);
				//		if (exist_breakpoint(Process, BaseAddress))
				//		{
				//			Status = GetBreakpoint(Process, BaseAddress, Buffer, BufferSize);
				//			if (NT_SUCCESS(Status))
				//			{
				//				if (Process)
				//				{
				//					ObDereferenceObject(Process);
				//				}
				//				return Status;
				//			}
				//		}		

				//		if (Process)
				//		{
				//			ObDereferenceObject(Process);
				//		}
				//	}
				//	else
				//	{
				//		return STATUS_UNSUCCESSFUL;
				//	}					
				//}


				//Status = EptReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
				//if (NT_SUCCESS(Status))
				//{
				//	return Status;
				//}
			}

			//return MyReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
		}
		ASSERT(Original_NtReadVirtualMemory);
		Status = Original_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
	}

	return Status;
}

NTSTATUS NewMmCopyVirtualMemory(_EPROCESS* FromProcess,
	PVOID FromAddress,
	_EPROCESS* ToProcess,
	PVOID ToAddress,
	size_t BufferSize,
	KPROCESSOR_MODE PreviousMode,
	size_t* NumberOfBytesCopied)
{
	if (IsDebugger(PsGetCurrentProcess()))
	{
		PreviousMode = KernelMode;
	}
	return Original_MmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress, BufferSize, PreviousMode, NumberOfBytesCopied);
}