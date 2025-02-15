#pragma once

#ifndef _PROTECT_DRX_H
#define _PROTECT_DRX_H

typedef struct _WOW64_FLOATING_SAVE_AREA
{
    /* 0x0000 */ unsigned long ControlWord;
    /* 0x0004 */ unsigned long StatusWord;
    /* 0x0008 */ unsigned long TagWord;
    /* 0x000c */ unsigned long ErrorOffset;
    /* 0x0010 */ unsigned long ErrorSelector;
    /* 0x0014 */ unsigned long DataOffset;
    /* 0x0018 */ unsigned long DataSelector;
    /* 0x001c */ unsigned char RegisterArea[80];
    /* 0x006c */ unsigned long Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, * PWOW64_FLOATING_SAVE_AREA; /* size: 0x0070 */

typedef struct _WOW64_CONTEXT
{
    /* 0x0000 */ unsigned long ContextFlags;
    /* 0x0004 */ unsigned long Dr0;
    /* 0x0008 */ unsigned long Dr1;
    /* 0x000c */ unsigned long Dr2;
    /* 0x0010 */ unsigned long Dr3;
    /* 0x0014 */ unsigned long Dr6;
    /* 0x0018 */ unsigned long Dr7;
    /* 0x001c */ struct _WOW64_FLOATING_SAVE_AREA FloatSave;
    /* 0x008c */ unsigned long SegGs;
    /* 0x0090 */ unsigned long SegFs;
    /* 0x0094 */ unsigned long SegEs;
    /* 0x0098 */ unsigned long SegDs;
    /* 0x009c */ unsigned long Edi;
    /* 0x00a0 */ unsigned long Esi;
    /* 0x00a4 */ unsigned long Ebx;
    /* 0x00a8 */ unsigned long Edx;
    /* 0x00ac */ unsigned long Ecx;
    /* 0x00b0 */ unsigned long Eax;
    /* 0x00b4 */ unsigned long Ebp;
    /* 0x00b8 */ unsigned long Eip;
    /* 0x00bc */ unsigned long SegCs;
    /* 0x00c0 */ unsigned long EFlags;
    /* 0x00c4 */ unsigned long Esp;
    /* 0x00c8 */ unsigned long SegSs;
    /* 0x00cc */ unsigned char ExtendedRegisters[512];
} WOW64_CONTEXT, * PWOW64_CONTEXT; /* size: 0x02cc */

NTSTATUS NtQueryInformationThread(
    _In_       HANDLE ThreadHandle,
    _In_       THREADINFOCLASS ThreadInformationClass,
    _Inout_    PVOID           ThreadInformation,
    _In_       ULONG           ThreadInformationLength,
    _Out_opt_  PULONG          ReturnLength
);

NTSTATUS NtGetContextThread(_In_ HANDLE hThread, _Inout_ PCONTEXT ThreadContext);

NTSTATUS
NtSetContextThread(
    __in HANDLE ThreadHandle,
    __in PCONTEXT ThreadContext  /*�˲������û����ṩ�Ļ�����*/
);


#endif // !_PROTECT_DRX_H
