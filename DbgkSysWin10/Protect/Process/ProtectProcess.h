#pragma once

#ifndef _PROTECT_PROCESS_H
#define _PROTECT_PROCESS_H

//�ǰ���������
NTSTATUS IsWhiteListProcess(_In_ HANDLE ProcessHandle,  //Ҫ��ȡ��Ŀ�����
    _In_opt_ PVOID BaseAddress,
    _Out_opt_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead);

#endif // !_PROTECT_PROCESS_H
