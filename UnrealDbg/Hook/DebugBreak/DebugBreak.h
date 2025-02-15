#pragma once

#ifndef _DEBUG_BREAK_H
#define _DEBUG_BREAK_H

//Vol3B[18.2.4 Debug Control Register(DR7)]
#define WATCH_EXECUTION_ONLY   0
#define WATCH_WRITE            1
#define WATCH_READWRITE        3

#define BYTE_1  0
#define BYTE_2  1
#define BYTE_8  2
#define BYTE_4  3

#define BREAKPOINT_COUNT  1

BOOL
WINAPI
NewSetThreadContext(
    _In_ HANDLE hThread,
    _In_ CONTEXT* lpContext
);

BOOL WINAPI NewGetThreadContext(
    _In_ HANDLE    hThread,
    _Inout_ LPCONTEXT lpContext
);

//��Ӷϵ�
bool AddBreakpoint(PVOID setAddress, unsigned __int64 command, int length);
bool RemoveBreakpoint();

//����Ӧ�ý���ֱַ�Ӵ���vt
//����vt���޸�ept pteҳ������
bool SetBreakpoint(PVOID lpBaseAddress, unsigned __int64 command, int length);


#endif // !_DEBUG_BREAK_H
