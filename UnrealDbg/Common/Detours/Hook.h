#pragma once

#ifndef _HOOK_H
#define _HOOK_H

//��װhook
void HookOn(_In_ PVOID* pfun, _In_ PVOID proxy_fun, _In_ HANDLE hThread);

//ж��hook
void HookOff(_In_ PVOID* pfun, _In_ PVOID proxy_fun, _In_ HANDLE hThread);


#endif // !_HOOK_H
