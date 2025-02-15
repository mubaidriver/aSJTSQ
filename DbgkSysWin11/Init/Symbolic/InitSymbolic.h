#pragma once

#ifndef _INIT_SYMBOLIC_H
#define _INIT_SYMBOLIC_H

VOID InitSymbolsTable(IN PUSER_DATA userData, IN PIRP pIrp);

BOOLEAN InitNtoskrnlSymbolsTable();
BOOLEAN InitWin32kbaseSymbolsTable();
BOOLEAN InitWin32kfullSymbolsTable();

//���ں˽ṹ��ƫ�Ʒ��͸�vt host
bool DispatchOffsetToHost();

//Dump����ƫ�ƺͺ���ָ��
void DumpOffsetAndFuncPtr();

void CheckFunctionPointers();

#endif // !_INIT_SYMBOLIC_H
