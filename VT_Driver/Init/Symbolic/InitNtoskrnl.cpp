#include "../../Driver.h"
#include "../../poolmanager.h"
#include "../../Globals.h"
#include "InitNtoskrnl.h"


BOOLEAN InitNtoskrnlSymbolsTable()
{

    //DbgBreakPoint();
    symbolic_access::ModuleExtenderFactory extenderFactory{};
    const auto& moduleExtender = extenderFactory.Create(L"ntoskrnl.exe");
    if (!moduleExtender.has_value())
    {
        outDebug("ntoskrnl.exe ���ų�ʼ��ʧ��..");
        return FALSE;
    }

    PsGetNextProcess = (PFN_PSGETNEXTPROCESS)moduleExtender->GetPointer<PFN_PSGETNEXTPROCESS>("PsGetNextProcess");

    return TRUE;
}