#pragma once

#ifndef _CALLBACKS_H
#define _CALLBACKS_H

//ע��˱��������޷�����FindWindow
OB_PREOP_CALLBACK_STATUS preProcessCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);

//���ý��̻ص�
VOID SetProcessCallbacks(IN PDRIVER_OBJECT pDriver_Object);

//ж�ؽ��̻ص�
VOID UnProcessCallbacks();


#endif // !_CALLBACKS_H
