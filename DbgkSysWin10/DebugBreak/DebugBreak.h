#pragma once

#ifndef _DEBUG_BREAK_H
#define _DEBUG_BREAK_H

//����Ӳ���ϵ�
void SetHardwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp);
//�Ƴ�Ӳ���ϵ�
void RemoveHardwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp);

//��������ϵ�
void SetSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp);
//�Ƴ�����ϵ�
void RemoveSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp);
//��int3�ϵ�
void ReadSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp);


#endif // !_DEBUG_BREAK_H