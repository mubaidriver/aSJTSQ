#pragma once

#ifndef _INVALID_EPT_H
#define _INVALID_EPT_H

struct __invept_descriptor
{
	unsigned __int64 ept_pointer;
	unsigned __int64 reserved;
};

//ˢ��ȫ�����߼�������
void invept_all_contexts_func();
//ˢ��ָ�����߼���������eptp
void invept_single_context_func(unsigned __int64 ept_pointer);

#endif // !_INVALID_EPT_H
