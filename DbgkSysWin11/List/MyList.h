#pragma once

#ifndef _MY_LIST_H
#define _MY_LIST_H


typedef struct _MY_LIST
{
	LIST_ENTRY ListHead;
	ULONG Count;
} MY_LIST;

VOID InitFunctionEventList();
//��ʼ�����������б�
VOID InitializeList(MY_LIST* list, PFAST_MUTEX FastMutex);
VOID InsertNode(MY_LIST* list, LIST_ENTRY* entry);
VOID RemoveNode(MY_LIST* list, LIST_ENTRY* entry);
ULONG GetListCount(MY_LIST* list);


class CMyList
{
private:
	DWORD m_FCount;  //��¼Ԫ�ظ���
	DWORD m_FCapacity;  //�������
	FAST_MUTEX m_FLock;
	PVOID* m_FList;  //�ײ�����洢��

public:
	CMyList()
	{

	}
	CMyList(DWORD MaxCount)
	{
		m_FCount = 0;
		m_FCapacity = MaxCount;
		m_FList = new PVOID[MaxCount];
		RtlZeroMemory(m_FList, MaxCount * sizeof(PVOID));
		ExInitializeFastMutex(&m_FLock);
	}

	~CMyList()
	{
		delete[] m_FList;
	}

	VOID Lock()
	{
		ExAcquireFastMutex(&m_FLock);
	}

	VOID UnLock()
	{
		ExReleaseFastMutex(&m_FLock);
	}

	DWORD Count()
	{
		return m_FCount;
	}

	//ȡ��Ԫ��
	PVOID Get(DWORD dwIndex)
	{
		if (dwIndex >= m_FCount)
		{
			return NULL;
		}
		else
		{
			return m_FList[dwIndex];
		}
	}

	//ɾ��Ԫ��
	VOID Delete(DWORD dwIndex)
	{
		if (dwIndex < m_FCount)
		{
			--m_FCount;
			RtlCopyMemory(&m_FList[dwIndex], &m_FList[dwIndex + 1], (m_FCount - dwIndex) * sizeof(PVOID));
		}
	}

	//���Ԫ��
	DWORD Add(PVOID Item)
	{
		if (m_FCount < m_FCapacity)
		{
			m_FList[m_FCount++] = Item;
		}
		else
		{
			//���Ԫ�ظ������ڻ�������ͨ��int3��������
			DbgBreakPoint();
		}
		return m_FCount;
	}
};


#endif // !_MY_LIST_H
