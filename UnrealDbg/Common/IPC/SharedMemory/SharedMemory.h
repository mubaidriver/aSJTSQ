#pragma once

#ifndef _SHARED_MEMORY_H
#define _SHARED_MEMORY_H

#define IPC_GAME_CLIENT_ID    1000

typedef struct _tag_GAME_CLIENT {
    DWORD dwPid;  //��Ϸ�ͻ���pid
    TCHAR szClient[100];
    TCHAR szGamePath[256];  //��ϷĿ¼
}GAME_CLIENT, * PGAME_CLIENT;

typedef struct _tag_IPC_MSG_RCD {
    DWORD MsgId;  //��Ϣid
    BYTE buffer[1024];
}IPC_MSG_RCD, * PIPC_MSG_RCD;

// �����ڴ�ṹ��
typedef struct _tag_SharedData {
    IPC_MSG_RCD ipc_msg;
    //CRITICAL_SECTION cs; // ����ͬ�����ʵĻ�����
}SHARED_DATA, * PSHARED_DATA;

class SharedMemory {
public:
    SharedMemory(const std::wstring& name, size_t size)
        : m_name(name), m_size(size) {

        // ���Դ��Ѿ����ڵĹ����ڴ�
        m_hMapFile = OpenFileMapping(
            FILE_MAP_ALL_ACCESS,
            FALSE,
            m_name.c_str()
        );

        if (m_hMapFile == NULL) {
            // ��������ڴ治���ڣ������µĹ����ڴ�
            m_hMapFile = CreateFileMapping(
                INVALID_HANDLE_VALUE,
                NULL,
                PAGE_READWRITE,
                0,
                static_cast<DWORD>(m_size),
                m_name.c_str()
            );

            if (m_hMapFile == NULL) {
                throw std::runtime_error("CreateFileMapping failed");
            }
        }
        else
        {
            m_exists = TRUE;
        }

        m_pData = static_cast<PSHARED_DATA>(MapViewOfFile(
            m_hMapFile,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            m_size
        ));

        if (m_pData == NULL) {
            CloseHandle(m_hMapFile);
            throw std::runtime_error("MapViewOfFile failed");
        }

        //char szBuf[MAX_PATH] = { 0 };
        //sprintf(szBuf, "�����ڴ�: %p", m_pData);
        //OutputDebugStringA(szBuf);

        char szBuf[MAX_PATH] = { 0 };
        sprintf(szBuf, "������: %p", m_hMapFile);
        OutputDebugStringA(szBuf);

        if (!m_exists)
        {
            // ������´����Ĺ����ڴ棬��ʼ���ٽ���
            OutputDebugStringA("�´����Ĺ����ڴ棬��ʼ���ٽ���");
            //InitializeCriticalSection(&m_pData->cs);
        }        
    }

    ~SharedMemory() {
        if (m_pData)
        {
            if (!m_exists)
            {
                //��ΪERROR_ALREADY_EXISTS˵���ǵ�ǰ���̴�����, ������Ҫ�����������
                OutputDebugStringA("���չ����ڴ�");
                //DeleteCriticalSection(&m_pData->cs);
                UnmapViewOfFile(m_pData);                
            }
            CloseHandle(m_hMapFile);
        }
    }

    template<typename T>
    void CopyToBuffer(const T& data, void* buffer, size_t bufferSize)
    {
        // ����������ʹ�С�Ƿ񳬹���������С
        if (sizeof(T) > bufferSize) {
            throw std::runtime_error("Data structure size exceeds buffer size.");
        }

        std::memcpy(buffer, &data, sizeof(T));
    }

    template<typename T>
    void parseBuffer(const T& data, void* buffer, size_t bufferSize)
    {
        std::memcpy(buffer, &data, bufferSize);
    }

    void Write(SHARED_DATA SharedData) {
        //EnterCriticalSection(&m_pData->cs);
        std::memcpy(&m_pData->ipc_msg, &SharedData.ipc_msg, sizeof(IPC_MSG_RCD));
        //LeaveCriticalSection(&m_pData->cs);
    }

    SHARED_DATA Read() {
        //EnterCriticalSection(&m_pData->cs);
        SHARED_DATA SharedData = { 0 };
        std::memcpy(&SharedData.ipc_msg, &m_pData->ipc_msg, sizeof(IPC_MSG_RCD));
        //LeaveCriticalSection(&m_pData->cs);
        return SharedData;
    }

private:
    std::wstring m_name;
    size_t m_size;
    HANDLE m_hMapFile;
    PSHARED_DATA m_pData;  //�����ڴ�
    DWORD m_Error;
    BOOL m_exists;
};

SharedMemory* InitializeSharedMemory(const std::wstring& name);

#endif // !_SHARED_MEMORY_H
