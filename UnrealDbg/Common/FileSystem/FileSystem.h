#pragma once

#ifndef _FILE_SYSTEM_H
#define _FILE_SYSTEM_H

namespace FileSystem
{
    //����ini�ļ�
    void CreateIniFile(const std::wstring& filename);
    //ɾ��ini�ļ�
    bool DeleteIniFile(const std::wstring& filename);
    //����ָ��Ŀ¼�µ��ļ�
    std::vector<std::wstring> TraverseDirectory(const std::wstring& directoryPath);
    std::wstring ReadIniValue(const std::wstring& filename, const std::wstring& section, const std::wstring& key);
    void WriteIniValue(const std::wstring& filename, const std::wstring& section, const std::wstring& key, const std::wstring& value);
    std::wstring GetModuleDirectory(HMODULE hModule);
    std::wstring GetModuleDirectory2(std::wstring path);
    //��ȡ����ģ������
    std::string GetSelfModuleName();
}

#endif // !_FILE_SYSTEM_H
