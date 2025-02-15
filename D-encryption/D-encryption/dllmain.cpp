#include "dllmain.h"


#pragma comment(lib, "advapi32.lib")

void EncryptDataToFile(TCHAR* data, TCHAR* filename, TCHAR* userKey)
{
    try
    {
        if (data && filename && userKey)
        {
            std::string _data = Common::wideStringToString(data);
            std::string _filename = Common::wideStringToString(filename);
            std::string _userKey = Common::wideStringToString(userKey);            
            EncryptDataToFile_internal(_data, _filename, _userKey);
        }
    }
    catch (const std::exception& e)
    {
        Common::ReportSeriousError("%s[%d]  %s", __func__, __LINE__, e.what());
    }
}

int DecryptDataFromFile(TCHAR* filename, TCHAR* userKey, TCHAR* decryptedData)
{
    int decryptedDataLen = 0;
    try
    {
        if (filename && userKey)
        {
            std::string _filename = Common::wideStringToString2(filename);
            std::string _userKey = Common::wideStringToString(userKey);
            std::string _decryptedData;
            DecryptDataFromFile_internal(_filename, _userKey, _decryptedData);

            std::wstring ws_decryptedData = Common::stringToWideString(_decryptedData);
            decryptedDataLen = (ws_decryptedData.length() + 1) * sizeof(WCHAR);

            if (decryptedData)
            {
                // ��������
                wcscpy(decryptedData, ws_decryptedData.c_str());
            }
        }
    }
    catch (const std::exception& e)
    {
        Common::ReportSeriousError("%s[%d]  %s", __func__, __LINE__, e.what());
        //Common::ReportSeriousError("%s[%d] ��������ʧ��! (error: %d)", __func__, __LINE__, GetLastError());
    }
    return decryptedDataLen;
}



void EncryptDataToFile_internal(const std::string& data, const std::string& filename, const std::string& userKey)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE* pbData = (BYTE*)data.c_str();
    DWORD dwPlainTextLen = data.length();
    DWORD dwBufLen = dwPlainTextLen;

    // 1. Acquire a cryptographic provider context
    // ��ȡ�����ṩ����������
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return;
    }

    // 2. Create a hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return;
    }

    // 3. Hash the data (you can also use a password)
    // �����ݽ��й�ϣ������Ҳ����ʹ�����룩
    if (!CryptHashData(hHash, (BYTE*)userKey.c_str(), userKey.length(), 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // 4. Derive a key from the hash
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    //������ĳ���
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dwBufLen, 0)) {
        std::cerr << "CryptEncrypt (size) failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }


    // 5. Encrypt the data
    BYTE* pbCipherText = new BYTE[dwBufLen + 1];  //�������Ļ�����
    memset(pbCipherText, 0, dwBufLen + 1);
    memcpy(pbCipherText, pbData, dwPlainTextLen);  //������������

    DWORD tmp = dwPlainTextLen;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, pbCipherText, &tmp, dwBufLen + 1)) {
        std::cerr << "CryptEncrypt failed: " << GetLastError() << std::endl;
        delete[] pbCipherText;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // 6. Write the encrypted data to a file
    std::ofstream outFile(filename, std::ios::binary);
    outFile.write((char*)pbCipherText, dwBufLen);
    outFile.close();

    // Clean up
    delete[] pbCipherText;
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}


void DecryptDataFromFile_internal(const std::string& filename, const std::string& userKey, std::string& decryptedData)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE* pbCipherText = nullptr;
    DWORD dwCipherTextLen = 0;

    // 1. Acquire a cryptographic provider context
    // ��ȡ�����ṩ����������
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return;
    }

    // 2. Create a hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return;
    }

    // 3. Hash the user key
    if (!CryptHashData(hHash, (BYTE*)userKey.c_str(), userKey.length(), 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // 4. Derive a key from the hash
    // �ӹ�ϣ�е�����Կ
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // 5. Read the encrypted data from the file
    // ���ļ��ж�ȡ��������
    std::ifstream inFile(filename, std::ios::binary | std::ios::ate);
    if (!inFile.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    dwCipherTextLen = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    pbCipherText = new BYTE[dwCipherTextLen + 1];
    memset(pbCipherText, 0, dwCipherTextLen + 1);
    inFile.read((char*)pbCipherText, dwCipherTextLen);
    inFile.close();

    // 6. Decrypt the data
    // ��������
    DWORD dwPlainTextLen = dwCipherTextLen;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, pbCipherText, &dwPlainTextLen)) {
        std::cerr << "CryptDecrypt failed: " << GetLastError() << std::endl;
        delete[] pbCipherText;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // 7. Convert decrypted data to string
    // ����������ת��Ϊ�ַ���
    decryptedData.assign((char*)pbCipherText, dwPlainTextLen);

    // Clean up
    delete[] pbCipherText;
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}