#pragma once

#ifndef _MD5_H
#define _MD5_H

//�����ļ�md5
std::string calculateMD5(const std::string& filePath);
//�ֽ�����ϣժҪ
std::string calculateMD5(const std::vector<unsigned char>& data);
//���ַ������й�ϣժҪ
std::string calculateMD5(const TCHAR* inputParam);

#endif // !_MD5_H
