#include <iostream>
#include <Windows.h>
#include "../VMProtect/vmp.h"
#include "Crc32.h"

////////////////////////////////////////////////////////////////
// �����ַ�����CRC32ֵ
// ������������CRC32ֵ�ַ������׵�ַ�ʹ�С
// ����ֵ: ����CRC32ֵ

DWORD CRC32(BYTE* first_ptr, DWORD Size)
{
	VMProtectionScope vmpScope;

	DWORD crcTable[256], crcTmp1;

	//��̬����CRC-32��
	for (int i = 0; i < 256; i++)
	{
		crcTmp1 = i;
		for (int j = 8; j > 0; j--)
		{
			if (crcTmp1 & 1) crcTmp1 = (crcTmp1 >> 1) ^ 0xEDB88320L;
			else crcTmp1 >>= 1;
		}

		crcTable[i] = crcTmp1;
	}
	//����CRC32ֵ
	DWORD crcTmp2 = 0xFFFFFFFF;
	while (Size--)
	{
		crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*first_ptr)) & 0xFF];
		first_ptr++;
	}

	return ~(crcTmp2 ^ 0xFFFFFFFF);
}