#pragma once
#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <tchar.h>

#define BUFFER_SIZE 256

class SCD_Crypto
{
	CHAR m_pContainer[BUFFER_SIZE];
	CHAR m_pProviderName[BUFFER_SIZE];
	CHAR m_szReader[BUFFER_SIZE];
	CHAR m_szCard[BUFFER_SIZE];

	std::string m_Certificate;

public:
	SCD_Crypto();

	std::string GetSC_RSAFull_certificate();
	std::string encrypt_decrypt_test();
};

