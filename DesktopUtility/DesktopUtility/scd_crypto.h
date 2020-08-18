#pragma once
#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <tchar.h>

#define BUFFER_SIZE 1024

class SCD_Crypto
{
	CHAR m_pContainer[BUFFER_SIZE];
	CHAR m_pProviderName[BUFFER_SIZE];
	CHAR m_szReader[BUFFER_SIZE];
	CHAR m_szCard[BUFFER_SIZE];

	std::string m_Certificate;

public:
	SCD_Crypto();

	std::string Get_SmartCard_RSAFull_certificate();
	std::string Get_SelfSigned_RSAFull_certificate();
	int Export_SelfSigned_RSAFull_certificate();
	std::string encrypt_decrypt_test();

	bool SignMessage(CRYPT_DATA_BLOB *pSignedMessageBlob);
	bool VerifySignedMessage(
		CRYPT_DATA_BLOB *pSignedMessageBlob,
		CRYPT_DATA_BLOB *pDecodedMessageBlob);
	HCERTSTORE Import_SelfSigned_RSAFull_certificate();
};

