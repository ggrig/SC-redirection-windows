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
	_CRYPTOAPI_BLOB m_pfxBlob = { 0 };

	inline void freePFXBlob() {
		if (m_pfxBlob.pbData) delete[] m_pfxBlob.pbData;
		m_pfxBlob = { 0 };
	}

public:
	SCD_Crypto();
	~SCD_Crypto() {
		freePFXBlob();
	}

	//std::string Get_SelfSigned_RSAFull_certificate();
	//std::string encrypt_decrypt_test();

	std::string Get_SmartCard_RSAFull_certificate();
	int Export_SelfSigned_RSAFull_certificate();

	bool SignMessage(CRYPT_DATA_BLOB *pSignedMessageBlob, BOOL fDetachedSignature, BYTE* pbMessage);
	bool VerifySignedMessage(
		CRYPT_DATA_BLOB *pSignedMessageBlob,
		CRYPT_DATA_BLOB *pDecodedMessageBlob);
	BOOL Import_SelfSigned_RSAFull_certificate();
};

