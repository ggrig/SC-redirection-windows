#include <fstream>
#include "scd_crypto.h"

#define MAX_CERT_SIMPLE_NAME_STR 1000

std::string GetErrorString(LPCTSTR psz);

SCD_Crypto::SCD_Crypto()
{
	memset(m_pContainer, 0, BUFFER_SIZE);
	memset(m_pProviderName, 0, BUFFER_SIZE);
	memset(m_szReader, 0, BUFFER_SIZE);
	memset(m_szCard, 0, BUFFER_SIZE);
}

std::string SCD_Crypto::GetSC_RSAFull_certificate()
{
// based on https://docs.microsoft.com/en-us/archive/blogs/winsdk/how-to-read-a-certificate-from-a-smart-card-and-add-it-to-the-system-store

	std::string retval;

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	BOOL fStatus;
	SCARDCONTEXT hSC;
	OPENCARDNAME_EX dlgStruct;

	LONG lReturn;
	DWORD lStatus;
	DWORD dwCertLen;
	DWORD dwCertStringLen;
	BYTE* pCertBlob = NULL;
	TCHAR * pCertString = NULL;
	PCCERT_CONTEXT pCertContext = NULL;

	DWORD nParamLength = BUFFER_SIZE;

	m_Certificate.clear();

	// Establish a context.

	// It will be assigned to the structure's hSCardContext field.
do {

	lReturn = SCardEstablishContext(
		SCARD_SCOPE_USER,
		NULL,
		NULL,
		&hSC);

	if (SCARD_S_SUCCESS != lReturn)
	{
		SetLastError(lReturn);
		retval = GetErrorString(_T("Failed SCardEstablishContext"));
		break;
	}

	// Initialize the structure.

	memset(&dlgStruct, 0, sizeof(dlgStruct));
	dlgStruct.dwStructSize = sizeof(dlgStruct);
	dlgStruct.hSCardContext = hSC;
	dlgStruct.dwFlags = SC_DLG_FORCE_UI;
	dlgStruct.lpstrRdr = m_szReader;
	dlgStruct.nMaxRdr = BUFFER_SIZE;
	dlgStruct.lpstrCard = m_szCard;
	dlgStruct.nMaxCard = BUFFER_SIZE;
	dlgStruct.lpstrTitle = _T("My Select Card Title");

	// Display the select card dialog box.

	lReturn = SCardUIDlgSelectCard(&dlgStruct);

	if (SCARD_S_SUCCESS != lReturn)
	{
		SetLastError(lReturn);
		retval = GetErrorString(_T("Failed SCardUIDlgSelectCard"));
		break;
	}
	_tprintf(_T("Reader: %s\nCard: %s\n"), m_szReader, m_szCard);

	nParamLength = BUFFER_SIZE;
	lStatus = SCardGetCardTypeProviderName(
		dlgStruct.hSCardContext, // SCARDCONTEXT hContext,
		dlgStruct.lpstrCard, // LPCTSTR szCardName,
		SCARD_PROVIDER_CSP, // DWORD dwProviderId,
		m_pProviderName, // LPTSTR szProvider,
		&nParamLength // LPDWORD* pcchProvider
	);

	_tprintf(_T("SCardGetCardTypeProviderName returned: %u (a value of 0 is success)\n"), lStatus);

	if (SCARD_S_SUCCESS != lReturn)
	{
		SetLastError(lStatus);
		retval = GetErrorString(_T("Failed SCardGetCardTypeProviderName"));
		break;
	}
	_tprintf(_T("Provider name: %s.\n"), m_pProviderName);

	fStatus = CryptAcquireContext(
		&hProv, // HCRYPTPROV* phProv,
		NULL, // LPCTSTR pszContainer,
		m_pProviderName, // LPCTSTR pszProvider,
		PROV_RSA_FULL, // DWORD dwProvType,
		CRYPT_VERIFYCONTEXT // DWORD dwFlags
	);

	if (!fStatus)
	{
		retval = GetErrorString(_T("CryptAcquireContext failed"));
		break;
	}

	_tprintf(_T("CryptAcquireContext succeeded.\n"));

	//---------------------------------------------------------------
	// Read the name of the key container.
	nParamLength = BUFFER_SIZE;
	fStatus = CryptGetProvParam(
		hProv,
		PP_ENUMCONTAINERS,
		(BYTE*)m_pContainer,
		&nParamLength,
		CRYPT_FIRST);

	if (!fStatus)
	{
		retval = GetErrorString(TEXT("Error reading key container name.\n"));
		break;
	}
	_tprintf(TEXT("CryptGetProvParam succeeded.\n"));
	printf("Key Container name: %s\n", m_pContainer);

	CryptReleaseContext(hProv, 0);
	hProv = 0;

	fStatus = CryptAcquireContext(
		&hProv, // HCRYPTPROV* phProv,
		m_pContainer, // LPCTSTR pszContainer,
		m_pProviderName, // LPCTSTR pszProvider,
		PROV_RSA_FULL, // DWORD dwProvType,
		0 // DWORD dwFlags
	);

	if (!fStatus)
	{
		retval = GetErrorString(_T("CryptAcquireContext failed"));
		break;
	}
	_tprintf(_T("CryptAcquireContext succeeded.\n"));

	fStatus = CryptGetUserKey(
		hProv, // HCRYPTPROV hProv,
		AT_KEYEXCHANGE, // DWORD dwKeySpec,
		&hKey // HCRYPTKEY* phUserKey
	);

	if (!fStatus)
	{
		retval = GetErrorString(_T("CryptGetUserKey failed"));
		break;
	}

	_tprintf(_T("CryptGetUserKey succeeded.\n"));

	dwCertLen = 0;

	fStatus = CryptGetKeyParam(
		hKey, // HCRYPTKEY hKey,
		KP_CERTIFICATE, // DWORD dwParam,
		NULL, // BYTE* pbData,
		&dwCertLen, // DWORD* pdwDataLen,
		0 // DWORD dwFlags
	);

	if (!fStatus)
	{
		retval = GetErrorString(_T("CryptGetKeyParam failed"));
		break;
	}

	_tprintf(_T("CryptGetKeyParam Cert Length succeeded.\n"));
	_tprintf(_T("dwCertLen: %u\n"), dwCertLen);

	pCertBlob = (BYTE*)malloc(dwCertLen);
	fStatus = CryptGetKeyParam(
		hKey, // HCRYPTKEY hKey,
		KP_CERTIFICATE, // DWORD dwParam,
		pCertBlob, // BYTE* pbData,
		&dwCertLen, // DWORD* pdwDataLen,
		0 // DWORD dwFlags
	);

	if (!fStatus)
	{
		retval = GetErrorString(_T("CryptGetKeyParam failed"));
		break;
	}

	_tprintf(_T("CryptGetKeyParam Cert Blob succeeded.\n"));

	CryptReleaseContext(hProv, 0);
	hProv = 0;

	std::ofstream derCertFile("cert.der", std::ios::out | std::ios::binary);
	derCertFile.write((const char *)pCertBlob, dwCertLen);

	fStatus = CryptBinaryToString(
		pCertBlob,
		dwCertLen,
		CRYPT_STRING_BASE64HEADER,
		NULL,
		&dwCertStringLen
	);

	if (!fStatus)
	{
		retval = GetErrorString(_T("CryptBinaryToString failed"));
		break;
	}

	_tprintf(_T("CryptBinaryToString succeeded. Length %u\n"), dwCertStringLen);

	pCertString = (TCHAR*)malloc(dwCertStringLen);
	fStatus = CryptBinaryToString(
		pCertBlob,
		dwCertLen,
		CRYPT_STRING_BASE64HEADER,
		pCertString,
		&dwCertStringLen
	);

	if (!fStatus)
	{
		retval = GetErrorString(_T("CryptBinaryToString failed"));
		break;
	}

	std::ofstream pemCertFile("cert.pem", std::ios::out | std::ios::binary);
	pemCertFile.write((const char *)pCertString, dwCertStringLen);

	m_Certificate = pCertString;
	retval = pCertString;

} while (FALSE);

	if (hKey != 0) CryptDestroyKey(hKey);
	if (hProv != 0) CryptReleaseContext(hProv, 0);
	if (NULL != pCertBlob) free(pCertBlob);
	if (NULL != pCertString) free(pCertString);

	return retval;

}

std::string SCD_Crypto::encrypt_decrypt_test()
{
	std::string retval;
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	BOOL fStatus;

	if (m_Certificate.empty())
	{
		retval = GetSC_RSAFull_certificate();

		if (m_Certificate.empty())
		{
			return retval;
		}

		retval.clear();
	}

	do {
		fStatus = CryptAcquireContext(
			&hProv, // HCRYPTPROV* phProv,
			m_pContainer, // LPCTSTR pszContainer,
			m_pProviderName, // LPCTSTR pszProvider,
			PROV_RSA_FULL, // DWORD dwProvType,
			0 // DWORD dwFlags
		);

		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptAcquireContext failed"));
			break;
		}
		_tprintf(_T("CryptAcquireContext succeeded.\n"));

		fStatus = CryptGetUserKey(
			hProv, // HCRYPTPROV hProv,
			AT_KEYEXCHANGE, // DWORD dwKeySpec,
			&hKey // HCRYPTKEY* phUserKey
		);

		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptGetUserKey failed"));
			break;
		}

		_tprintf(_T("CryptGetUserKey succeeded.\n"));

	} while (FALSE);


	if (hKey != 0) CryptDestroyKey(hKey);
	if (hProv != 0) CryptReleaseContext(hProv, 0);

	return retval;
}
