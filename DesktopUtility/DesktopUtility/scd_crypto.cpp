#include <fstream>
#include "scd_crypto.h"

#define MAX_CERT_SIMPLE_NAME_STR 1000

void PrintErrorMessage(DWORD dwErr);

// based on https://docs.microsoft.com/en-us/archive/blogs/winsdk/how-to-read-a-certificate-from-a-smart-card-and-add-it-to-the-system-store

void MyHandleError(LPCTSTR psz)
{
	_ftprintf(stderr, TEXT("\nAn error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	PrintErrorMessage(GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	exit(1);
} // End of MyHandleError.


int SCD_Crypto::SmartCardLogon(TCHAR * pPIN)
{
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCERTSTORE hStoreHandle = NULL;
	BOOL fStatus;
	BOOL fSave = FALSE;
	SCARDCONTEXT hSC;
	OPENCARDNAME_EX dlgStruct;

	TCHAR szReader[256];
	TCHAR szCard[256];
	TCHAR pProviderName[256];
	LONG lReturn;
	DWORD lStatus;
	DWORD cchProvider = 256;
	DWORD dwCertLen;
	DWORD dwCertStringLen;
	DWORD dwLogonCertsCount = 0;
	DWORD dwHashLen = CERT_HASH_LENGTH;
	BYTE* pCertBlob = NULL;
	TCHAR * pCertString = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	LPTSTR szMarshaledCred = NULL;


	CHAR pszName[1000];
	DWORD cbName;

	// Establish a context.

	// It will be assigned to the structure's hSCardContext field.

	lReturn = SCardEstablishContext(
		SCARD_SCOPE_USER,
		NULL,
		NULL,
		&hSC);

	if (SCARD_S_SUCCESS != lReturn)
	{
		_tprintf(_T("Failed SCardEstablishContext\n"));
		return 1;
	}

	// Initialize the structure.

	memset(&dlgStruct, 0, sizeof(dlgStruct));
	dlgStruct.dwStructSize = sizeof(dlgStruct);
	dlgStruct.hSCardContext = hSC;
	dlgStruct.dwFlags = SC_DLG_FORCE_UI;
	dlgStruct.lpstrRdr = szReader;
	dlgStruct.nMaxRdr = 256;
	dlgStruct.lpstrCard = szCard;
	dlgStruct.nMaxCard = 256;
	dlgStruct.lpstrTitle = _T("My Select Card Title");

	// Display the select card dialog box.

	lReturn = SCardUIDlgSelectCard(&dlgStruct);

	if (SCARD_S_SUCCESS != lReturn)
	{
		PrintErrorMessage(lReturn);
		MyHandleError(_T("Failed SCardUIDlgSelectCard"));
	}
	_tprintf(_T("Reader: %s\nCard: %s\n"), szReader, szCard);

	lStatus = SCardGetCardTypeProviderName(
		dlgStruct.hSCardContext, // SCARDCONTEXT hContext,
		dlgStruct.lpstrCard, // LPCTSTR szCardName,
		SCARD_PROVIDER_CSP, // DWORD dwProviderId,
		pProviderName, // LPTSTR szProvider,
		&cchProvider // LPDWORD* pcchProvider
	);

	_tprintf(_T("SCardGetCardTypeProviderName returned: %u (a value of 0 is success)\n"), lStatus);

	if (SCARD_S_SUCCESS != lReturn)
	{
		PrintErrorMessage(lStatus);
		MyHandleError(_T("Failed SCardGetCardTypeProviderName"));
	}
	_tprintf(_T("Provider name: %s.\n"), pProviderName);

	fStatus = CryptAcquireContext(
		&hProv, // HCRYPTPROV* phProv,
		NULL, // LPCTSTR pszContainer,
		pProviderName, // LPCTSTR pszProvider,
		PROV_RSA_FULL, // DWORD dwProvType,
		CRYPT_VERIFYCONTEXT // DWORD dwFlags
	);

	if (!fStatus)
	{
		MyHandleError(_T("CryptAcquireContext failed"));
	}

	_tprintf(_T("CryptAcquireContext succeeded.\n"));


	//---------------------------------------------------------------
	// Read the name of the CSP.
	cbName = 1000;
	fStatus = CryptGetProvParam(
		hProv,
		PP_NAME,
		(BYTE*)pszName,
		&cbName,
		0);

	if (!fStatus)
	{
		MyHandleError(TEXT("Error reading CSP name.\n"));
	}
	_tprintf(TEXT("CryptGetProvParam succeeded.\n"));
	printf("Provider name: %s\n", pszName);

	//---------------------------------------------------------------
	// Read the name of the key container.
	cbName = 1000;

	fStatus = CryptGetProvParam(
		hProv,
		PP_ENUMCONTAINERS,
		(BYTE*)pszName,
		&cbName,
		CRYPT_FIRST);

	if (!fStatus)
	{
		MyHandleError(TEXT("Error reading key container name.\n"));
	}
	_tprintf(TEXT("CryptGetProvParam succeeded.\n"));
	printf("Key Container name: %s\n", pszName);

	CryptReleaseContext(hProv, 0);

	fStatus = CryptAcquireContext(
		&hProv, // HCRYPTPROV* phProv,
		pszName, // LPCTSTR pszContainer,
		pProviderName, // LPCTSTR pszProvider,
		PROV_RSA_FULL, // DWORD dwProvType,
		0 // DWORD dwFlags
	);

	if (!fStatus)
	{
		MyHandleError(_T("CryptAcquireContext failed"));
	}
	_tprintf(_T("CryptAcquireContext succeeded.\n"));

	fStatus = CryptGetUserKey(
		hProv, // HCRYPTPROV hProv,
		AT_KEYEXCHANGE, // DWORD dwKeySpec,
		&hKey // HCRYPTKEY* phUserKey
	);

	if (!fStatus)
	{
		MyHandleError(_T("CryptGetUserKey failed"));
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
		MyHandleError(_T("CryptGetKeyParam failed"));
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
		MyHandleError(_T("CryptGetKeyParam failed"));
	}

	_tprintf(_T("CryptGetKeyParam Cert Blob succeeded.\n"));

	CryptReleaseContext(hProv, 0);

	std::ofstream derCertFile("cert.der", std::ios::out | std::ios::binary);
	derCertFile.write((const char *) pCertBlob, dwCertLen);

	fStatus = CryptBinaryToString(
		pCertBlob,
		dwCertLen,
		CRYPT_STRING_BASE64HEADER,
		NULL,
		&dwCertStringLen
	);

	if (!fStatus)
	{
		MyHandleError(_T("CryptBinaryToString failed"));
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
		MyHandleError(_T("CryptBinaryToString failed"));
	}

	_tprintf(_T("CryptBinaryToString succeeded %s\n"), pCertString);

	std::ofstream pemCertFile("cert.pem", std::ios::out | std::ios::binary);
	pemCertFile.write((const char *)pCertString, dwCertStringLen);

	free(pCertBlob);
	free(pCertString);

	return 0;

}