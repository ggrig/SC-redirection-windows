#include "scd_crypto.h"

#define MAX_CERT_SIMPLE_NAME_STR 1000

// based on https://docs.microsoft.com/en-us/archive/blogs/winsdk/how-to-read-a-certificate-from-a-smart-card-and-add-it-to-the-system-store
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
	DWORD dwLogonCertsCount = 0;
	DWORD dwHashLen = CERT_HASH_LENGTH;
	BYTE* pCertBlob;
	PCCERT_CONTEXT pCertContext = NULL;
	LPTSTR szMarshaledCred = NULL;

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
	dlgStruct.lpstrTitle = "My Select Card Title";

	// Display the select card dialog box.

	lReturn = SCardUIDlgSelectCard(&dlgStruct);

	if (SCARD_S_SUCCESS != lReturn)
	{
		_tprintf(_T("Failed SCardUIDlgSelectCard - %x\n"), lReturn);
	}
	else
	{
		_tprintf(_T("Reader: %s\nCard: %s\n"), szReader, szCard);
	}

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
		_tprintf(_T("Failed SCardGetCardTypeProviderName - %u\n"), lStatus);
	}
	else
	{
		_tprintf(_T("Provider name: %s.\n"), pProviderName);
	}

	fStatus = CryptAcquireContext(
		&hProv, // HCRYPTPROV* phProv,
		NULL, // LPCTSTR pszContainer,
		pProviderName, // LPCTSTR pszProvider,
		PROV_RSA_FULL, // DWORD dwProvType,
		0 // DWORD dwFlags
	);

	if (!fStatus)
	{
		_tprintf(_T("CryptAcquireContext failed: 0x%x\n"), GetLastError());
		return 1;
	}
	else
	{
		_tprintf(_T("CryptAcquireContext succeeded.\n"));
	}

	fStatus = CryptGetUserKey(
		hProv, // HCRYPTPROV hProv,
		AT_KEYEXCHANGE, // DWORD dwKeySpec,
		&hKey // HCRYPTKEY* phUserKey
	);

	if (!fStatus)
	{
		_tprintf(_T("CryptGetUserKey failed: 0x%x\n"), GetLastError());
		return 1;
	}
	else
	{
		_tprintf(_T("CryptGetUserKey succeeded.\n"));
	}

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
		_tprintf(_T("CryptGetUserKey failed: 0x%x\n"), GetLastError());
		return 1;
	}
	else
	{
		_tprintf(_T("CryptGetUserKey succeeded.\n"));
	}

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
		_tprintf(_T("CryptGetUserKey failed: 0x%x\n"), GetLastError());
		return 1;
	}
	else
	{
		_tprintf(_T("CryptGetUserKey succeeded.\n"));
	}

	pCertContext = CertCreateCertificateContext(
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		pCertBlob,
		dwCertLen);

	if (pCertContext)
	{

		// Add the certificate to the MY store for the current user.

		// Open Root cert store in users profile

		_tprintf(_T("CertOpenStore... "));

		hStoreHandle = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"My");

		if (!hStoreHandle)
		{
			_tprintf(_T("CertOpenStore failed: 0x%x\n"), GetLastError());
			return 0;
		}

		// Add self-signed cert to the store

		_tprintf(_T("CertAddCertificateContextToStore... "));

		if (!CertAddCertificateContextToStore(hStoreHandle, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0))
		{
			_tprintf(_T("CertAddCertificateContextToStore failed: 0x%x\n"), GetLastError());
			return 0;
		}

		CertFreeCertificateContext(pCertContext);

	}

	return 0;

}