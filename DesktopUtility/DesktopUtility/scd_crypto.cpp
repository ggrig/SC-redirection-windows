#include <fstream>
#include <iostream>
#include <scd_pcsc.h>
#include <tchar.h>

#include <sstream>
#include <iomanip>

#include "scd_smartcardserver.h"
#include "scd_crypto.h"

#include <conio.h>

#define MAX_CERT_SIMPLE_NAME_STR 1000
#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4

#define PFX_FILE_NAME "mysite.local.pfx"
#define PFX_FILE_PSW L"123456789"

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

std::string GetErrorString(LPCTSTR psz);

//-------------------------------------------------------------------
//    MyHandleError
void MyHandleError(LPCTSTR psz)
{
	_ftprintf(stderr, GetErrorString(psz).c_str());
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
} // End of MyHandleError

BOOL saveBlobToFile(CRYPT_DATA_BLOB * pBlob, const CHAR * pFileName)
{
	std::ofstream fileStream(pFileName, std::ios::out | std::ios::binary);
	fileStream.write((const char *)pBlob->pbData, pBlob->cbData);

	return 0;
}

BOOL binToBase64(CRYPT_DATA_BLOB * pBin, CRYPT_DATA_BLOB * pBase64)
{
	BOOL fStatus;
	*pBase64 = { 0 };

	do {
		fStatus = CryptBinaryToString(
			pBin->pbData,
			pBin->cbData,
			CRYPT_STRING_BASE64,
			NULL,
			&pBase64->cbData
		);

		if (!fStatus)
		{
			MyHandleError(_T("CryptBinaryToString failed"));
			break;
		}

		_tprintf(_T("CryptBinaryToString succeeded. Length %u\n"), pBase64->cbData);

		pBase64->pbData = (BYTE *)malloc(pBase64->cbData);
		fStatus = CryptBinaryToString(
			pBin->pbData,
			pBin->cbData,
			CRYPT_STRING_BASE64,
			(LPTSTR) pBase64->pbData,
			&pBase64->cbData
		);

		if (!fStatus)
		{
			MyHandleError(_T("CryptBinaryToString failed"));
			break;
		}


	} while (FALSE);

	return fStatus;
}

SCD_Crypto::SCD_Crypto()
{
	memset(m_pContainer, 0, BUFFER_SIZE);
	memset(m_pProviderName, 0, BUFFER_SIZE);
	memset(m_szReader, 0, BUFFER_SIZE);
	memset(m_szCard, 0, BUFFER_SIZE);
}

std::string SCD_Crypto::Get_SmartCard_RSAFull_certificate()
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

		//std::ofstream derCertFile("cert.der", std::ios::out | std::ios::binary);
		//derCertFile.write((const char *)pCertBlob, dwCertLen);

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

		//std::ofstream pemCertFile("cert.pem", std::ios::out | std::ios::binary);
		//pemCertFile.write((const char *)pCertString, dwCertStringLen);

		m_Certificate = pCertString;
		retval = pCertString;

	} while (FALSE);

	if (hKey != 0) CryptDestroyKey(hKey);
	if (hProv != 0) CryptReleaseContext(hProv, 0);
	if (NULL != pCertBlob) free(pCertBlob);
	if (NULL != pCertString) free(pCertString);

	return retval;

}

bool SCD_Crypto::SignMessage_With_SmartCard(CRYPT_DATA_BLOB * pSignedMessageBlob, CRYPT_DATA_BLOB * pData)
{
	bool retval = FALSE;

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
	PCCERT_CONTEXT pSignerCert = NULL;

	DWORD nParamLength = BUFFER_SIZE;

	CRYPT_SIGN_MESSAGE_PARA  SigParams;
	// Create the MessageArray and the MessageSizeArray.
	const BYTE* MessageArray[] = { pData->pbData };
	DWORD MessageSizeArray;
	MessageSizeArray = pData->cbData;

	DWORD cbSignedMessageBlob;
	BYTE  *pbSignedMessageBlob = NULL;

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
			MyHandleError(_T("Failed SCardEstablishContext"));
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
			MyHandleError(_T("Failed SCardUIDlgSelectCard"));
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
			MyHandleError(_T("Failed SCardGetCardTypeProviderName"));
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
			MyHandleError(_T("CryptAcquireContext failed"));
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
			MyHandleError(TEXT("Error reading key container name.\n"));
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
			MyHandleError(_T("CryptAcquireContext failed"));
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
			MyHandleError(_T("CryptGetUserKey failed"));
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
			MyHandleError(_T("CryptGetKeyParam failed"));
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
			MyHandleError(_T("CryptGetKeyParam failed"));
			break;
		}

		_tprintf(_T("CryptGetKeyParam Cert Blob succeeded.\n"));

		pSignerCert = CertCreateCertificateContext(
			MY_ENCODING_TYPE,
			pCertBlob,
			dwCertLen);

		// Initialize the signature structure.
		SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
		SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
		SigParams.pSigningCert = pSignerCert;
		SigParams.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;//szOID_RSA_SHA1RSA;
		SigParams.HashAlgorithm.Parameters.cbData = NULL;
		SigParams.cMsgCert = 1;
		SigParams.rgpMsgCert = &pSignerCert;
		SigParams.cAuthAttr = 0;
		SigParams.dwInnerContentType = 0;
		SigParams.cMsgCrl = 0;
		SigParams.cUnauthAttr = 0;
		SigParams.dwFlags = 0;
		SigParams.pvHashAuxInfo = NULL;
		SigParams.rgAuthAttr = NULL;

		fStatus = CryptSignMessage(
			&SigParams,
			FALSE,
			1,
			MessageArray,
			&MessageSizeArray,
			NULL,
			&cbSignedMessageBlob);

		if (!fStatus)
		{
			MyHandleError(_T("CryptSignMessage - Get blob size failed"));
			break;
		}

		_tprintf(_T("CryptSignMessage Blob Size %u.\n"), cbSignedMessageBlob);

		// Allocate memory for the signed BLOB.
		if (!(pbSignedMessageBlob =
			(BYTE*)malloc(cbSignedMessageBlob)))
		{
			MyHandleError(
				TEXT("Memory allocation error while signing."));
			break;
		}

		fStatus = CryptSignMessage(
			&SigParams,
			FALSE,
			1,
			MessageArray,
			&MessageSizeArray,
			pbSignedMessageBlob,
			&cbSignedMessageBlob);

		if (!fStatus)
		{
			MyHandleError(_T("CryptSignMessage failed"));
			break;
		}

		_tprintf(TEXT("The message was signed successfully. \n"));

		retval = TRUE;

	} while (FALSE);

	if (pSignerCert)
	{
		CertFreeCertificateContext(pSignerCert);
	}

	//if (hCertStore)
	//{
	//	CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	//	hCertStore = NULL;
	//}

	// Only free the signed message if a failure occurred.
	if (retval)
	{
		if (pbSignedMessageBlob)
		{
			free(pbSignedMessageBlob);
			pbSignedMessageBlob = NULL;
		}
	}

	if (pbSignedMessageBlob)
	{
		pSignedMessageBlob->cbData = cbSignedMessageBlob;
		pSignedMessageBlob->pbData = pbSignedMessageBlob;
	}

	if (hKey != 0) CryptDestroyKey(hKey);
	if (hProv != 0) CryptReleaseContext(hProv, 0);
	if (NULL != pCertBlob) free(pCertBlob);

	return retval;

}

#if 0
std::string SCD_Crypto::Get_SelfSigned_RSAFull_certificate()
{
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

		fStatus = CryptAcquireContext(
			&hProv, // HCRYPTPROV* phProv,
			NULL, // LPCTSTR pszContainer,
			NULL, // LPCTSTR pszProvider,
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
		// Read the name of the provider.
		nParamLength = BUFFER_SIZE;
		fStatus = CryptGetProvParam(
			hProv,
			PP_NAME,
			(BYTE*)m_pProviderName,
			&nParamLength,
			0);

		if (!fStatus)
		{
			retval = GetErrorString(TEXT("Error reading key container name.\n"));
			break;
		}
		_tprintf(TEXT("CryptGetProvParam succeeded.\n"));
		printf("Key Provider name: %s\n", m_pProviderName);

		DWORD containerNameSize = 1024;
		TCHAR containerNameLocal[1024];
		if (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, (BYTE*)containerNameLocal, &containerNameSize, CRYPT_FIRST))
		{
			//WString alias;
			//KeyInfo info;
			do
			{
				HCRYPTPROV containerProvider = 0;
				_tprintf(_T("containerNameLocal %s.\n"), containerNameLocal);

				if (!CryptAcquireContextA(&containerProvider, containerNameLocal, 0, PROV_RSA_FULL, 0))
				{
					continue;
				}
				HCRYPTKEY key = 0;
				if (!CryptGetUserKey(containerProvider, AT_SIGNATURE, &key))
				{
					CryptReleaseContext(containerProvider, 0);
					continue;
				}
				DWORD certificateSize = 0;
				if (!CryptGetKeyParam(key, KP_CERTIFICATE, 0, &certificateSize, 0))
				{
					CryptDestroyKey(key);
					CryptReleaseContext(containerProvider, 0);
					continue;
				}
				//KeyInfo info;
				//info.alias = getName(containerProvider, PP_CONTAINER);
				//ByteArray certificate(certificateSize);
				//poco_assert(CryptGetKeyParam(key, KP_CERTIFICATE, (BYTE*)certificate.data(), &certificateSize, 0));
				//certificate.resize(certificateSize);
				//info.certificate = certificate;

				_tprintf(_T("certificateSize %u.\n"), certificateSize);

				CryptDestroyKey(key);
				CryptReleaseContext(containerProvider, 0);

				containerNameSize = 1024;
			} while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, (BYTE*)containerNameLocal, &containerNameSize, CRYPT_NEXT));
		}
		//CryptReleaseContext(enumerationProvider, 0);

/*
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
			AT_SIGNATURE, // DWORD dwKeySpec,
			&hKey // HCRYPTKEY* phUserKey
		);

		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptGetUserKey failed"));
			break;
		}

		_tprintf(_T("CryptGetUserKey succeeded.\n"));


		DWORD dwKeyLen = 0;
		dwCertLen = 4;

		fStatus = CryptGetKeyParam(
			hKey, // HCRYPTKEY hKey,
			KP_KEYLEN, // DWORD dwParam,
			(BYTE *)&dwKeyLen, // BYTE* pbData,
			&dwCertLen, // DWORD* pdwDataLen,
			0 // DWORD dwFlags
		);

		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptGetKeyParam failed"));
			break;
		}

		_tprintf(_T("CryptGetKeyParam Key Length succeeded.\n"));
		_tprintf(_T("dwKeyLen: %u\n"), dwKeyLen);
*/
/*
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
*/
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
	HCRYPTKEY hXchgKey = 0;
	HCRYPTKEY hKey = 0;
	BOOL fStatus;

	DWORD dwKeyBlobLen;
	//DWORD dwCertLen;

	if (m_Certificate.empty())
	{
		retval = Get_SmartCard_RSAFull_certificate();

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

		const CHAR * pin = "116257";

		fStatus = CryptSetProvParam(
			hProv,
			PP_KEYEXCHANGE_PIN,
			(const BYTE *)pin,
			0
		);
		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptSetProvParam failed"));
			break;
		}
		_tprintf(_T("CryptSetProvParam succeeded.\n"));

/*
		fStatus = CryptGenKey(
			hProv,
			ENCRYPT_ALGORITHM,
			KEYLENGTH | CRYPT_EXPORTABLE,
			&hKey);

		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptGenKey failed"));
			break;
		}
		_tprintf(_T("CryptGenKey succeeded.\n"));
*/
		fStatus = CryptGetUserKey(
			hProv, // HCRYPTPROV hProv,
			AT_KEYEXCHANGE, // DWORD dwKeySpec,
			&hXchgKey // HCRYPTKEY* phUserKey
		);

		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptGetUserKey failed"));
			break;
		}
		_tprintf(_T("CryptGetUserKey succeeded.\n"));
/*
		fStatus = CryptGetKeyParam(
			hXchgKey, // HCRYPTKEY hXchgKey,
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
*/
		fStatus = CryptExportKey(
			hKey,
			hXchgKey,
			SIMPLEBLOB,
			0,
			NULL,
			&dwKeyBlobLen);

		if (!fStatus)
		{
			retval = GetErrorString(_T("CryptExportKey failed"));
			break;
		}
		_tprintf(_T("CryptExportKey succeeded: BLOB length %u\n"), dwKeyBlobLen);

/*
		//-----------------------------------------------------------
		// Determine size of the key BLOB, and allocate memory.
		if()
		{
			_tprintf(
				TEXT("The key BLOB is %d bytes long. \n"),
				dwKeyBlobLen);
		}
		else
		{
			MyHandleError(
				TEXT("Error computing BLOB length! \n"),
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		if(pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen))
		{
			_tprintf(
				TEXT("Memory is allocated for the key BLOB. \n"));
		}
		else
		{
			MyHandleError(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
			goto Exit_MyEncryptFile;
		}

*/

	} while (FALSE);


	if (hXchgKey != 0) CryptDestroyKey(hXchgKey);
	if (hProv != 0) CryptReleaseContext(hProv, 0);

	return retval;
}
#endif

// https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-signing-a-message-and-verifying-a-message-signature

// Link with the Crypt32.lib file.
#pragma comment (lib, "Crypt32")

//-------------------------------------------------------------------
//   Define the name of a certificate subject.
//   To use this program, the definition of SIGNER_NAME
//   must be changed to the name of the subject of
//   a certificate that has access to a private key. That certificate
//   must have either the CERT_KEY_PROV_INFO_PROP_ID or 
//   CERT_KEY_CONTEXT_PROP_ID property set for the context to 
//   provide access to the private signature key.

//-------------------------------------------------------------------
//    You can use a command similar to the following to create a 
//    certificate that can be used with this example:
//
//    makecert -n "cn=Test" -sk Test -ss my

//#define SIGNER_NAME L"Insert_signer_name_here"
#define SIGNER_NAME L"test"

//-------------------------------------------------------------------
//    Define the name of the store where the needed certificate
//    can be found. 

#define CERT_STORE_NAME  L"MY"


bool SCD_Crypto::SignMessage(CRYPT_DATA_BLOB * pSignedMessageBlob, CRYPT_DATA_BLOB * pData)
{
	bool fReturn = false;
	
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pSignerCert = NULL;
	CRYPT_SIGN_MESSAGE_PARA  SigParams;
	DWORD cbSignedMessageBlob;
	BYTE  *pbSignedMessageBlob = NULL;

	// Initialize the output pointer.
	pSignedMessageBlob->cbData = 0;
	pSignedMessageBlob->pbData = NULL;

	HCERTSTORE hPFXtoStore = 0;
	DWORD dwImportFlags = CRYPT_EXPORTABLE | CRYPT_USER_KEYSET | PKCS12_NO_PERSIST_KEY;

	// Create the MessageArray and the MessageSizeArray.
	const BYTE* MessageArray[] = { pData->pbData };
	DWORD MessageSizeArray;
	MessageSizeArray = pData->cbData;

	//  Begin processing. 
	_tprintf(TEXT("The message to be signed is \"%s\".\n"),
		pData->pbData);

	if (FALSE == Import_SelfSigned_RSAFull_certificate())
	{
		std::cout << _T("\nImport_SelfSigned_RSAFull_certificate failed");
		goto exit_SignMessage;
	}


	hPFXtoStore = PFXImportCertStore(&m_pfxBlob, PFX_FILE_PSW, dwImportFlags);
	if (hPFXtoStore == NULL)
	{
		std::cout << GetErrorString(_T("\nPFXImportCertStore failed"));
		goto exit_SignMessage;
	}

	// Find the certificate in P12 file (we expect there is only one)
	if (pSignerCert = CertFindCertificateInStore(hPFXtoStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL))
	{
		_tprintf(TEXT("The signer's certificate was found.\n"));
		_tprintf(TEXT("The size, in bytes, of the encoded certificate %u\n"), pSignerCert->cbCertEncoded);
	}
	else
	{
		MyHandleError(TEXT("Signer certificate not found."));
		goto exit_SignMessage;
	}

	// Initialize the signature structure.
	SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
	SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
	SigParams.pSigningCert = pSignerCert;
	SigParams.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;//szOID_RSA_SHA1RSA;
	SigParams.HashAlgorithm.Parameters.cbData = NULL;
	SigParams.cMsgCert = 1;
	SigParams.rgpMsgCert = &pSignerCert;
	SigParams.cAuthAttr = 0;
	SigParams.dwInnerContentType = 0;
	SigParams.cMsgCrl = 0;
	SigParams.cUnauthAttr = 0;
	SigParams.dwFlags = 0;
	SigParams.pvHashAuxInfo = NULL;
	SigParams.rgAuthAttr = NULL;

	// First, get the size of the signed BLOB.
	if (CryptSignMessage(
		&SigParams,
		FALSE,
		1,
		MessageArray,
		&MessageSizeArray,
		NULL,
		&cbSignedMessageBlob))
	{
		_tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"),
			cbSignedMessageBlob);
	}
	else
	{
		MyHandleError(TEXT("Getting signed BLOB size failed"));
		goto exit_SignMessage;
	}

	// Allocate memory for the signed BLOB.
	if (!(pbSignedMessageBlob =
		(BYTE*)malloc(cbSignedMessageBlob)))
	{
		MyHandleError(
			TEXT("Memory allocation error while signing."));
		goto exit_SignMessage;
	}

	// Get the signed message BLOB.
	if (CryptSignMessage(
		&SigParams,
		FALSE,
		1,
		MessageArray,
		&MessageSizeArray,
		pbSignedMessageBlob,
		&cbSignedMessageBlob))
	{
		_tprintf(TEXT("The message was signed successfully. \n"));

		// pbSignedMessageBlob now contains the signed BLOB.
		fReturn = true;
	}
	else
	{
		MyHandleError(TEXT("Error getting signed BLOB"));
		goto exit_SignMessage;
	}

exit_SignMessage:

	// Clean up and free memory as needed.
	if (pSignerCert)
	{
		CertFreeCertificateContext(pSignerCert);
	}

	if (hCertStore)
	{
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
		hCertStore = NULL;
	}

	// Only free the signed message if a failure occurred.
	if (!fReturn)
	{
		if (pbSignedMessageBlob)
		{
			free(pbSignedMessageBlob);
			pbSignedMessageBlob = NULL;
		}
	}

	if (pbSignedMessageBlob)
	{
		pSignedMessageBlob->cbData = cbSignedMessageBlob;
		pSignedMessageBlob->pbData = pbSignedMessageBlob;
	}

	return fReturn;
}

bool SCD_Crypto::GetSignature(CRYPT_DATA_BLOB * pEncodedBlob, CRYPT_DATA_BLOB * pSignatureBlob)
{
	//---------------------------------------------------------------
	//  The following variables are used only in the decoding phase.

	HCRYPTMSG hMsg;

	pSignatureBlob->cbData = 0;
	pSignatureBlob->pbData = 0;

	do {
		//---------------------------------------------------------------
		//  Open a message for decoding.

		if (hMsg = CryptMsgOpenToDecode(
			MY_ENCODING_TYPE,      // encoding type
			0,                     // flags
			0,                     // use the default message type
								   // the message type is 
								   // listed in the message header
			NULL,                  // cryptographic provider 
								   // use NULL for the default provider
			NULL,                  // recipient information
			NULL))                 // stream information
		{
			printf("The message to decode is open. \n");
		}
		else
		{
			MyHandleError("OpenToDecode failed");
		}
		//---------------------------------------------------------------
		//  Update the message with an encoded BLOB.

		if (CryptMsgUpdate(
			hMsg,                 // handle to the message
			pEncodedBlob->pbData, // pointer to the encoded BLOB
			pEncodedBlob->cbData, // size of the encoded BLOB
			TRUE))                // last call
		{
			printf("The encoded BLOB has been added to the message. \n");
		}
		else
		{
			MyHandleError("Decode MsgUpdate failed");
			break;
		}

		//---------------------------------------------------------------
		//  Get the number of bytes needed for a buffer
		//  to hold the decoded message.

		if (CryptMsgGetParam(
			hMsg,                  // handle to the message
			CMSG_ENCRYPTED_DIGEST,    // parameter type
			0,                     // index
			NULL,
			&pSignatureBlob->cbData))           // size of the returned information
		{
			printf("The message parameter has been acquired. \n");
		}
		else
		{
			MyHandleError("Decode CMSG_CONTENT_PARAM failed.");
			break;
		}
		//---------------------------------------------------------------
		// Allocate memory.

		if (!(pSignatureBlob->pbData = (BYTE *)malloc(pSignatureBlob->cbData)))
		{
			MyHandleError("Decode memory allocation failed.");
		}

		//---------------------------------------------------------------
		// Copy the content to the buffer.

		if (CryptMsgGetParam(
			hMsg,                 // handle to the message
			CMSG_ENCRYPTED_DIGEST,   // parameter type
			0,                    // index
			pSignatureBlob->pbData,            // address for returned information
			&pSignatureBlob->cbData))          // size of the returned information
		{
			printf("The signature decoded. The length is %u\n",	pSignatureBlob->cbData);
		}
		else
		{
			MyHandleError("Decode CMSG_CONTENT_PARAM #2 failed");
			break;
		}

	} while (FALSE);


	//---------------------------------------------------------------
	// Verify the signature.
	// First, get the signer CERT_INFO from the message.

	// Clean up.
	//if (pEncodedBlob->pbData)
	//{
	//	free(pEncodedBlob->pbData);
	//	pEncodedBlob->pbData = NULL;
	//}
	if (hMsg)
	{
		CryptMsgClose(hMsg);
	}


	return true;
}

bool SCD_Crypto::VerifySignedMessage(CRYPT_DATA_BLOB * pSignedMessageBlob, CRYPT_DATA_BLOB * pDecodedMessageBlob)
{
	bool fReturn = false;
	DWORD cbDecodedMessageBlob;
	BYTE *pbDecodedMessageBlob = NULL;
	CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

	// Initialize the output.
	pDecodedMessageBlob->cbData = 0;
	pDecodedMessageBlob->pbData = NULL;

	// Initialize the VerifyParams data structure.
	VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
	VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
	VerifyParams.hCryptProv = 0;
	VerifyParams.pfnGetSignerCertificate = NULL;
	VerifyParams.pvGetArg = NULL;

	// First, call CryptVerifyMessageSignature to get the length 
	// of the buffer needed to hold the decoded message.
	if (CryptVerifyMessageSignature(
		&VerifyParams,
		0,
		pSignedMessageBlob->pbData,
		pSignedMessageBlob->cbData,
		NULL,
		&cbDecodedMessageBlob,
		NULL))
	{
		_tprintf(TEXT("%d bytes needed for the decoded message.\n"),
			cbDecodedMessageBlob);

	}
	else
	{
		_tprintf(TEXT("Verification message failed. \n"));
		goto exit_VerifySignedMessage;
	}

	//---------------------------------------------------------------
	//   Allocate memory for the decoded message.
	if (!(pbDecodedMessageBlob =
		(BYTE*)malloc(cbDecodedMessageBlob)))
	{
		MyHandleError(
			TEXT("Memory allocation error allocating decode BLOB."));
		goto exit_VerifySignedMessage;
	}

	//---------------------------------------------------------------
	// Call CryptVerifyMessageSignature again to verify the signature
	// and, if successful, copy the decoded message into the buffer. 
	// This will validate the signature against the certificate in 
	// the local store.
	if (CryptVerifyMessageSignature(
		&VerifyParams,
		0,
		pSignedMessageBlob->pbData,
		pSignedMessageBlob->cbData,
		pbDecodedMessageBlob,
		&cbDecodedMessageBlob,
		NULL))
	{
		_tprintf(TEXT("The verified message is \"%s\".\n"),
			pbDecodedMessageBlob);

		fReturn = true;
	}
	else
	{
		_tprintf(TEXT("Verification message failed. \n"));
	}

exit_VerifySignedMessage:
	// If something failed and the decoded message buffer was 
	// allocated, free it.
	if (!fReturn)
	{
		if (pbDecodedMessageBlob)
		{
			free(pbDecodedMessageBlob);
			pbDecodedMessageBlob = NULL;
		}
	}

	// If the decoded message buffer is still around, it means the 
	// function was successful. Copy the pointer and size into the 
	// output parameter.
	if (pbDecodedMessageBlob)
	{
		pDecodedMessageBlob->cbData = cbDecodedMessageBlob;
		pDecodedMessageBlob->pbData = pbDecodedMessageBlob;
	}

	return fReturn;
}

BOOL SCD_Crypto::getBlobFromFile(CRYPT_DATA_BLOB * pBryptBlob, const CHAR * pFileName)
{
	BOOL retval = TRUE;

	freePFXBlob();

	do {
		std::ifstream pfx_file(pFileName, std::ifstream::binary);

		if (!pfx_file)
		{
			_tprintf(_T("The file \"%s\" not found"), pFileName);
			retval = FALSE;
			break;
		}

		pfx_file.seekg(0, pfx_file.end);
		pBryptBlob->cbData = pfx_file.tellg();
		pfx_file.seekg(0, pfx_file.beg);

		pBryptBlob->pbData = new BYTE[pBryptBlob->cbData];

		//std::cout << "Reading " << pfxBlob.cbData << " characters... ";
		// read data as a block:
		pfx_file.read((CHAR *)pBryptBlob->pbData, pBryptBlob->cbData);

		retval != pfx_file.fail();
		pfx_file.close();

		if (!retval)
		{
			_tprintf(_T("Failed to read the content of the file  \"%s\" "), pFileName);
			retval = FALSE;
			break;
		}

		_tprintf(_T("\nImport successful\n"));
		retval = TRUE;
	} while (FALSE);

	return retval;
}

BOOL SCD_Crypto::Import_SelfSigned_RSAFull_certificate()
{
	BOOL retval = TRUE;
	HCERTSTORE hPFXtoStore = 0;

	freePFXBlob();

	do {

		if (!getBlobFromFile(&m_pfxBlob, PFX_FILE_NAME))
		{
			retval = FALSE;
			break;
		}

		if (FALSE == PFXIsPFXBlob(&m_pfxBlob))  // Check to see if it is a blob
		{
			_tprintf(_T("The file \"%s\" is not a PFX container"), PFX_FILE_NAME);
			retval = FALSE;
			break;
		}

		DWORD dwImportFlags = CRYPT_EXPORTABLE | CRYPT_USER_KEYSET | PKCS12_NO_PERSIST_KEY;

		hPFXtoStore = PFXImportCertStore(&m_pfxBlob, PFX_FILE_PSW, dwImportFlags);
		if (hPFXtoStore == NULL) 
		{
			std::cout << GetErrorString(_T("\nPFXImportCertStore failed"));
			retval = FALSE;
			break;
		}

		_tprintf(_T("\nImport successful\n"));
		retval = TRUE;
	} while (FALSE);

	return retval;
}

// https://groups.google.com/forum/#!topic/microsoft.public.platformsdk.security/Q4xmlRRug-0
/*
int SCD_Crypto::Export_SelfSigned_RSAFull_certificate()
{
	//-------------------------------------------------------------------
	//  Open the store.

	HCERTSTORE  hMemStore = NULL;
	if (hMemStore = CertOpenStore(
		CERT_STORE_PROV_MEMORY,  // A memory store
		0,  // Encoding type not used
		NULL,  // Use the default HCRYPTPROV
		0,  // No flags
		NULL))
	{
		_tprintf(_T("The file store was created successfully.\n"));
	}
	else
	{
		_tprintf(_T("An error occurred during creation of the file store!\n"));
		exit(1);
	}

	//-------------------------------------------------------------------
	// Open a system store, in this case, the My store.

	HCERTSTORE hSysStore = NULL;
	if (hSysStore = CertOpenStore(
		//CERT_STORE_PROV_SYSTEM,  // The store provider type
		//0,  // The encoding type is not needed
		//NULL,  // Use the default HCRYPTPROV
		//CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a	registry location
		//L"MY"  // The store name as a Unicode string
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		CERT_STORE_NAME
	))
	{
		_tprintf(_T("The system store was created successfully.\n"));
	}
	else
	{
		_tprintf(_T("An error occurred during creation of the system store!\n"));
		exit(1);
	}

	//-------------------------------------------------------------------
	// Get a certificate that has lpszCertSubject as its subject.  

	LPCWSTR lpszCertSubject = L"ABC Company";

	PCCERT_CONTEXT  pDesiredCert = NULL;

	if (pDesiredCert = CertFindCertificateInStore(
		//hSysStore,
		//MY_ENCODING_TYPE,  // Use X509_ASN_ENCODING.
		//0,  // No dwFlags needed.
		//CERT_FIND_SUBJECT_STR,  // Find a certificate with a subject that matches the string in the next parameter.
		//lpszCertSubject,  // The Unicode string to be found in a certificate's	subject.
		//NULL
		hSysStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SUBJECT_STR,
		SIGNER_NAME,
		NULL
	))
	{
		_tprintf(_T("The desired certificate was found. \n"));
	}
	else
	{
		_tprintf(_T("Could not find the desired certificate.\n"));
	}

	if (pDesiredCert)
	{
		if (CertAddCertificateContextToStore(
			hMemStore,
			pDesiredCert,
			CERT_STORE_ADD_NEW,
			NULL))
		{
			_tprintf(_T("The certificate context was added to the file store.\n"));
		}
		else
		{
			_tprintf(_T("Could not add the certificate context to the file store.\n"));
		}
	}

	// Create the cer file
	LPCSTR    pszFileName = "test.cer";
	HANDLE    hFile = NULL;

	if (hFile = CreateFile(
		pszFileName,  // The file name
		GENERIC_WRITE,  // Access mode: write to this file
		0,  // Share mode
		NULL,  // Uses the DACL created previously
		CREATE_ALWAYS,  // How to create
		FILE_ATTRIBUTE_NORMAL,  // File attributes
		NULL))  // Template
	{
		_tprintf(_T("The file was created successfully.\n"));
	}
	else
	{
		_tprintf(_T("An error occurred during creating of the file!\n"));
		exit(1);
	}

	//-------------------------------------------------------------------
	// Save the memory store and its certificates to the output file.
	if (CertSaveStore(
		//hSysStore,
		hMemStore,  // Store handle
		MY_ENCODING_TYPE,
		CERT_STORE_SAVE_AS_PKCS7,
		CERT_STORE_SAVE_TO_FILE,
		hFile,  // The handle of an open disk file
		0))  // dwFlags: No flags are needed here.
	{
		_tprintf(_T("Saved the memory store to disk. \n"));
	}
	else
	{
		std::string retval = GetErrorString("Could not save the memory store to disk.\n");
		std::cout << retval;
		exit(1);
	}


	//-------------------------------------------------------------------
	// Clean up.

	if (pDesiredCert && CertFreeCertificateContext(pDesiredCert))
	{
		_tprintf(_T("The certificate context was closed successfully.\n"));
	}
	else
	{
		_tprintf(_T("An error occurred during closing of the certificate context.\n"));
	}

	if (hSysStore && CertCloseStore(
		hSysStore,
		CERT_CLOSE_STORE_CHECK_FLAG))
	{
		_tprintf(_T("The system store was closed successfully.\n"));
	}
	else
	{
		_tprintf(_T("An error occurred during closing of the system store.\n"));
	}

	if (hMemStore && CertCloseStore(
		hMemStore,
		CERT_CLOSE_STORE_CHECK_FLAG))
	{
		_tprintf(_T("The file store was closed successfully.\n"));
	}
	else
	{
		_tprintf(_T("An error occurred during closing of the file store.\n"));
	}

	if (hFile && CloseHandle(hFile))
	{
		_tprintf(_T("The file was closed successfully.\n"));
	}
	else
	{
		_tprintf(_T("An error occurred during closing of the file.\n"));
	}
	return 0;

}
*/