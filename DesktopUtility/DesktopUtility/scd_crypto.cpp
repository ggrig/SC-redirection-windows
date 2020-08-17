#include <fstream>
#include "scd_crypto.h"

#define MAX_CERT_SIMPLE_NAME_STR 1000
#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4

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
	HCRYPTKEY hXchgKey = 0;
	HCRYPTKEY hKey = 0;
	BOOL fStatus;

	DWORD dwKeyBlobLen;
	DWORD dwCertLen;

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

// https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-signing-a-message-and-verifying-a-message-signature

// Link with the Crypt32.lib file.
#pragma comment (lib, "Crypt32")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

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


//-------------------------------------------------------------------
//    MyHandleError
void MyHandleError(LPCTSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
} // End of MyHandleError


bool SCD_Crypto::SignMessage(CRYPT_DATA_BLOB * pSignedMessageBlob)
{
	bool fReturn = false;
	BYTE* pbMessage;
	DWORD cbMessage;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pSignerCert = NULL;
	CRYPT_SIGN_MESSAGE_PARA  SigParams;
	DWORD cbSignedMessageBlob;
	BYTE  *pbSignedMessageBlob = NULL;

	// Initialize the output pointer.
	pSignedMessageBlob->cbData = 0;
	pSignedMessageBlob->pbData = NULL;

	// The message to be signed.
	// Usually, the message exists somewhere and a pointer is
	// passed to the application.
	pbMessage =
		(BYTE*)TEXT("CryptoAPI is a good way to handle security");

	// Calculate the size of message. To include the 
	// terminating null character, the length is one more byte 
	// than the length returned by the strlen function.
	cbMessage = (lstrlen((TCHAR*)pbMessage) + 1) * sizeof(TCHAR);

	// Create the MessageArray and the MessageSizeArray.
	const BYTE* MessageArray[] = { pbMessage };
	DWORD MessageSizeArray;
	MessageSizeArray = cbMessage;

	//  Begin processing. 
	_tprintf(TEXT("The message to be signed is \"%s\".\n"),
		pbMessage);

	// Open the certificate store.
	if (!(hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		CERT_STORE_NAME)))
	{
		MyHandleError(TEXT("The MY store could not be opened."));
		goto exit_SignMessage;
	}

	// Get a pointer to the signer's certificate.
	// This certificate must have access to the signer's private key.
	if (pSignerCert = CertFindCertificateInStore(
		hCertStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SUBJECT_STR,
		SIGNER_NAME,
		NULL))
	{
		_tprintf(TEXT("The signer's certificate was found.\n"));
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
	SigParams.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
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
