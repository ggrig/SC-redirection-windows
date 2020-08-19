// DesktopUtility.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <scd_pcsc.h>
#include <tchar.h>

#include <sstream>
#include <iomanip>

#include "scd_smartcardserver.h"
#include "scd_crypto.h"

#include <conio.h>


int main()
{
	SCD_SmartCardServer server;
	SCD_Crypto sc_crypto;

/*
	server.data = server.cardReader.CheckCard();

	if (!server.data.atrvalid)           // if readed ATR code is valid
	{
		_tprintf(_T("Error %s\n"), server.data.errmsg);
		return 0;
	}

	int err;

	std::string code = server.getCardCode(&server.data, &err);//hexStr(server.data.data, server.data.datalen);
	_tprintf(_T("ATR %s\n"), code.c_str());

	std::string retval = sc_crypto.Get_SmartCard_RSAFull_certificate();
	//std::string retval = sc_crypto.encrypt_decrypt_test();
	std::cout << retval;
*/

	CRYPT_DATA_BLOB SignedMessage;
	CRYPT_DATA_BLOB Data;

	sc_crypto.getBlobFromFile(&Data, _T("msg"));

	if (sc_crypto.SignMessage(&SignedMessage, &Data))
	{
		CRYPT_DATA_BLOB Signature;
		CRYPT_DATA_BLOB DecodedMessage;

		if (sc_crypto.GetSignature(&SignedMessage, &Signature))
		{
			sc_crypto.saveBlobToFile(&Signature, "sig.bin");
		}

		if (sc_crypto.VerifySignedMessage(&SignedMessage, &DecodedMessage))
		{
			free(DecodedMessage.pbData);
		}

		free(SignedMessage.pbData);
	}

	_tprintf(TEXT("Press any key to exit."));
	_getch();

}
