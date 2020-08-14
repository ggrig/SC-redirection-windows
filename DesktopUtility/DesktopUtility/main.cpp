// DesktopUtility.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <scd_pcsc.h>
#include <tchar.h>

#include <sstream>
#include <iomanip>

#include "scd_smartcardserver.h"
#include "scd_crypto.h"


int main()
{
	SCD_SmartCardServer server;

	server.data = server.cardReader.CheckCard();

	if (server.data.atrvalid)           // if readed ATR code is valid
	{
		int err;

		std::string code = server.getCardCode(&server.data, &err);//hexStr(server.data.data, server.data.datalen);

		_tprintf(_T("ATR %s\n"), code.c_str());
	}
	else
	{
		_tprintf(_T("Error %s\n"), server.data.errmsg);
	}

	SCD_Crypto sc_crypto;
	TCHAR PIN[] = _T("");
	sc_crypto.SmartCardLogon(PIN);
}
