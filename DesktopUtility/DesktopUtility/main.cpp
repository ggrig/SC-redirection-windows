// DesktopUtility.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <scd_pcsc.h>

#include <sstream>
#include <iomanip>

#include "scd_smartcardserver.h"

int main()
{
	SCD_SmartCardServer server;

	server.data = server.cardReader.CheckCard();

	if (server.data.atrvalid)           // if readed ATR code is valid
	{
		int err;

		std::string code = server.getCardCode(&server.data, &err);//hexStr(server.data.data, server.data.datalen);

		printf("ATR %s\n", code.c_str());
	}
	else
	{
		printf("Error %s\n", server.data.errmsg);
	}

}
