// DesktopUtility.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <scd_pcsc.h>

#include <sstream>
#include <iomanip>

std::string hexStr(BYTE *data, int len);

int main()
{

	SCD_PCSC cardReader;
	SCD_PCSC::card_data data;

	data = cardReader.CheckCard();

	if (data.atrvalid)           // if readed ATR code is valid
	{
		//code = getCardCode(&data, &err);

		//qDebug() << "Login: " << code << "\n";

		//socket->sendTextMessage(msg[0] + "|atr:" + code); // send ATR to client

		std::string code = hexStr(data.data, data.datalen);

		printf("ATR %s\n", code.c_str());
	}
	else
	{
		//qDebug() << data.errmsg << "\n";

		//emit error(msg[0], data.errmsg);

		//socket->sendTextMessage(msg[0] + "|" + data.errmsg);

		printf("Error %s\n", data.errmsg);
	}

}
