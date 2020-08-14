#pragma once
#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <tchar.h>

class SCD_Crypto
{
public:
	int SmartCardLogon(TCHAR * pPIN);
};

