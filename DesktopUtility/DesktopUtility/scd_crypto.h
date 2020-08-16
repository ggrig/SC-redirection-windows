#pragma once
#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <tchar.h>

class SCD_Crypto
{
public:
	std::string certificate;

	std::string GetSC_RSAFull_certificate();
	BOOL encrypt_decrypt_test();
};

