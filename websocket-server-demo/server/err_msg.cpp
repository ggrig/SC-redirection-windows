// based on https://docs.microsoft.com/en-us/windows/win32/seccrypto/retrieving-error-messages

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

// Get error message text, given an error code.
// Typically, the dwErr parameter passed to this function is retrieved
// from GetLastError().

void GetCSBackupAPIErrorMessage(DWORD dwErr, TCHAR * wszMsgBuff)
{

	DWORD   dwChars;  // Number of chars returned.

	// Try to get the message from the system errors.
	dwChars = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErr,
		0,
		wszMsgBuff,
		512,
		NULL);

	if (0 == dwChars)
	{
		// The error code did not exist in the system errors.
		// Try Ntdsbmsg.dll for the error code.

		HINSTANCE hInst;

		// Load the library.
		hInst = LoadLibrary(_T("Ntdsbmsg.dll"));
		if (NULL == hInst)
		{
			printf("cannot load Ntdsbmsg.dll\n");
			exit(1);  // Could 'return' instead of 'exit'.
		}

		// Try getting message text from ntdsbmsg.
		dwChars = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			hInst,
			dwErr,
			0,
			wszMsgBuff,
			512,
			NULL);

		// Free the library.
		FreeLibrary(hInst);
	}
}