#ifndef SCD_PCSC_H
#define SCD_PCSC_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#else
#include <wintypes.h>
#endif
#include <winscard.h>

#ifdef _WIN32
#define MAX_ATR_SIZE 33
#define MAX_READERNAME 128

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#endif

class SCD_PCSC
{
   public:

     struct card_data
     {
        int freeError = 0;  // error on free resource
        int error     = 0;  // card error
        int atrvalid  = 0;  // set to 1 if readed atrcode is valid

        TCHAR *errmsg; // card error message
        TCHAR *freeErrMsg = NULL; // free resource error message

        unsigned char *data   = NULL; // readed data buffer
        unsigned int  datalen = 0;    // data len (bytes)
     };

   private:

     BYTE pbAtr[MAX_ATR_SIZE];

     TCHAR pbReader[MAX_READERNAME];

     TCHAR msg[1024];       // card message

     TCHAR lastError[1024]; // last error message

     TCHAR *ptr;
     TCHAR **readers = NULL; // array of readers;

     int nbReaders; // readers number
     int reader_nb;

     LPTSTR mszReaders = NULL;

     SCARDHANDLE  hCard;    // card handle
     SCARDCONTEXT hContext; // current card context

     DWORD dwActiveProtocol;
     DWORD dwReaderLen;
     DWORD dwState;
     DWORD dwProt;
     DWORD dwAtrLen;
     DWORD dwReaders;

     void init();

     int freeResource(card_data *card);

   public:

     SCD_PCSC();

     struct card_data CheckCard();
};

#endif // SCD_PCSC_H
