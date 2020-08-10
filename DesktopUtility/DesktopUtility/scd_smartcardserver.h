#ifndef SCD_SMARTCARDSERVER_H
#define SCD_SMARTCARDSERVER_H

#ifdef _WIN32
#include <map>
#include <string>
#else
#include <QObject>
#include <QWebSocketServer>
#include <QWebSocket>
#include <QTimer>
#endif

#include <scd_pcsc.h>

#ifdef _WIN32
class SCD_SmartCardServer
{
#else
class SCD_SmartCardServer : public QObject
{
   Q_OBJECT
#endif
   private:

     enum ServerType {ST_UNKNOWN, ST_STANDALONE, ST_INTEGRATED};

     enum StatusMess {SM_AUTHENTICATED , SM_NOTAUTHENTICATED,SM_VALIDATED,
                      SM_NOTVALIDATED  , SM_ALREADYAUTH     ,SM_SESSIONTIMEOUT,
                      SM_UNKNOWNCOMMAND, SM_INTEGRATED      ,SM_STANDALONE,
                      SM_UNKNOWN,SM_ERROR};

     enum Commands {C_SERVERTYPE, C_ATR, C_LOGIN, C_CHECK, C_AUTH, C_TIMEOUT};

     enum PollingMode {PM_NONE, PM_LOGIN, PM_CHECK};

#ifdef _WIN32
	 std::map<int, std::string> messages;
	 std::map<int, std::string> commands;
	 std::string lastCardError;
#else
     QStringList messages;
     QStringList commands;
     QString lastCardError;
#endif

     StatusMess  lastPollStatus = SM_UNKNOWN;
     PollingMode pollMode       = PM_NONE;
     PollingMode currentPollMode;

     ServerType type;

#ifdef _WIN32
public:

#else
     QWebSocketServer *cardServer;
     QWebSocket *socket;
#endif

     SCD_PCSC cardReader;
     SCD_PCSC::card_data data;

#ifdef _WIN32
	 std::string lastError;
	 std::string atr = "";

	 int16_t port;
#else
     QString lastError;
     QString atr = "";

     qint16 port;
#endif
     int timer = 0;
     int isAuthenticated = 0;

     bool permanentConnection;

#ifdef _WIN32
     std::string getCardCode(SCD_PCSC::card_data *data, int *err);
#else
     QTimer pollTimer;

     QByteArray getCardCode(SCD_PCSC::card_data *data, int *err);
#endif

     void resetAuthentication();

     void startPolling(PollingMode mode);

     void restartPolling();

     void stopPolling();

#ifdef _WIN32
#else
	 void messageParse(QWebSocket *socket, const QString &message);
#endif

   public:

#ifdef _WIN32
#else
	   explicit SCD_SmartCardServer(qint16 port=10522, ServerType type=ST_STANDALONE , QObject *parent = nullptr);
#endif

     int  start();
     void stop();

#ifdef _WIN32
#else
   signals:

     void status(QString command, StatusMess status, bool logout);
     void error(QString command, QString error);
     void serverType(ServerType type);
     void loginCode(QByteArray ATR);

   private slots:

     void onConnect();

     void onCheckCardMessageReceived(const QString &message);    

     void onPolling();
#endif
};

#endif // SCD_SMARTCARDSERVER_H
