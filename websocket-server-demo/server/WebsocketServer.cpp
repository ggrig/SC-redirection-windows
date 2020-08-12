#include "WebsocketServer.h"

#include <algorithm>
#include <functional>
#include <iostream>

//The name of the special JSON field that holds the message type for messages
#define MESSAGE_FIELD "__MESSAGE__"

#pragma warning(push)
#pragma warning(disable: 4996) //4996 for _CRT_SECURE_NO_WARNINGS equivalent
// deprecated code here
Json::Value WebsocketServer::parseJson(const string& json)
{
	Json::Value root;
	Json::Reader reader;
	reader.parse(json, root);
	return root;
}
#pragma warning(pop)

string WebsocketServer::stringifyJson(const Json::Value& val)
{
	//When we transmit JSON data, we omit all whitespace
	Json::StreamWriterBuilder wbuilder;
	wbuilder["commentStyle"] = "None";
	wbuilder["indentation"] = "";
	
	return Json::writeString(wbuilder, val);
}

WebsocketServer::WebsocketServer(int16_t port, ServerType type) : type(type), port(port)
{
	//Wire up our event handlers
	this->endpoint.set_open_handler(std::bind(&WebsocketServer::onOpen, this, std::placeholders::_1));
	this->endpoint.set_close_handler(std::bind(&WebsocketServer::onClose, this, std::placeholders::_1));
	this->endpoint.set_message_handler(std::bind(&WebsocketServer::onMessage, this, std::placeholders::_1, std::placeholders::_2));
	
	//Initialise the Asio library, using our own event loop object
	this->endpoint.init_asio(&(this->eventLoop));

	messages.insert(std::pair<int, std::string>(SM_AUTHENTICATED, "Authenticated"));
	messages.insert(std::pair<int, std::string>(SM_NOTAUTHENTICATED, "NotAuthenticated"));
	messages.insert(std::pair<int, std::string>(SM_VALIDATED, "Validated"));
	messages.insert(std::pair<int, std::string>(SM_NOTVALIDATED, "NotValidated"));
	messages.insert(std::pair<int, std::string>(SM_ALREADYAUTH, "AlreadyAuthenticated"));
	messages.insert(std::pair<int, std::string>(SM_SESSIONTIMEOUT, "SessionExpired"));
	messages.insert(std::pair<int, std::string>(SM_UNKNOWNCOMMAND, "UnknownCommand"));
	messages.insert(std::pair<int, std::string>(SM_INTEGRATED, "Integrated"));
	messages.insert(std::pair<int, std::string>(SM_STANDALONE, "Standalone"));
	messages.insert(std::pair<int, std::string>(SM_UNKNOWN, "Unknown"));

	commands.insert(std::pair<int, std::string>(C_SERVERTYPE, "SERVERTYPE"));
	commands.insert(std::pair<int, std::string>(C_ATR, "ATRCODE"));
	commands.insert(std::pair<int, std::string>(C_LOGIN, "LOGINCODE"));
	commands.insert(std::pair<int, std::string>(C_CHECK, "CHECKCODE"));
	commands.insert(std::pair<int, std::string>(C_AUTH, "AUTHCODE"));
	commands.insert(std::pair<int, std::string>(C_TIMEOUT, "POLLTIMEOUT"));

}

void WebsocketServer::run()
{
	//Listen on the specified port number and start accepting connections
	this->endpoint.listen(port);
	this->endpoint.start_accept();
	
	//Start the Asio event loop
	this->endpoint.run();
}

size_t WebsocketServer::numConnections()
{
	//Prevent concurrent access to the list of open connections from multiple threads
	std::lock_guard<std::mutex> lock(this->connectionListMutex);
	
	return this->openConnections.size();
}

void WebsocketServer::sendMessage(ClientConnection conn, const string& messageType, const Json::Value& arguments)
{
	//Copy the argument values, and bundle the message type into the object
	Json::Value messageData = arguments;
	messageData[MESSAGE_FIELD] = messageType;
	
	//Send the JSON data to the client (will happen on the networking thread's event loop)
	this->endpoint.send(conn, WebsocketServer::stringifyJson(messageData), websocketpp::frame::opcode::text);
}

void WebsocketServer::broadcastMessage(const string& messageType, const Json::Value& arguments)
{
	//Prevent concurrent access to the list of open connections from multiple threads
	std::lock_guard<std::mutex> lock(this->connectionListMutex);
	
	for (auto conn : this->openConnections) {
		this->sendMessage(conn, messageType, arguments);
	}
}

void WebsocketServer::onOpen(ClientConnection conn)
{
	{
		//Prevent concurrent access to the list of open connections from multiple threads
		std::lock_guard<std::mutex> lock(this->connectionListMutex);
		
		//Add the connection handle to our list of open connections
		this->openConnections.push_back(conn);
	}
	
	//Invoke any registered handlers
	for (auto handler : this->connectHandlers) {
		handler(conn);
	}
}

void WebsocketServer::onClose(ClientConnection conn)
{
	{
		//Prevent concurrent access to the list of open connections from multiple threads
		std::lock_guard<std::mutex> lock(this->connectionListMutex);
		
		//Remove the connection handle from our list of open connections
		auto connVal = conn.lock();
		auto newEnd = std::remove_if(this->openConnections.begin(), this->openConnections.end(), [&connVal](ClientConnection elem)
		{
			//If the pointer has expired, remove it from the vector
			if (elem.expired() == true) {
				return true;
			}
			
			//If the pointer is still valid, compare it to the handle for the closed connection
			auto elemVal = elem.lock();
			if (elemVal.get() == connVal.get()) {
				return true;
			}
			
			return false;
		});
		
		//Truncate the connections vector to erase the removed elements
		this->openConnections.resize(std::distance(openConnections.begin(), newEnd));
	}

	//Invoke any registered handlers
	for (auto handler : this->disconnectHandlers) {
		handler(conn);
	}
}

void WebsocketServer::onMessage(ClientConnection conn, WebsocketEndpoint::message_ptr msg)
{
	if (messageParse(conn, msg->get_payload()))
	{
		return;
	}

	//Validate that the incoming message contains valid JSON
	Json::Value messageObject = WebsocketServer::parseJson(msg->get_payload());
	if (messageObject.isNull() == false)
	{
		//Validate that the JSON object contains the message type field
		if (messageObject.isMember(MESSAGE_FIELD))
		{
			//Extract the message type and remove it from the payload
			std::string messageType = messageObject[MESSAGE_FIELD].asString();
			messageObject.removeMember(MESSAGE_FIELD);
			
			//If any handlers are registered for the message type, invoke them
			auto& handlers = this->messageHandlers[messageType];
			for (auto handler : handlers) {
				handler(conn, messageObject);
			}
		}
	}
}

std::string hexStr(BYTE *data, int len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i(0); i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];

	return ss.str();
}

std::string WebsocketServer::getCardCode(SCD_PCSC::card_data *data, int *err)
{
	std::string cdata;

	*err = data->error;

	if (data->error)
	{
		cdata = data->errmsg;

		return cdata;
	}

	cdata = hexStr(data->data, data->datalen);

	return cdata;
}

/**
 * @brief WebsocketServer::resetAuthentication
 */
void WebsocketServer::resetAuthentication()
{
	isAuthenticated = 0;
	atr = "";
}

void split(const string& s, char c,
	vector<string>& v) {
	string::size_type i = 0;
	string::size_type j = s.find(c);

	while (j != string::npos) {
		v.push_back(s.substr(i, j - i));
		i = ++j;
		j = s.find(c, j);

		if (j == string::npos)
			v.push_back(s.substr(i, s.length()));
	}
}


/**
 * @brief WebsocketServer::messageParse
 * @param conn
 * @param message
 */
boolean WebsocketServer::messageParse(ClientConnection conn, string message)
{

	string code;
	int err;

	// convert string to upper case
	std::for_each(message.begin(), message.end(), [](char & c) {
		c = ::toupper(c);
	});

	std::clog << "Message Received: " << message << "\n";

	vector<string> msg;

	split(message, ':', msg);


	if (msg.size() != 2)
	{
		std::clog << messages.at(SM_UNKNOWNCOMMAND) << "\n";

		//emit error(msg[0], messages.at(SM_UNKNOWNCOMMAND));

		//socket->close(); // close suspect connection

		return false;
	}
/*
	// Require to change polling tmeout interval -------------------------------------------

	if (msg[0] == commands.at(C_TIMEOUT))
	{
		int msec = msg[1].trimmed().toInt() * 1000;

		if (msec >= 0)
		{
			pollTimer.stop(); // pause current polling (if any)

			pollTimer.setInterval(msec);
			socket->sendTextMessage(msg[0] + "|Timeout: " + msg[1].trimmed());  // reply to client

			restartPolling();
		}
		else
		{
			socket->sendTextMessage(msg[0] + "|ERROR:invalid timeout => " + msg[1].trimmed());  // send server type to client
		}

		return;
	}

	// Require server type ------------------------------------------------------------------

	if (msg[0] == commands.at(C_SERVERTYPE))
	{
		pollTimer.stop();

		emit serverType(type);

		if (type == ST_STANDALONE)
		{
			std::clog << messages.at(SM_STANDALONE) << "\n";

			socket->sendTextMessage(msg[0] + "|" + messages.at(SM_STANDALONE));  // send server type to client
		}
		else
			if (type == ST_INTEGRATED)
			{
				std::clog << messages.at(SM_INTEGRATED) << "\n";

				socket->sendTextMessage(msg[0] + "|" + messages.at(SM_INTEGRATED)); // send server type to client
			}
			else
			{
				std::clog << messages.at(SM_UNKNOWN) << "\n";

				socket->sendTextMessage(msg[0] + "|ERROR:" + messages.at(SM_UNKNOWN));
			}

		restartPolling();

		return;
	}
*/
	// Read the ATR code (for diagnostic use, or code detection)

	if (msg[0] == commands.at(C_ATR))
	{
		//stopPolling();

		//pollTimer.stop();

		data = cardReader.CheckCard();

		if (data.atrvalid)           // if readed ATR code is valid
		{
			code = getCardCode(&data, &err);

			std::clog << "Login: " << code << "\n";

			sendMessage(conn, msg[0] + "|ATR:" + code.c_str(), Json::Value());
		}
		else
		{
			std::clog << data.errmsg << "\n";

			//emit error(msg[0], data.errmsg);

			sendMessage(conn, msg[0] + "|" + data.errmsg, Json::Value());
		}

		//restartPolling();

		return true;
	}

	// Require ATR authentication code -----------------------------------------------------
/*
	if (msg[0] == commands.at(C_LOGIN))
	{
		pollTimer.stop();

		data = cardReader.CheckCard();

		resetAuthentication();  // unvalidate authentication

		emit status(msg[0], SM_SESSIONTIMEOUT, true); // emit session timeout signal

		if (data.atrvalid) // if readed ATR is valid
		{
			code = getCardCode(&data, &err);

			std::clog << "Login: " << code << "\n";

			emit loginCode(code);

			if (lastPollStatus != SM_SESSIONTIMEOUT)
			{
				socket->sendTextMessage(msg[0] + "|" + messages.at(SM_SESSIONTIMEOUT)); // send login ATR to client
				socket->sendTextMessage(msg[0] + "|" + "atr:" + code); // send login ATR to client
			}

			lastPollStatus = SM_SESSIONTIMEOUT;
			lastError.clear();
		}
		else
		{
			std::clog << data.errmsg << "\n";

			emit error(msg[0], data.errmsg);

			if (lastPollStatus != SM_ERROR || (lastPollStatus == SM_ERROR && lastError != data.errmsg))
			{
				socket->sendTextMessage(msg[0] + "|" + messages.at(SM_SESSIONTIMEOUT)); // send login ATR to client
				socket->sendTextMessage(msg[0] + "|" + data.errmsg);
			}

			lastPollStatus = SM_ERROR;
			lastError = data.errmsg;
		}

		startPolling(PM_LOGIN);

		return;
	}

	// Authentication check ----------------------------------------------------------------

	if (msg[0] == commands.at(C_CHECK))
	{
		pollTimer.stop();

		if (isAuthenticated)
		{
			data = cardReader.CheckCard();

			code = getCardCode(&data, &err); // Get Hex ATR code

			if (data.atrvalid)   // if readed ATR is valid
			{
				timer = 0;

				if (atr == code)    // if readed ATR match authenticated ATR
				{
					std::clog << "Check success => Card code: " << code << " => " << atr << "\n";

					emit status(msg[0], SM_VALIDATED, false);

					if (lastPollStatus != SM_VALIDATED)
					{
						socket->sendTextMessage(msg[0] + "|" + messages.at(SM_VALIDATED));
					}

					lastPollStatus = SM_VALIDATED;
					lastError.clear();
				}
				else // validation failure
				{
					std::clog << "Check failure => Card code: " << code << " => " << atr << "\n";

					resetAuthentication(); // unvalidate authentication

					emit status(msg[0], SM_NOTVALIDATED, true);

					if (lastPollStatus != SM_NOTVALIDATED)
					{
						socket->sendTextMessage(msg[0] + "|" + messages.at(SM_NOTVALIDATED));
						socket->sendTextMessage(msg[0] + "|" + messages.at(SM_SESSIONTIMEOUT));
					}

					lastPollStatus = SM_NOTVALIDATED;
					lastError.clear();
				}
			}
			else  // on reading card error
			{
				timer++;

				if (timer > 3) // wait tree times
				{
					timer = 0;

					resetAuthentication(); // unvalidate authentication

					std::clog << messages.at(SM_SESSIONTIMEOUT) << "\n";

					emit status(msg[0], SM_SESSIONTIMEOUT, true);

					if (lastError != SM_SESSIONTIMEOUT)
					{
						socket->sendTextMessage(msg[0] + "|" + messages.at(SM_SESSIONTIMEOUT));
					}

					lastPollStatus = SM_SESSIONTIMEOUT;
					lastError.clear();;
				}
				else
				{
					std::clog << "Check error" << data.errmsg << "\n";

					QString errMsg = QString(data.errmsg) + " (" + QString::number(timer) + ")";

					emit error(msg[0], errMsg);

					//socket->sendTextMessage(msg[0] + "|" + errMsg);

					lastPollStatus = SM_ERROR;
					lastError = data.errmsg;
				}
			}

			startPolling(PM_CHECK);
		}
		else
		{
			// if it is not authenticated, do not start again the polling,
			// becose the auhentication do not change if it do not to try to authenticate again.
			// the client must be send a LOGINCODE command.

			std::clog << messages.at(SM_NOTAUTHENTICATED) << "\n";

			emit status(msg[0], SM_NOTAUTHENTICATED, true);

			if (lastPollStatus != SM_NOTAUTHENTICATED)
			{
				socket->sendTextMessage(msg[0] + "|" + messages.at(SM_NOTAUTHENTICATED));
			}

			lastPollStatus = SM_NOTAUTHENTICATED;
			lastError.clear();
		}

		return;
	}

	// Require to authenticate ATR code --------------------------------------------------

	if (msg[0] == commands.at(C_AUTH))
	{
		stopPolling();

		if (isAuthenticated)
		{
			std::clog << messages.at(SM_ALREADYAUTH) << "\n";

			emit status(msg[0], SM_ALREADYAUTH, false);

			socket->sendTextMessage(msg[0] + "|" + messages.at(SM_ALREADYAUTH));
		}
		else  // try to authenticate
		{
			data = cardReader.CheckCard();

			code = getCardCode(&data, &err);

			if (data.atrvalid)   // reading ATR code success
			{
				if (msg[1] == code) // authentication success
				{
					atr = code;

					isAuthenticated = 1;

					std::clog << messages.at(SM_AUTHENTICATED) << "\n";

					emit status(msg[0], SM_AUTHENTICATED, false);

					socket->sendTextMessage(msg[0] + "|" + messages.at(SM_AUTHENTICATED));
				}
				else
				{
					resetAuthentication();

					std::clog << messages.at(SM_NOTAUTHENTICATED) << "\n";

					emit status(msg[0], SM_NOTAUTHENTICATED, true);

					socket->sendTextMessage(msg[0] + "|" + messages.at(SM_NOTAUTHENTICATED));
				}
			}
			else // on reading card error
			{
				std::clog << data.errmsg << "\n";

				emit error(msg[0], data.errmsg);

				socket->sendTextMessage(msg[0] + "|" + data.errmsg);

				socket->sendTextMessage(msg[0] + "|" + messages.at(SM_NOTAUTHENTICATED));
			}
		}

		return;
	}
*/
	std::clog << messages.at(SM_UNKNOWNCOMMAND) << "\n";
/*
	emit error(msg[0], messages.at(SM_UNKNOWNCOMMAND));

	socket->close(); // close suspect connection
*/

	return false;
}
