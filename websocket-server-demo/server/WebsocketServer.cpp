#include "WebsocketServer.h"

#include <algorithm>
#include <functional>
#include <iostream>

#include <string>
#include <fstream>
#include <streambuf>

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

	messages.insert(std::pair<int, std::string>(SM_UNKNOWNCOMMAND, "UnknownCommand"));
	messages.insert(std::pair<int, std::string>(SM_UNKNOWN, "Unknown"));

	commands.insert(std::pair<int, std::string>(C_ATR, "ATRCODE"));
	commands.insert(std::pair<int, std::string>(C_VIEW_CERT, "VIEWCERT"));
	commands.insert(std::pair<int, std::string>(C_AUTH, "AUTHENTICATE"));
	commands.insert(std::pair<int, std::string>(C_SIGN, "TOSIGN"));

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
	//std::for_each(message.begin(), message.end(), [](char & c) {
	//	c = ::toupper(c);
	//});

	std::clog << "Message Received: " << message << "\n";

	vector<string> msg;

	split(message, ':', msg);


	if (msg.size() != 2)
	{
		std::clog << messages.at(SM_UNKNOWNCOMMAND) << "\n";

		return false;
	}

	// Read the ATR code (for diagnostic use, or code detection)
	if (msg[0] == commands.at(C_ATR))
	{
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

			sendMessage(conn, msg[0] + "|" + data.errmsg, Json::Value());
		}

		return true;
	}

	if (msg[0] == commands.at(C_VIEW_CERT))
	{
		std::clog << "VIEWCERT:" << "\n";
		code = crypto.Get_SmartCard_RSAFull_certificate();
		sendMessage(conn, msg[0] + "|CERT:" + code.c_str(), Json::Value());
		return true;
	}

	if (msg[0] == commands.at(C_AUTH))
	{
		std::clog << "AUTHENTICATE:" << "\n";

		std::ifstream t("mysite.local.cer");
		std::string str((std::istreambuf_iterator<char>(t)),
			std::istreambuf_iterator<char>());

		sendMessage(conn, msg[0] + "|AUTH:" + str.c_str(), Json::Value());
		return true;
	}

	if (msg[0] == commands.at(C_SIGN))
	{
		std::clog << "TOSIGN: " << msg[1] <<"\n";

		std::ifstream t("sig64.txt");
		std::string str((std::istreambuf_iterator<char>(t)),
			std::istreambuf_iterator<char>());


		sendMessage(conn, msg[0] + "|SIGNED:" + str.c_str(), Json::Value());
		return true;
	}

	std::clog << messages.at(SM_UNKNOWNCOMMAND) << "\n";

	return false;
}
