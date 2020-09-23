#include "WebsocketServer.h"

#include <iostream>
#include <thread>
#include <asio/io_service.hpp>
#include "tcptunnel.h"

int main(int argc, char* argv[])
{
	//Create the event loop for the main thread, and the WebSocket server
	asio::io_service mainEventLoop;
	WebsocketServer server;
	
	//Register our network callbacks, ensuring the logic is run on the main thread's event loop
	server.connect([&mainEventLoop, &server](ClientConnection conn)
	{
		mainEventLoop.post([conn, &server]()
		{
			std::clog << "Connection opened." << std::endl;
			std::clog << "There are now " << server.numConnections() << " open connections." << std::endl;
			
			//Send a hello message to the client
			server.sendMessage(conn, "LOGIN|hello", Json::Value());
		});
	});
	server.disconnect([&mainEventLoop, &server](ClientConnection conn)
	{
		mainEventLoop.post([conn, &server]()
		{
			std::clog << "Connection closed." << std::endl;
			std::clog << "There are now " << server.numConnections() << " open connections." << std::endl;
		});
	});
	server.message("message", [&mainEventLoop, &server](ClientConnection conn, const Json::Value& args)
	{
		mainEventLoop.post([conn, args, &server]()
		{
			std::clog << "message handler on the main thread" << std::endl;
			std::clog << "Message payload:" << std::endl;
			for (auto key : args.getMemberNames()) {
				std::clog << "\t" << key << ": " << args[key].asString() << std::endl;
			}
			
			//Echo the message pack to the client
			server.sendMessage(conn, "message", args);
		});
	});
	
	//Start the networking thread
	std::thread serverThread([&server]() {
		server.run();
	});
	
	//Start a keyboard input thread that reads from stdin
	std::thread inputThread([&server, &mainEventLoop]()
	{
		string input;
		while (1)
		{
			//Read user input from stdin
			std::getline(std::cin, input);
			
			//Broadcast the input to all connected clients (is sent on the network thread)
			Json::Value payload;
			payload["input"] = input;
			server.broadcastMessage("userInput", payload);
			
			//Debug output on the main thread
			mainEventLoop.post([]() {
				std::clog << "User input debug output on the main thread" << std::endl;
			});
		}
	});

	//Start tcptunnel thread
	//  ./tcptunnel.exe --local-port=23240 --remote-port=3240 --remote-host=127.0.0.1 --stay-alive
	std::thread tcptunnel([]() {
		set_option(LOCAL_PORT_OPTION, "23240");
		set_option(REMOTE_PORT_OPTION, "3240");
		set_option(REMOTE_HOST_OPTION, "127.0.0.1");
		set_option(STAY_ALIVE_OPTION, "");
#if 0
#ifdef __MINGW32__
			WSADATA info;
			if (WSAStartup(MAKEWORD(1, 1), &info) != 0)
			{
				perror("main: WSAStartup()");
				exit(1);
			}
#endif

			name = argv[0];

			set_options(argc, argv);
#endif
			if (build_server() == 1)
			{
				exit(1);
			}

#ifndef __MINGW32__
			signal(SIGCHLD, SIG_IGN);
#endif

			do
			{
				if (wait_for_clients() == 0)
				{
					handle_client();
				}
			} while (stay_alive());
#if 0
			close(rc.server_socket);
#endif
	});
	
	//Start the event loop for the main thread
	asio::io_service::work work(mainEventLoop);
	mainEventLoop.run();
	
	return 0;
}
