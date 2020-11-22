/*
 * Copyright (C) 2000-2015 Clemens Fuchslocher <clemens@vakuumverpackt.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#include "utils.h"
#include "base64.h"
#include "tcptunnel.h"
#include "TMultiThreadSingleQueue.h"

#include <iostream>
#include <atomic>
#include <condition_variable>
#include <thread>
#include <chrono>

const char *name;

struct struct_rc rc;
struct struct_options options;
struct struct_settings settings = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

WebsocketServer * pServer = NULL;
CTMultiThreadSingleQueue<std::string> client_socket_data;
CTMultiThreadSingleQueue<std::string> remote_socket_data;

#define IS_WINDOWS_SERVER (pServer != NULL && pServer->isWindowsSide())
#define IS_LINUX_SERVER (pServer != NULL && pServer->isLinuxSide())

int stay_alive()
{
	return settings.stay_alive;
}

void rcv_callback(std::string str)
{
	std::string decoded = base64_decode(str);
	client_socket_data.Push(decoded);
	if (settings.log)
	{
		hexDump("rcv_callback", decoded.c_str(), decoded.length());
	}
}

void send_callback(std::string str)
{
	std::string decoded = base64_decode(str);
	remote_socket_data.Push(decoded);
	if (settings.log)
	{
		hexDump("send_callback", decoded.c_str(), decoded.length());
	}
}

void set_option(char option, const char *optarg)
{
	switch (option)
	{
		case LOCAL_PORT_OPTION:
		{
			options.local_port = optarg;
			settings.local_port = 1;
			break;
		}

		case REMOTE_PORT_OPTION:
		{
			options.remote_port = optarg;
			settings.remote_port = 1;
			break;
		}

		case REMOTE_HOST_OPTION:
		{
			options.remote_host = optarg;
			settings.remote_host = 1;
			break;
		}

		case BIND_ADDRESS_OPTION:
		{
			options.bind_address = optarg;
			settings.bind_address = 1;
			break;
		}

		case CLIENT_ADDRESS_OPTION:
		{
			options.client_address = optarg;
			settings.client_address = 1;
			break;
		}

		case FORK_OPTION:
		{
			settings.fork = 1;
			settings.stay_alive = 1;
			break;
		}

		case LOG_OPTION:
		{
			settings.log = 1;
			break;
		}

		case STAY_ALIVE_OPTION:
		{
			settings.stay_alive = 1;
			break;
		}
	}
}

std::condition_variable cv;
std::mutex cv_m;


int wait_for_clients(void)
{
	std::unique_lock<std::mutex> lk(cv_m);
	auto now = std::chrono::system_clock::now();
	if (cv.wait_until(lk, now + std::chrono::milliseconds(1000), []() {return 1; })) {}

	return 0;
}

void handle_client(void)
{
	handle_tunnel();
}

void handle_tunnel(void)
{
	if (build_tunnel() == 0)
	{
		use_tunnel();
	}
}

int build_tunnel(void)
{
	if (client_socket_data.GetSize() <= 0)
	{
		//perror("build_tunnel: no client socket data");
		return 1;
	}

	rc.remote_host = gethostbyname(options.remote_host);
	if (rc.remote_host == NULL)
	{
		perror("build_tunnel: gethostbyname()");
		return 1;
	}

	memset(&rc.remote_addr, 0, sizeof(rc.remote_addr));

	rc.remote_addr.sin_family = AF_INET;
	rc.remote_addr.sin_port = htons(atoi(options.remote_port));

	memcpy(&rc.remote_addr.sin_addr.s_addr, rc.remote_host->h_addr, rc.remote_host->h_length);

	rc.remote_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (rc.remote_socket < 0)
	{
		perror("build_tunnel: socket()");
		return 1;
	}

	if (connect(rc.remote_socket, (struct sockaddr *) &rc.remote_addr, sizeof(rc.remote_addr)) < 0)
	{
		perror("build_tunnel: connect()");
		return 1;
	}

	return 0;
}

#define NODATA_TIMEOUT 16

int use_tunnel(void)
{
	fd_set io;
#ifdef __MINGW32__
	char buffer[OPTIONS_BUFFER_SIZE];
#else
	char buffer[options.buffer_size];
#endif

	int nodata = 0;

	for (;;)
	{
		bool client_data = (client_socket_data.GetSize() > 0);
		if (client_data)
		{
			std::string decoded;
			client_socket_data.Pop(decoded);
			send(rc.remote_socket, decoded.c_str(), decoded.length(), 0);
			if (settings.log)
			{
				printf("to remote_socket ");
				hexDump(get_current_timestamp(), decoded.c_str(), decoded.length());
			}
		}

		struct timeval tv = { 1, 0 };
		FD_ZERO(&io);
		FD_SET(rc.remote_socket, &io);

		memset(buffer, 0, sizeof(buffer));

		int select_value = select(0, &io, NULL, NULL, &tv);

		if (select_value == 0 || select_value >= WSABASEERR)
		{
			if (client_data)
			{
				nodata = 0;
				continue;
			}

			nodata++;
			if (nodata >= NODATA_TIMEOUT)
			{
				perror("use_tunnel: remote_socket timed out");
				closesocket(rc.remote_socket);
				return 0;
			}

			continue;
		}

		nodata = 0;

		if (FD_ISSET(rc.remote_socket, &io))
		{
			int count = recv(rc.remote_socket, buffer, sizeof(buffer), 0);
			if (count < 0)
			{
				perror("use_tunnel: recv(rc.remote_socket)");
				closesocket(rc.remote_socket);
				return 1;
			}

			if (count == 0)
			{
				printf("use_tunnel: remote_socket closed");
				closesocket(rc.remote_socket);
				return 0;
			}

			if (settings.log)
			{
				printf("to client socket ");
				hexDump(get_current_timestamp(), buffer, count);
			}

			if (NULL != pServer && pServer->isWindowsSide())
			{
				std::string encodedData = base64_encode((const unsigned char *)buffer, count);
				pServer->broadcastMessage("BIN_DATA|" + encodedData, Json::Value());
			}
		}
	}

	return 0;
}

int fd(void)
{
	return 0;
}

char *get_current_timestamp(void)
{
	static char date_str[20];
	time_t date;

	time(&date);
	strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", localtime(&date));
	return date_str;
}

void print_usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n\n", name);
}

void print_helpinfo(void)
{
	fprintf(stderr, "Try `%s --help' for more options\n", name);
}

void print_help(void)
{
	fprintf(stderr, "\
Options:\n\
  --version\n\
  --help\n\n\
  --local-port=PORT    local port\n\
  --remote-port=PORT   remote port\n\
  --remote-host=HOST   remote host\n\
  --bind-address=IP    bind address\n\
  --client-address=IP  only accept connections from this address\n\
  --buffer-size=BYTES  buffer size\n"
#ifndef __MINGW32__
"  --fork               fork-based concurrency\n"
#endif
"  --log\n\
  --stay-alive\n\n\
\n");
}

void print_version(void)
{
	fprintf(stderr, "\
tcptunnel v" VERSION " Copyright (C) 2000-2013 Clemens Fuchslocher\n\n\
This program is distributed in the hope that it will be useful,\n\
but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
GNU General Public License for more details.\n\n\
Written by Clemens Fuchslocher <clemens@vakuumverpackt.de>\n\
");
}

void print_missing(const char *message)
{
	print_usage();
	fprintf(stderr, "%s: %s\n", name, message);
	print_helpinfo();
}

int tcptunnel_loop(WebsocketServer& server)
{
	pServer = &server;
	if (NULL != pServer)
	{
		pServer->set_rcv_callback(rcv_callback);
		pServer->set_send_callback(send_callback);
	}
#ifdef __MINGW32__
	WSADATA info;
	if (WSAStartup(MAKEWORD(1, 1), &info) != 0)
	{
		perror("main: WSAStartup()");
		exit(1);
	}
#endif

#ifndef __MINGW32__
	signal(SIGCHLD, SIG_IGN);
#endif

	do
	{
		if (wait_for_clients() == 0)
		{
			handle_client();
		}
	} while (settings.stay_alive);

	return 0;
}
