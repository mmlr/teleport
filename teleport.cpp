#include "Common.h"
#include "ServerSession.h"
#include "Socket.h"
#include "Thread.h"

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>


int
server(uint16_t port)
{
	Socket socket;
	int result = socket.Listen(port);
	if (result < 0)
		return result;

	while (true) {
		Socket *clientSocket = socket.Accept();
		if (clientSocket == NULL)
			continue;

		ServerSession *session = new(std::nothrow) ServerSession(*clientSocket);
		if (session == NULL) {
			LOG_ERROR("failed to allocate session\n");
			continue;
		}

		Thread<ServerSession> thread("server session", &ServerSession::Run,
			*session, NULL);
		thread.Run();
	}
}


int
client(const char *host, uint16_t port, uint16_t localPort, uint16_t remotePort)
{
	Socket socket;
	int result = socket.Connect(host, port);
	if (result < 0)
		return result;

	Handshake handshake;
	handshake.header.init();
	handshake.header.id_length = 0;
	handshake.header.key_length = 0;
	handshake.header.port = remotePort;
	result = handshake.Allocate();
	if (result < 0)
		return result;

	result = handshake.Write(socket);
	if (result < 0)
		return result;

	result = handshake.Read(socket);
	if (result < 0)
		return result;

	handshake.header.id_length = 0;
	handshake.header.key_length = 0;
	result = handshake.Allocate();
	if (result < 0)
		return result;

	result = handshake.Write(socket);
	if (result < 0)
		return result;

	result = handshake.Read(socket);
	if (result < 0)
		return result;

	uint8_t connectionMark;
	result = socket.ReadFully(&connectionMark, sizeof(connectionMark));
	if (result < 0) {
		LOG_ERROR("failed to read connection mark\n");
		return result;
	}

	Socket connection;
	result = connection.Connect("localhost", localPort);
	if (result < 0)
		return result;

	Thread<Socket, Socket &> thread("client transfer", &Socket::Transfer,
		connection, socket, true, pthread_self());
	thread.Run();

	socket.Transfer(connection);
	thread.Interrupt();
	thread.Join();
	return 0;
}


void
interrupt(int)
{
}


void
print_usage_and_exit(const char *programName)
{
	printf("usage:\n");
	printf("\t%s server <listenPort>\n", programName);
	printf("\t%s client <host> <port> <localPort> <remotePort> [loop]\n",
		programName);
	exit(1);
}


int
main(int argc, const char *argv[])
{
	if (argc < 3)
		print_usage_and_exit(argv[0]);

	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = &interrupt;
	sigaction(SIGUSR1, &action, NULL);
	sigaction(SIGPIPE, &action, NULL);

	if (strcmp(argv[1], "server") == 0) {
		uint16_t listenPort;
		if (sscanf(argv[2], "%" SCNu16, &listenPort) != 1)
			print_usage_and_exit(argv[0]);

		server(listenPort);
	} else if (strcmp(argv[1], "client") == 0) {
		uint16_t connectPort;
		uint16_t localPort;
		uint16_t remotePort;
		if (argc < 6 || sscanf(argv[3], "%" SCNu16, &connectPort) != 1
			|| sscanf(argv[4], "%" SCNu16, &localPort) != 1
			|| sscanf(argv[5], "%" SCNu16, &remotePort) != 1) {
			print_usage_and_exit(argv[0]);
		}

		while (true) {
			int result = client(argv[2], connectPort, localPort, remotePort);
			if (argc <= 6 || strcmp(argv[6], "loop") != 0)
				break;

			if (result < 0)
				sleep(1);
		}
	} else
		print_usage_and_exit(argv[0]);

	return 0;
}
