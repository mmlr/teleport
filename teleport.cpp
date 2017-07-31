#include "AutoDeleter.h"
#include "Common.h"
#include "ServerSession.h"
#include "Socket.h"
#include "Auth.h"
#include "Thread.h"

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>


static const char *kAuthmoduleName = "srp";


int
server(uint16_t port, const AuthDatabase &authDatabase)
{
	Socket socket;
	int result = socket.Listen(port);
	if (result < 0)
		return result;

	while (true) {
		Socket *clientSocket = socket.Accept();
		if (clientSocket == NULL)
			continue;

		ServerSession *session = new(std::nothrow) ServerSession(*clientSocket,
			authDatabase);
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
client(const char *host, uint16_t port, uint16_t localPort, uint16_t remotePort,
	const char *username, const char *password)
{
	Socket socket;
	int result = socket.Connect(host, port);
	if (result < 0)
		return result;

	ClientAuth *auth = Auth::GetClientAuth(kAuthmoduleName, username, password);
	if (auth == NULL) {
		LOG_ERROR("failed to create client auth\n");
		return -1;
	}

	AutoDeleter<ClientAuth> _(auth);

	Handshake handshake;
	handshake.header.init();
	handshake.header.port = remotePort;

	result = auth->StartAuthentication(handshake);
	if (result < 0)
		return result;

	result = handshake.Write(socket);
	if (result < 0)
		return result;

	result = handshake.Read(socket);
	if (result < 0)
		return result;

	result = auth->ProcessChallenge(handshake);
	if (result < 0)
		return result;

	result = handshake.Write(socket);
	if (result < 0)
		return result;

	result = handshake.Read(socket);
	if (result < 0)
		return result;

	result = auth->VerifySession(handshake);
	if (result < 0)
		return result;

	LOG_INFO("authenticated to server \"%s\" port %" PRIu16 "\n", host, port);

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
	printf("\t%s server <listenPort> <authDatabase>\n", programName);
	printf("\t%s client <host> <port> <localPort> <remotePort> <username>\n",
		programName);
	printf("\t\t<password> [loop]\n");
	printf("\t%s user add <authDatabase> <username> <password> <allowedPort>\n",
		programName);
	printf("\t%s user remove <authDatabase> <username>\n", programName);
	printf("\t%s user list <authDatabase>\n", programName);
	exit(1);
}


int
main(int argc, const char *argv[])
{
	if (argc < 4)
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

		AuthDatabase *authDatabase = Auth::GetAuthDatabase(kAuthmoduleName,
			argv[3]);
		if (authDatabase == NULL) {
			LOG_ERROR("failed to create auth database\n");
			return -1;
		}

		AutoDeleter<AuthDatabase> _(authDatabase);
		return server(listenPort, *authDatabase);
	} else if (strcmp(argv[1], "client") == 0) {
		uint16_t connectPort;
		uint16_t localPort;
		uint16_t remotePort;
		if (argc < 8 || sscanf(argv[3], "%" SCNu16, &connectPort) != 1
			|| sscanf(argv[4], "%" SCNu16, &localPort) != 1
			|| sscanf(argv[5], "%" SCNu16, &remotePort) != 1) {
			print_usage_and_exit(argv[0]);
		}

		while (true) {
			int result = client(argv[2], connectPort, localPort, remotePort,
				argv[6], argv[7]);
			if (argc <= 8 || strcmp(argv[8], "loop") != 0)
				break;

			if (result < 0)
				sleep(1);
		}
	} else if (strcmp(argv[1], "user") == 0 && argc > 3) {
		AuthDatabase *database
			= Auth::GetAuthDatabase(kAuthmoduleName, argv[3]);
		if (database == NULL) {
			LOG_ERROR("failed to create auth database\n");
			return -1;
		}

		AutoDeleter<AuthDatabase> _(database);

		if (strcmp(argv[2], "add") == 0) {
			uint16_t allowedPort;
			if (argc < 7 || sscanf(argv[6], "%" SCNu16, &allowedPort) != 1)
				print_usage_and_exit(argv[0]);

			if (database->Add(argv[4], argv[5], allowedPort) < 0)
				LOG_ERROR("failed to add user\n");

		} else if (strcmp(argv[2], "remove") == 0) {
			if (argc < 5)
				print_usage_and_exit(argv[0]);

			int result = database->Remove(argv[4]);
			if (result < 0) {
				LOG_ERROR("failed to remove user\n");
				return result;
			}

		} else if (strcmp(argv[2], "list") == 0) {
			int result = database->List();
			if (result < 0) {
				LOG_ERROR("failed to list users\n");
				return result;
			}

		} else
			print_usage_and_exit(argv[0]);
	} else
		print_usage_and_exit(argv[0]);

	return 0;
}
