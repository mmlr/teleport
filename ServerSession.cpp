#include "ServerSession.h"

#include "AutoDeleter.h"
#include "Handshake.h"
#include "Auth.h"
#include "Thread.h"


ServerSession::ServerSession(Socket &socket, const AuthDatabase &authDatabase)
	:
	fSocket(socket),
	fAuthDatabase(authDatabase)
{
	LOG_DEBUG("server session created\n");
}


ServerSession::~ServerSession()
{
	delete &fSocket;
	LOG_DEBUG("server session destroyed\n");
}


int
ServerSession::Init()
{
	Handshake handshake;
	int result = handshake.Read(fSocket);
	if (result < 0)
		return result;

	fListenPort = handshake.header.port;
	LOG_DEBUG("requested listen port: %" PRIu16 "\n", handshake.header.port);

	ServerAuth *auth = fAuthDatabase.GetServerAuth();
	if (auth == NULL) {
		LOG_ERROR("failed to create server auth\n");
		return -1;
	}

	AutoDeleter<ServerAuth> _(auth);

	result = auth->ProduceChallenge(handshake);
	if (result < 0)
		return result;

	result = handshake.Write(fSocket);
	if (result < 0)
		return result;

	result = handshake.Read(fSocket);
	if (result < 0)
		return result;

	result = auth->VerifySession(handshake);
	if (result < 0)
		return result;

	result = handshake.Write(fSocket);
	if (result < 0)
		return result;

	LOG_DEBUG("server session init complete\n");
	LOG_INFO("authenticated user \"%s\"\n", auth->Username());
	return 0;
}


void
ServerSession::Run(void *)
{
	_Run();
	delete this;
}


void
ServerSession::_Run()
{
	if (Init() < 0)
		return;

	LOG_DEBUG("server session trying to listen on port %" PRIu16 "\n",
		fListenPort);

	Socket listener;
	if (listener.Listen(fListenPort, true, 1) < 0)
		return;

	LOG_INFO("server session listening on port %" PRIu16 "\n", fListenPort);

	Socket *socket = listener.Accept(&fSocket);
	if (socket == NULL) {
		LOG_ERROR("failed accepting socket on listening port %" PRIu16 "\n",
			fListenPort);
		return;
	}

	LOG_INFO("server session accepted connection on port %" PRIu16 "\n",
		fListenPort);

	uint8_t connectionMark = 0;
	if (fSocket.WriteFully(&connectionMark, sizeof(connectionMark))) {
		LOG_ERROR("failed to write connection mark\n");
		return;
	}

	Thread<Socket, Socket &> thread("server transfer", &Socket::Transfer,
		*socket, fSocket, true, pthread_self());
	thread.Run();

	fSocket.Transfer(*socket);
	thread.Interrupt();
	thread.Join();

	LOG_INFO("servers session ended for port %" PRIu16 "\n", fListenPort);
}
