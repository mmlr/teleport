#include "ServerSession.h"

#include "Handshake.h"
#include "Thread.h"


ServerSession::ServerSession(Socket &socket)
	:
	fSocket(socket)
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

	handshake.header.id_length = 0;
	handshake.header.key_length = 0;
	result = handshake.Allocate();
	if (result < 0)
		return result;

	result = handshake.Write(fSocket);
	if (result < 0)
		return result;

	result = handshake.Read(fSocket);
	if (result < 0)
		return result;

	handshake.header.id_length = 0;
	handshake.header.key_length = 0;
	result = handshake.Allocate();
	if (result < 0)
		return result;

	result = handshake.Write(fSocket);
	if (result < 0)
		return result;

	LOG_DEBUG("server session init complete\n");
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

	LOG_DEBUG("server session starting listening on port %" PRIu16 "\n",
		fListenPort);

	Socket *socket = listener.Accept(&fSocket);
	if (socket == NULL) {
		LOG_ERROR("failed accepting socket on listening port %" PRIu16 "\n",
			fListenPort);
		return;
	}

	LOG_DEBUG("server session accepted connection on port %" PRIu16 "\n",
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
}
