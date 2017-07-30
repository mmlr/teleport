#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <new>


#define LOG_VERBOSE(...)	/* printf(__VA_ARGS__) */
#define LOG_ERROR(...)		printf(__VA_ARGS__)
#define LOG_DEBUG(...)		printf(__VA_ARGS__)


#define HANDSHAKE_MAGIC		'tele'
#define HANDSHAKE_VERSION	1


struct handshake_header {
	uint32_t		magic;
	uint32_t		version;
	uint32_t		id_length;
	uint32_t		key_length;
	uint16_t		port;

	void			init()
					{
						magic = HANDSHAKE_MAGIC;
						version = HANDSHAKE_VERSION;
					}

	bool			is_valid()
					{
						return magic == HANDSHAKE_MAGIC
							&& version == HANDSHAKE_VERSION
							&& id_length <= 1024
							&& key_length <= 1024;
					}
} __attribute__((__packed__));


class Socket {
public:
								Socket();
								~Socket();

		int						Create();
		void					Close();

		int						Listen(uint16_t port, bool loopback = false,
									int backlog = 5);
		Socket *				Accept(Socket *cancelSocket = NULL);

		int						Connect(const char *host, uint16_t port);

		ssize_t					Read(void *buffer, size_t bufferSize);
		int						ReadFully(void *buffer, size_t bufferSize);

		ssize_t					Write(const void *buffer, size_t bufferSize);
		int						WriteFully(const void *buffer,
									size_t bufferSize);

		void					Transfer(Socket &other);

private:
								Socket(int socket);

		int						fSocket;
};


Socket::Socket()
	:
	fSocket(-1)
{
}


Socket::Socket(int socket)
	:
	fSocket(socket)
{
	LOG_DEBUG("socket adopted: %d\n", socket);
}


Socket::~Socket()
{
	Close();
}


int
Socket::Create()
{
	Close();

	fSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (fSocket < 0) {
		LOG_ERROR("failed to create socket: %s\n", strerror(errno));
		return fSocket;
	}

	LOG_DEBUG("socket created: %d\n", fSocket);
	return 0;
}


void
Socket::Close()
{
	if (fSocket < 0)
		return;

	LOG_DEBUG("closing socket %d\n", fSocket);
	close(fSocket);
	fSocket = -1;
}


int
Socket::Listen(uint16_t port, bool loopback, int backlog)
{
	int result;
	if (fSocket < 0) {
		result = Create();
		if (result < 0)
			return result;
	}

	int reuse = 1;
	result = setsockopt(fSocket, SOL_SOCKET, SO_REUSEADDR, &reuse,
		sizeof(reuse));
	if (result < 0) {
		LOG_ERROR("failed to set reuse address socket option on socket %d\n",
			fSocket);
	} else
		LOG_DEBUG("reuse address socket option set on socket %d\n", fSocket);

	sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = loopback ? INADDR_ANY : INADDR_ANY;

	result = bind(fSocket, (sockaddr *)&address, sizeof(address));
	if (result < 0) {
		LOG_ERROR("failed to bind socket to port %" PRIu16 ": %s\n", port,
			strerror(errno));
		return result;
	}

	LOG_DEBUG("bound socket %d to port %" PRIu16 "\n", fSocket, port);

	result = listen(fSocket, backlog);
	if (result < 0) {
		LOG_ERROR("failed to listen: %s\n", strerror(errno));
		return result;
	}

	LOG_DEBUG("listening on socket %d\n", fSocket);
	return 0;
}


Socket *
Socket::Accept(Socket *cancelSocket)
{
	sockaddr_in address;
	socklen_t addressLength = sizeof(address);

	if (cancelSocket != NULL) {
		pollfd fds[2];
		fds[0].fd = fSocket;
		fds[1].fd = cancelSocket->fSocket;
		fds[0].events = fds[1].events = POLLIN;
		fds[0].revents = fds[1].revents = 0;

		poll(fds, 2, -1);
		if (fds[1].revents != 0) {
			LOG_DEBUG("cancel socket polled events: %hd\n", fds[1].revents);
			return NULL;
		}
	}

	int socket = accept(fSocket, (sockaddr *)&address, &addressLength);
	if (socket < 0) {
		LOG_ERROR("accept failed: %s\n", strerror(errno));
		return NULL;
	}

	LOG_DEBUG("socket %d accepted: %d\n", fSocket, socket);
	return new(std::nothrow) Socket(socket);
}


int
Socket::Connect(const char *host, uint16_t port)
{
	int result;
	if (fSocket < 0) {
		result = Create();
		if (result < 0)
			return result;
	}

	char portString[16];
	snprintf(portString, sizeof(portString), "%" PRIu16, port);

	addrinfo hint;
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;

	addrinfo *addressInfo;
	result = getaddrinfo(host, portString, &hint, &addressInfo);
	if (result != 0) {
		LOG_ERROR("failed to resolve host \"%s\": %s\n", host,
			gai_strerror(result));
		return -1;
	}

	LOG_DEBUG("host \"%s\" resolved\n", host);

	result = connect(fSocket, addressInfo->ai_addr, addressInfo->ai_addrlen);
	freeaddrinfo(addressInfo);
	if (result < 0) {
		LOG_ERROR("failed to connect: %s\n", strerror(errno));
		return result;
	}

	LOG_DEBUG("connected socket %d\n", fSocket);
	return 0;
}


ssize_t
Socket::Read(void *buffer, size_t bufferSize)
{
	LOG_VERBOSE("reading socket %d into buffer %p of size %zu\n", fSocket,
		buffer, bufferSize);
	return read(fSocket, buffer, bufferSize);
}


int
Socket::ReadFully(void *_buffer, size_t bufferSize)
{
	LOG_VERBOSE("reading socket %d into buffer %p of size %zu fully\n", fSocket,
		_buffer, bufferSize);

	uint8_t *buffer = (uint8_t *)_buffer;
	while (bufferSize > 0) {
		ssize_t result = read(fSocket, buffer, bufferSize);
		if (result == 0) {
			LOG_DEBUG("connection on socket %d closed\n", fSocket);
			return -1;
		}

		if (result <= 0) {
			LOG_ERROR("read failed on socket %d: %s\n", fSocket,
				strerror(errno));
			return result;
		}

		LOG_VERBOSE("read %zd from socket %d\n", result, fSocket);
		bufferSize -= result;
		buffer += result;
	}

	return 0;
}


ssize_t
Socket::Write(const void *buffer, size_t bufferSize)
{
	LOG_VERBOSE("writing buffer %p of size %zu to socket %d\n", buffer,
		bufferSize, fSocket);
	return write(fSocket, buffer, bufferSize);
}


int
Socket::WriteFully(const void *_buffer, size_t bufferSize)
{
	LOG_VERBOSE("writing buffer %p of size %zu fully to socket %d\n", _buffer,
		bufferSize, fSocket);

	if (fSocket < 0)
		return -1;

	const uint8_t *buffer = (const uint8_t *)_buffer;
	while (bufferSize > 0) {
		ssize_t result = write(fSocket, buffer, bufferSize);
		if (result < 0) {
			LOG_ERROR("write failed on socket %d: %s\n", fSocket,
				strerror(errno));
			return result;
		}

		LOG_VERBOSE("wrote %zd to socket %d\n", result, fSocket);
		bufferSize -= result;
		buffer += result;
	}

	return 0;
}


void
Socket::Transfer(Socket &other)
{
	size_t bufferSize = 1024 * 1024;
	uint8_t *buffer = new(std::nothrow) uint8_t[bufferSize];

	if (buffer == NULL) {
		LOG_ERROR("failed to allocate transfer buffer\n");
		return;
	}

	LOG_DEBUG("starting transfer from socket %d to %d\n", fSocket,
		other.fSocket);

	while (true) {
		ssize_t read = Read(buffer, bufferSize);
		if (read <= 0 || other.WriteFully(buffer, read) < 0)
			break;
	}

	delete[] buffer;

	LOG_DEBUG("transfer from socket %d to %d completed\n", fSocket,
		other.fSocket);

	Close();
}


class Handshake {
public:
		handshake_header		header;
		uint8_t *				id;
		uint8_t *				key;

								Handshake();
								~Handshake();

		void					Free();
		int						Allocate();

		int						Read(Socket &socket);
		int						Write(Socket &socket);
};


Handshake::Handshake()
	:
	id(NULL),
	key(NULL)
{
}


Handshake::~Handshake()
{
	Free();
}


void
Handshake::Free()
{
	delete[] id;
	id = NULL;

	delete[] key;
	key = NULL;
}


int
Handshake::Allocate()
{
	Free();

	id = new(std::nothrow) uint8_t[header.id_length];
	if (id == NULL) {
		LOG_ERROR("failed to allocate id buffer\n");
		return -1;
	}

	key = new(std::nothrow) uint8_t[header.key_length];
	if (key == NULL) {
		LOG_ERROR("failed to allocate key buffer\n");
		return -1;
	}

	return 0;
}


int
Handshake::Read(Socket &socket)
{
	int result = socket.ReadFully(&header, sizeof(header));
	if (result < 0)
		return result;

	if (!header.is_valid()) {
		LOG_ERROR("handshake header invalid\n");
		return -1;
	}

	LOG_DEBUG("got valid handshake header: id length %" PRIu32 " key length %"
		PRIu32 "\n", header.id_length, header.key_length);

	result = Allocate();
	if (result < 0)
		return result;

	result = socket.ReadFully(id, header.id_length);
	if (result < 0)
		return result;

	result = socket.ReadFully(key, header.key_length);
	if (result < 0)
		return result;

	LOG_DEBUG("handshake read complete\n");
	return 0;
}


int
Handshake::Write(Socket &socket)
{
	LOG_DEBUG("writing handshake header: id length %" PRIu32 " key length %"
		PRIu32 "\n", header.id_length, header.key_length);

	int result = socket.WriteFully(&header, sizeof(header));
	if (result < 0)
		return result;

	result = socket.WriteFully(id, header.id_length);
	if (result < 0)
		return result;

	result = socket.WriteFully(key, header.key_length);
	if (result < 0)
		return result;

	LOG_DEBUG("handshake write complete\n");
	return 0;
}


template<class T, typename A = void *>
class Thread {
public:
		typedef void (T::*Method)(A);

								Thread(const char *name, Method method,
									T &object, A argument,
									bool interrupt = false,
									pthread_t interruptId = 0)
									:
									fName(name),
									fMethod(method),
									fObject(object),
									fArgument(argument),
									fInterrupt(interrupt),
									fInterruptId(interruptId)
								{
								}

		void					Run()
								{
									LOG_DEBUG("running thread %s\n", fName);
									pthread_create(&fThread, NULL, &_Entry,
										this);
								}

		void					Join()
								{
									LOG_DEBUG("joining thread %s\n", fName);
									void *dummy;
									pthread_join(fThread, &dummy);
									LOG_DEBUG("thread %s joined\n", fName);
								}

		void					Interrupt()
								{
									LOG_DEBUG("interrupting thread %s\n",
										fName);
									pthread_kill(fThread, SIGUSR1);
								}

private:
static	void *					_Entry(void *data)
								{
									Thread<T, A> *thread = (Thread<T, A> *)data;
									thread->_Run();
									return NULL;
								}

		void					_Run()
								{
									LOG_DEBUG("thread %s run\n", fName);

									(fObject.*fMethod)(fArgument);

									if (fInterrupt) {
										LOG_DEBUG("interrupting other\n");
										pthread_kill(fInterruptId, SIGUSR1);
									}

									LOG_DEBUG("thread %s exit\n", fName);
								}

		const char *			fName;
		Method					fMethod;
		T &						fObject;
		A						fArgument;
		bool					fInterrupt;
		pthread_t				fInterruptId;

		pthread_t				fThread;
};


class ServerSession {
public:
								ServerSession(Socket &socket);
								~ServerSession();

		int						Init();

		void					Run(void *);

private:
		void					_Run();

		Socket &				fSocket;
		uint16_t				fListenPort;
};


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
