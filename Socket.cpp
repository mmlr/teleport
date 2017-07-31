#include "Socket.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>


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
