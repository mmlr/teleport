#ifndef SOCKET_H
#define SOCKET_H

#include "Common.h"


class Socket {
public:
								Socket();
								Socket(int socket);

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
		int						fSocket;
};

#endif // SOCKET_H
