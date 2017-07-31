#ifndef SERVER_SESSION_H
#define SERVER_SESSION_H

#include "Socket.h"


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

#endif // SERVER_SESSION_H
