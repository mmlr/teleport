#ifndef SERVER_SESSION_H
#define SERVER_SESSION_H

#include "Socket.h"

class AuthDatabase;


class ServerSession {
public:
								ServerSession(Socket &socket,
									const AuthDatabase &authDatabase);
								~ServerSession();

		int						Init();

		void					Run(void *);

private:
		void					_Run();

		Socket &				fSocket;
		uint16_t				fListenPort;

		const AuthDatabase &	fAuthDatabase;
};

#endif // SERVER_SESSION_H
