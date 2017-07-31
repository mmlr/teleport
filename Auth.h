#ifndef AUTH_H
#define AUTH_H

#include "Handshake.h"


class ServerAuth;


class AuthDatabase {
public:
								AuthDatabase(const char *databaseFile);
virtual							~AuthDatabase();

virtual	int						Add(const char *username, const char *password)
									= 0;
virtual	int						Remove(const char *username) = 0;

virtual	int						List() const = 0;

virtual	ServerAuth *			GetServerAuth() const = 0;

protected:
		const char *			fDatabaseFile;
};


class ServerAuth {
public:
								ServerAuth();
virtual							~ServerAuth();

virtual	int						ProduceChallenge(Handshake &handshake) = 0;
virtual	int						VerifySession(Handshake &handshake) = 0;
};


class ClientAuth {
public:
								ClientAuth(const char *username,
									const char *password);
virtual							~ClientAuth();

virtual	int						StartAuthentication(Handshake &handshake) = 0;
virtual	int						ProcessChallenge(Handshake &handshake) = 0;
virtual	int						VerifySession(Handshake &handshake) = 0;
};


class Auth {
public:
static	AuthDatabase *			GetAuthDatabase(const char *authModuleName,
									const char *databaseFile);
static	ClientAuth *			GetClientAuth(const char *authModuleName,
									const char *username, const char *password);
};

#endif // AUTH_H
