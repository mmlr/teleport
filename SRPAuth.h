#ifndef SRP_AUTH_H
#define SRP_AUTH_H

#include "Auth.h"


class SRPAuthRecord;
struct SRPUser;
struct SRPVerifier;


class SRPAuthDatabase : public AuthDatabase {
public:
								SRPAuthDatabase(const char *databaseFile);

virtual	int						Add(const char *username, const char *password,
									uint16_t allowedPort);
virtual	int						Remove(const char *username);

		int						Lookup(const char *username,
									SRPAuthRecord &record) const;

virtual	int						List() const;

virtual	ServerAuth *			GetServerAuth() const;
};


class SRPServerAuth : public ServerAuth {
public:
								SRPServerAuth(const SRPAuthDatabase &database);
								~SRPServerAuth();

virtual	int						ProduceChallenge(Handshake &handshake);
virtual	int						VerifySession(Handshake &handshake);

private:
		const SRPAuthDatabase &	fDatabase;
		SRPVerifier *			fVerifier;
};


class SRPClientAuth : public ClientAuth {
public:
								SRPClientAuth(const char *username,
									const char *password);
								~SRPClientAuth();

virtual	int						StartAuthentication(Handshake &handshake);
virtual	int						ProcessChallenge(Handshake &handshake);
virtual	int						VerifySession(Handshake &handshake);

private:
		SRPUser *				fUser;
};

#endif // SRP_AUTH_H
