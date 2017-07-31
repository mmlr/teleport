#include "Auth.h"

#include "SRPAuth.h"


static const char *kSRPAuthModuleName = "srp";


AuthDatabase *
Auth::GetAuthDatabase(const char *authModuleName, const char *databaseFile)
{
	if (strcmp(authModuleName, kSRPAuthModuleName) == 0)
		return new(std::nothrow) SRPAuthDatabase(databaseFile);

	return NULL;
}


ClientAuth *
Auth::GetClientAuth(const char *authModuleName, const char *username,
	const char *password)
{
	if (strcmp(authModuleName, kSRPAuthModuleName) == 0)
		return new(std::nothrow) SRPClientAuth(username, password);

	return NULL;
}


AuthDatabase::AuthDatabase(const char *databaseFile)
	:
	fDatabaseFile(databaseFile)
{
}


AuthDatabase::~AuthDatabase()
{
}


ServerAuth::ServerAuth()
{
}


ServerAuth::~ServerAuth()
{
}


ClientAuth::ClientAuth(const char *, const char *)
{
}


ClientAuth::~ClientAuth()
{
}
