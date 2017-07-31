#include "SRPAuth.h"

#include "AutoDeleter.h"
#include "Common.h"
#include "Socket.h"

#include "csrp/srp.h"

#include <openssl/sha.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>


#define SRP_AUTH_RECORD_MAGIC		'srpa'
#define SRP_AUTH_RECORD_VERSION		1


static const SRP_NGType kNGType = SRP_NG_8192;
static const SRP_HashAlgorithm kHashAlgorithm = SRP_SHA512;


struct srp_auth_record_header {
	uint32_t	magic;
	uint32_t	version;
	uint32_t	record_length;
	uint32_t	username_length;
	uint32_t	salt_length;
	uint32_t	verifier_length;
	uint16_t	allowed_port;
} __attribute__((__packed__));


class SRPAuthRecord {
public:
		srp_auth_record_header	header;

		char *					username;
		void *					salt;
		void *					verifier;

								SRPAuthRecord();
								~SRPAuthRecord();

		void					Free();

		int						Read(Socket &file);
		int						Write(Socket &file);
};


SRPAuthRecord::SRPAuthRecord()
	:
	username(NULL),
	salt(NULL),
	verifier(NULL)
{
	memset(&header, 0, sizeof(header));
}


SRPAuthRecord::~SRPAuthRecord()
{
	Free();
}


void
SRPAuthRecord::Free()
{
	free(username);
	username = NULL;
	free(salt);
	salt = NULL;
	free(verifier);
	verifier = NULL;
}


int
SRPAuthRecord::Read(Socket &file)
{
	Free();

	bool eof;
	int result = file.ReadFully(&header, sizeof(header), &eof);
	if (result < 0) {
		if (!eof)
			LOG_ERROR("failed to read auth record header\n");
		return result;
	}

	if (header.magic != SRP_AUTH_RECORD_MAGIC) {
		LOG_ERROR("invalid auth record magic\n");
		return -1;
	}

	if (header.version != SRP_AUTH_RECORD_VERSION) {
		LOG_ERROR("unsupported auth record version\n");
		return -1;
	}

	username = (char *)malloc(header.username_length + 1);
	if (username == NULL) {
		LOG_ERROR("failed to allocate username\n");
		return -1;
	}

	result = file.ReadFully(username, header.username_length);
	if (result < 0) {
		LOG_ERROR("failed to read username\n");
		return result;
	}

	username[header.username_length] = 0;

	salt = malloc(header.salt_length);
	if (salt == NULL) {
		LOG_ERROR("failed to allocate salt\n");
		return -1;
	}

	result = file.ReadFully(salt, header.salt_length);
	if (result < 0) {
		LOG_ERROR("failed to read salt\n");
		return result;
	}

	verifier = malloc(header.verifier_length);
	if (verifier == NULL) {
		LOG_ERROR("failed to allocate verifier\n");
		return -1;
	}

	result = file.ReadFully(verifier, header.verifier_length);
	if (result < 0) {
		LOG_ERROR("failed to read verifier\n");
		return result;
	}

	LOG_DEBUG("auth record read for user \"%s\"\n", username);
	return 0;
}


int
SRPAuthRecord::Write(Socket &file)
{
	header.magic = SRP_AUTH_RECORD_MAGIC;
	header.version = SRP_AUTH_RECORD_VERSION;
	header.username_length = strlen(username);
	header.record_length = sizeof(header) + header.username_length
		+ header.salt_length + header.verifier_length;

	int result = file.WriteFully(&header, sizeof(header));
	if (result < 0) {
		LOG_ERROR("failed to write auth record header\n");
		return result;
	}

	result = file.WriteFully(username, header.username_length);
	if (result < 0) {
		LOG_ERROR("failed to write username\n");
		return result;
	}

	result = file.WriteFully(salt, header.salt_length);
	if (result < 0) {
		LOG_ERROR("failed to write salt\n");
		return result;
	}

	result = file.WriteFully(verifier, header.verifier_length);
	if (result < 0) {
		LOG_ERROR("failed to write verifier\n");
		return result;
	}

	LOG_DEBUG("auth record written for user \"%s\"\n", username);
	return 0;
}


SRPAuthDatabase::SRPAuthDatabase(const char *databaseFile)
	:
	AuthDatabase(databaseFile)
{
}


int
SRPAuthDatabase::Add(const char *username, const char *password,
	uint16_t allowedPort)
{
	int saltLength;
	const unsigned char *salt;
	int verifierLength;
	const unsigned char *verifier;

	srp_create_salted_verification_key(kHashAlgorithm, kNGType, username,
		(const unsigned char *)password, strlen(password), &salt, &saltLength,
		&verifier, &verifierLength, NULL, NULL);

	SRPAuthRecord record;
	record.username = strdup(username);
	record.header.salt_length = saltLength;
	record.salt = (void *)salt;
	record.header.verifier_length = verifierLength;
	record.verifier = (void *)verifier;
	record.header.allowed_port = allowedPort;

	int fd = open(fDatabaseFile, O_CREAT | O_APPEND | O_WRONLY,
		S_IWUSR | S_IRUSR);
	if (fd < 0) {
		LOG_ERROR("failed to open database file: %s\n", strerror(errno));
		return fd;
	}

	Socket file(fd);
	return record.Write(file);
}


int
SRPAuthDatabase::Remove(const char *username)
{
	int fd = open(fDatabaseFile, O_RDONLY);
	if (fd < 0) {
		LOG_ERROR("failed to open database file: %s\n", strerror(errno));
		return fd;
	}

	Socket inputFile(fd);

	const char *suffix = ".tmp";
	char *tempName = (char *)malloc(strlen(fDatabaseFile) + strlen(suffix) + 1);
	tempName[0] = 0;
	strcat(tempName, fDatabaseFile);
	strcat(tempName, suffix);

	fd = open(tempName, O_WRONLY | O_CREAT | O_EXCL, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		LOG_ERROR("failed to create temporary database file: %s\n",
			strerror(errno));
		return fd;
	}

	Socket outputFile(fd);
	SRPAuthRecord record;

	while (true) {
		int result = record.Read(inputFile);
		if (result < 0)
			break;

		if (strcmp(record.username, username) == 0)
			continue;

		result = record.Write(outputFile);
		if (result < 0) {
			LOG_ERROR("failed to write output file: %s\n", strerror(errno));
			free(tempName);
			return result;
		}
	}

	inputFile.Close();
	outputFile.Close();
	int result = rename(tempName, fDatabaseFile);
	free(tempName);

	if (result < 0) {
		LOG_ERROR("failed to replace database file: %s\n", strerror(errno));
		return result;
	}

	return 0;
}


int
SRPAuthDatabase::Lookup(const char *username, SRPAuthRecord &record) const
{
	int fd = open(fDatabaseFile, O_RDONLY);
	if (fd < 0) {
		LOG_ERROR("failed to open database file: %s\n", strerror(errno));
		return fd;
	}

	Socket file(fd);
	while (true) {
		int result = record.Read(file);
		if (result < 0)
			return result;

		if (strcmp(record.username, username) == 0)
			return 0;
	}
}


int
SRPAuthDatabase::List() const
{
	int fd = open(fDatabaseFile, O_RDONLY);
	if (fd < 0) {
		LOG_ERROR("failed to open database file: %s\n", strerror(errno));
		return fd;
	}

	printf("username\tallowed port\n");

	Socket file(fd);
	SRPAuthRecord record;
	while (true) {
		int result = record.Read(file);
		if (result < 0)
			return 0;

		printf("%s\t%" PRIu16 "\n", record.username,
			record.header.allowed_port);
	}
}


ServerAuth *
SRPAuthDatabase::GetServerAuth() const
{
	return new(std::nothrow) SRPServerAuth(*this);
}


SRPServerAuth::SRPServerAuth(const SRPAuthDatabase &database)
	:
	fDatabase(database),
	fVerifier(NULL)
{
}


SRPServerAuth::~SRPServerAuth()
{
	srp_verifier_delete(fVerifier);
}


int
SRPServerAuth::ProduceChallenge(Handshake &handshake)
{
	char *username = strndup((const char *)handshake.id,
		handshake.header.id_length);
	if (username == NULL) {
		LOG_ERROR("failed to allocate username buffer\n");
		return -1;
	}

	AutoFreeer _(username);

	SRPAuthRecord record;
	int result = fDatabase.Lookup(username, record);
	if (result < 0) {
		LOG_ERROR("user lookup failed for user \"%s\"\n", username);
		return result;
	}

	if (handshake.header.port != record.header.allowed_port) {
		LOG_ERROR("user \"%s\" not allowed to listen on port %" PRIu16 "\n",
			username, handshake.header.port);
		return -1;
	}

	int challengeLength;
	const unsigned char *challenge;
	fVerifier = srp_verifier_new(kHashAlgorithm, kNGType, record.username,
		(const unsigned char *)record.salt, record.header.salt_length,
		(const unsigned char *)record.verifier, record.header.verifier_length,
		handshake.key, handshake.header.key_length, &challenge,
		&challengeLength, NULL, NULL);
	if (challenge == NULL) {
		LOG_ERROR("SRP-6a safety check violation\n");
		return -1;
	}

	return handshake.Copy(record.header.salt_length, record.salt,
		challengeLength, challenge);
}


int
SRPServerAuth::VerifySession(Handshake &handshake)
{
	if (handshake.header.id_length != SHA512_DIGEST_LENGTH) {
		LOG_ERROR("session proof has invalid length: %" PRIu32 "\n",
			handshake.header.id_length);
		return -1;
	}

	const unsigned char *proof;
	srp_verifier_verify_session(fVerifier, handshake.id, &proof);
	if (proof == NULL) {
		LOG_ERROR("user authentication failed for user \"%s\"\n", Username());
		return -1;
	}

	return handshake.Copy(SHA512_DIGEST_LENGTH, proof, 0, NULL);
}


const char *
SRPServerAuth::Username() const
{
	return srp_verifier_get_username(fVerifier);
}


SRPClientAuth::SRPClientAuth(const char *username, const char *password)
	:
	ClientAuth(username, password)
{
	fUser = srp_user_new(kHashAlgorithm, kNGType, username,
		(const unsigned char *)password, strlen(password), NULL, NULL);
}


SRPClientAuth::~SRPClientAuth()
{
	srp_user_delete(fUser);
}


int
SRPClientAuth::StartAuthentication(Handshake &handshake)
{
	const char *id = NULL;
	const unsigned char *key = NULL;
	int keyLength;
	srp_user_start_authentication(fUser, &id, &key, &keyLength);

	return handshake.Copy(strlen(id), id, keyLength, key);
}


int
SRPClientAuth::ProcessChallenge(Handshake &handshake)
{
	int proofLength;
	const unsigned char *proof;
	srp_user_process_challenge(fUser, handshake.id, handshake.header.id_length,
		handshake.key, handshake.header.key_length, &proof, &proofLength);

	if (proof == NULL) {
		LOG_ERROR("SRP-6a safety check violation\n");
		return -1;
	}

	return handshake.Copy(proofLength, proof, 0, NULL);
}


int
SRPClientAuth::VerifySession(Handshake &handshake)
{
	if (handshake.header.id_length != SHA512_DIGEST_LENGTH) {
		LOG_ERROR("session proof has invalid length: %" PRIu32 "\n",
			handshake.header.id_length);
		return -1;
	}

	srp_user_verify_session(fUser, handshake.id);
	if (!srp_user_is_authenticated(fUser)) {
		LOG_ERROR("authentication failed\n");
		return -1;
	}

	return 0;
}
