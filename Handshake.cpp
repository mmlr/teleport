#include "Handshake.h"

#include "Common.h"


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
Handshake::Copy(uint32_t idLength, const void *_id, uint32_t keyLength,
	const void *_key)
{
	header.id_length = idLength;
	header.key_length = keyLength;
	int result = Allocate();
	if (result < 0)
		return result;

	memcpy(id, _id, idLength);
	memcpy(key, _key, keyLength);
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
