#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "Socket.h"


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


class Handshake {
public:
		handshake_header		header;
		uint8_t *				id;
		uint8_t *				key;

								Handshake();
								~Handshake();

		void					Free();
		int						Allocate();
		int						Copy(uint32_t idLength, const void *id,
									uint32_t keyLength, const void *key);

		int						Read(Socket &socket);
		int						Write(Socket &socket);
};

#endif // HANDSHAKE_H
