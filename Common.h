#ifndef COMMON_H
#define COMMON_H

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <new>


#define LOG_VERBOSE(...)	/* printf(__VA_ARGS__) */
#define LOG_DEBUG(...)		/* printf(__VA_ARGS__) */
#define LOG_INFO(...)		printf(__VA_ARGS__)
#define LOG_ERROR(...)		printf(__VA_ARGS__)


#define KEEP_ALIVE_TIMEOUT			30 * 1000

#define CONNECTION_MARK_CONNECTION	0
#define CONNECTION_MARK_KEEP_ALIVE	1

#endif // COMMON_H
