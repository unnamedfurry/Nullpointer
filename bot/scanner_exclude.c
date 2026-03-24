#define _GNU_SOURCE
#include "scanner_exclude.h"
#include <arpa/inet.h>

static const struct { uint32_t prefix; uint8_t mask; } exclude_ranges[] = {
	{ 0x0a000000, 8 },
	{ 0xac100000, 12 },
	{ 0xc0a80000, 16 },
	{ 0x7f000000, 8 },
	{ 0xe0000000, 4 },
	{ 0xf0000000, 4 },
	{ 0x95100000, 20 },
	{ 0x98640000, 16 },
};

#define EXCLUDE_COUNT (sizeof(exclude_ranges) / sizeof(exclude_ranges[0]))

BOOL scanner_is_excluded(ipv4_t ip)
{
	uint32_t host_ip = ntohl(ip);
	for (size_t i = 0; i < EXCLUDE_COUNT; i++) {
		uint32_t shift = 32 - exclude_ranges[i].mask;
		if ((host_ip >> shift) == (exclude_ranges[i].prefix >> shift))
			return TRUE;
	}
	return FALSE;
}
