#define _GNU_SOURCE
#include "proto.h"
#include "util.h"

#ifndef PROTO_KEY_HEX
#define PROTO_KEY_HEX "4e503132333435363738393031323334353637383930313233343536373839"
#endif

static uint8_t proto_key_buf[PROTO_KEY_LEN];

static uint8_t hexchar(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 0;
}

static void proto_init(void)
{
	static int done = 0;
	if (done) return;
	done = 1;
	const char *hex = PROTO_KEY_HEX;
	int i;
	for (i = 0; i < PROTO_KEY_LEN && hex[i*2] && hex[i*2+1]; i++)
		proto_key_buf[i] = (hexchar(hex[i*2]) << 4) | hexchar(hex[i*2+1]);
}

void proto_xor(uint8_t *buf, int len, const uint8_t *key)
{
	int i;
	for (i = 0; i < len; i++)
		buf[i] ^= key[i % PROTO_KEY_LEN];
}

void proto_encrypt(uint8_t *buf, int len)
{
	proto_init();
	proto_xor(buf, len, proto_key_buf);
}

void proto_decrypt(uint8_t *buf, int len)
{
	proto_init();
	proto_xor(buf, len, proto_key_buf);
}
