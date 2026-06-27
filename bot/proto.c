#define _GNU_SOURCE
#include "proto.h"
#include "polymorphic.h"
#include "util.h"
#include <sys/socket.h>

#ifndef PROTO_KEY_HEX
#define PROTO_KEY_HEX "4e503132333435363738393031323334353637383930313233343536373839"
#endif
#ifndef SHARED_SECRET_HEX
#define SHARED_SECRET_HEX PROTO_KEY_HEX
#endif

static uint8_t proto_key_buf[PROTO_KEY_LEN];
static uint8_t shared_secret_buf[PROTO_KEY_LEN];

static uint8_t hexchar(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 0;
}

static void hex2buf(const char *hex, uint8_t *buf, int max)
{
	int i;
	for (i = 0; i < max && hex[i*2] && hex[i*2+1]; i++)
		buf[i] = (hexchar(hex[i*2]) << 4) | hexchar(hex[i*2+1]);
}

static void proto_init(void)
{
	static int done = 0;
	if (done) return;
	done = 1;
	hex2buf(PROTO_KEY_HEX, proto_key_buf, PROTO_KEY_LEN);
	hex2buf(SHARED_SECRET_HEX, shared_secret_buf, PROTO_KEY_LEN);
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

// polymorphic protocol functions

static uint64_t xorshift64(uint64_t *state)
{
	uint64_t x = *state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

void xorshift_buf(uint8_t *buf, uint32_t len, const uint8_t *key)
{
	uint64_t state = 0;
	int i;
	for (i = 0; i < 8; i++)
		state = (state << 8) | key[i];
	for (i = 0; i < len; i++) {
		if (i % 8 == 0)
			state = xorshift64(&state);
		buf[i] ^= (state >> ((i % 8) * 8)) & 0xFF;
	}
}

void session_key_from_challenge(const uint8_t *challenge, const uint8_t *secret, uint8_t *key_out)
{
	int i;
	for (i = 0; i < CHALLENGE_LEN; i++)
		key_out[i] = challenge[i] ^ secret[i % SHARED_SECRET_LEN];
}

int polymorphic_handshake(int fd, struct handshake_ctx *ctx, const uint8_t *shared_secret)
{
	uint8_t noise_buf[NOISE_MAX];
	uint8_t resp[RESPONSE_LEN];
	uint8_t ack;
	int n;
	int i;

	ctx->valid = 0;

	// read noise_skip
	if (recv(fd, &ctx->noise_skip, 1, MSG_NOSIGNAL) != 1)
		return -1;

	// skip noise bytes
	if (ctx->noise_skip > 0 && ctx->noise_skip <= NOISE_MAX) {
		n = 0;
		while (n < ctx->noise_skip) {
			int r = recv(fd, noise_buf + n, ctx->noise_skip - n, MSG_NOSIGNAL);
			if (r <= 0) return -1;
			n += r;
		}
	}

	// read challenge
	n = 0;
	while (n < CHALLENGE_LEN) {
		int r = recv(fd, ctx->challenge + n, CHALLENGE_LEN - n, MSG_NOSIGNAL);
		if (r <= 0) return -1;
		n += r;
	}

	// compute and send response
	for (i = 0; i < RESPONSE_LEN; i++)
		resp[i] = ctx->challenge[i] ^ shared_secret[i % SHARED_SECRET_LEN];

	if (send(fd, resp, RESPONSE_LEN, MSG_NOSIGNAL) != RESPONSE_LEN)
		return -1;

	// read ack
	if (recv(fd, &ack, 1, MSG_NOSIGNAL) != 1)
		return -1;

	if (ack != ACK_OK)
		return -2;

	// derive session key
	session_key_from_challenge(ctx->challenge, shared_secret, ctx->session_key);
	ctx->valid = 1;
	return 0;
}

int polymorphic_send(int fd, struct handshake_ctx *ctx,
                     uint8_t type, uint8_t bitmap,
                     const uint8_t *payload, uint32_t payload_len)
{
	uint8_t hdr[4];
	uint32_t total = 4 + payload_len;
	uint16_t len_net;

	if (!ctx->valid) return -1;

	// build header: type + bitmap (merge caller flags with defaults)
	hdr[0] = type;
	hdr[1] = bitmap | BITM_DEFAULT;
	len_net = payload_len;
	hdr[2] = (len_net >> 8) & 0xFF;
	hdr[3] = len_net & 0xFF;

	// encrypt header
	xorshift_buf(hdr, 4, ctx->session_key);

	// send total length (big endian, not encrypted)
	uint16_t wire_len = total;
	uint8_t len_bytes[2];
	len_bytes[0] = (wire_len >> 8) & 0xFF;
	len_bytes[1] = wire_len & 0xFF;

	if (send(fd, len_bytes, 2, MSG_NOSIGNAL) != 2)
		return -1;

	// send encrypted header
	if (send(fd, hdr, 4, MSG_NOSIGNAL) != 4)
		return -1;

	// send encrypted payload if any
	if (payload_len > 0) {
		uint8_t enc_buf[UPDATE_CHUNK_SIZE + 32];
		uint32_t i;
		for (i = 0; i < payload_len; i++)
			enc_buf[i] = payload[i];
		xorshift_buf(enc_buf, payload_len, ctx->session_key);
		if (send(fd, enc_buf, payload_len, MSG_NOSIGNAL) != (int)payload_len)
			return -1;
	}

	return total + 2;
}

int polymorphic_recv(int fd, struct handshake_ctx *ctx,
                     uint8_t *type, uint8_t *bitmap,
                     uint8_t *buf, uint32_t *len)
{
	uint8_t hdr[4];
	uint16_t wire_len;
	int n;

	if (!ctx->valid) return -1;

	// read total length (2 bytes, big endian)
	n = recv(fd, &wire_len, 2, MSG_NOSIGNAL);
	if (n != 2) return -1;
	wire_len = (wire_len << 8) | (wire_len >> 8); // ntohs
	if (wire_len < 4) return -1;

	// read and decrypt header
	n = recv(fd, hdr, 4, MSG_NOSIGNAL);
	if (n != 4) return -1;
	xorshift_buf(hdr, 4, ctx->session_key);

	*type = hdr[0];
	*bitmap = hdr[1];
	uint16_t payload_len = (hdr[2] << 8) | hdr[3];

	if (payload_len > *len) return -1;

	// read payload
	if (payload_len > 0) {
		n = recv(fd, buf, payload_len, MSG_NOSIGNAL);
		if (n != (int)payload_len) return -1;
		xorshift_buf(buf, payload_len, ctx->session_key);
	}

	*len = payload_len;
	return 4 + payload_len;
}

const uint8_t *proto_get_shared_secret(void)
{
	proto_init();
	return shared_secret_buf;
}

int polymorphic_recv_inplace(struct handshake_ctx *ctx,
                             uint8_t *type, uint8_t *bitmap,
                             uint8_t *buf, uint32_t *len)
{
	uint8_t hdr[4];

	if (!ctx->valid) return -1;
	if (*len < 4) return -1;

	// first 4 bytes of buf are the encrypted header: type + bitmap + payload_len
	hdr[0] = buf[0]; hdr[1] = buf[1]; hdr[2] = buf[2]; hdr[3] = buf[3];
	xorshift_buf(hdr, 4, ctx->session_key);

	*type = hdr[0];
	*bitmap = hdr[1];
	uint16_t payload_len = (hdr[2] << 8) | hdr[3];

	if (payload_len > *len - 4) return -1;

	// decrypt payload in place
	if (payload_len > 0)
		xorshift_buf(buf + 4, payload_len, ctx->session_key);

	// shift payload to start of buf
	uint32_t i;
	for (i = 0; i < payload_len; i++)
		buf[i] = buf[4 + i];

	*len = payload_len;
	return 4 + payload_len;
}
