#pragma once

#include "includes.h"

#define PROTO_MAGIC_LEN 2
#define PROTO_KEY_LEN 32

#ifndef PROTO_MAGIC_BOT
#define PROTO_MAGIC_BOT 0x4E50
#endif

void proto_xor(uint8_t *buf, int len, const uint8_t *key);
void proto_encrypt(uint8_t *buf, int len);
void proto_decrypt(uint8_t *buf, int len);
