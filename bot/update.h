#pragma once
#include "includes.h"

#define UPDATE_FALLBACK_MEMFD  0
#define UPDATE_FALLBACK_INJECT 1
#define UPDATE_FALLBACK_TMP    2

#define UPDATE_PATH_TMP "/tmp/.fnbupd"

struct update_ctx {
    int fd;
    uint32_t total_size;
    uint32_t received;
    uint8_t fallback_method;
};

enum update_method {
    UPD_MEMFD  = 0,
    UPD_INJECT = 1,
    UPD_TMP    = 2,
};

int update_init(struct update_ctx *ctx, uint32_t total_size);
int update_write(struct update_ctx *ctx, const uint8_t *data, uint32_t len);
void update_close_clean(struct update_ctx *ctx);
int update_execute(struct update_ctx *ctx);
