#define _GNU_SOURCE
#include <sys/socket.h>
#include <arpa/inet.h>

#include "report.h"
#include "proto.h"
#include "util.h"

void report_send_encrypted(int fd, const uint8_t *buf, int len)
{
	uint8_t tmp[1024];
	uint16_t nlen;

	if (len <= 0 || len > (int)sizeof(tmp))
		return;
	util_memcpy(tmp, buf, len);
	proto_encrypt(tmp, len);
	nlen = htons((uint16_t)len);
	send(fd, &nlen, 2, MSG_NOSIGNAL);
	send(fd, tmp, len, MSG_NOSIGNAL);
}
