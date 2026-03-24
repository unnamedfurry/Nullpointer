#define _GNU_SOURCE
#include <unistd.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include "includes.h"
#include <time.h>

#ifndef DEBUG

static int ad_ptrace_check(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
		return 1;
	ptrace(PTRACE_DETACH, 0, 1, 0);
	return 0;
}

static int ad_status_check(void)
{
	char buf[64];
	int fd, n, i;
	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0) return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return 0;
	buf[n] = '\0';
	if (strstr(buf, "TracerPid:\t0") || strstr(buf, "TracerPid: 0"))
		return 0;
	return 1;
}

void anti_debug_check(void)
{
	if (ad_ptrace_check() == 0)
		return;
	if (ad_status_check())
		_exit(0);
}

#else
void anti_debug_check(void) { (void)0; }
#endif
